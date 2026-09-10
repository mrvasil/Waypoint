import Foundation
import WaypointCore
import Darwin

private final class LockedData: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Data()

    func store(_ data: Data) {
        lock.lock()
        value = data
        lock.unlock()
    }

    func load() -> Data {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

/// Живые проверки: читают настоящий state.json и поднимают xray.
/// Запуск: swift run waypoint-tests --live
enum LiveChecks {
    static func run() async {
        let store = Store()
        let state = store.snapshot()

        print("\nсостояние (\(store.fileURL.path)):")
        print("  туннелей: \(state.tunnels.count), прокси: \(state.proxies.count)")
        for t in state.tunnels { print("  · \(t.type) \(t.name) → \(t.host):\(t.port)") }
        for p in state.proxies {
            let route = p.target.map { target in
                "\(target.kind.rawValue):\(target.referenceId ?? "-")"
            } ?? "direct"
            print("  · \(p.url) → route=\(route)")
        }

        let engine = Engine(workDir: URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("waypoint-live"))

        print("\nсеть:")
        let info = engine.bypassInfo(for: state.settings)
        print("  обход включён : \(info.enabled)")
        print("  интерфейс     : \(info.active ?? "не определён")")
        print("  default route : \(info.status.defaultRoute ?? "?")")
        print("  туннели       : \(info.status.tunnels.map(\.name).joined(separator: ", "))")
        print("  маршрут перехвачен туннелем: \(info.status.tunnelCapturedRoute)")

        print("\nxray:")
        if let path = engine.resolveXrayPath(preferred: state.settings.xrayPath) {
            print("  бинарник: \(path)")
            print("  версия  : \(engine.version(of: path) ?? "?")")
        } else {
            print("  НЕ НАЙДЕН")
            return
        }

        do {
            let v = try await engine.validate(state: state, settings: state.settings)
            print("  xray -test: \(v.ok ? "Configuration OK" : "ОТВЕРГ КОНФИГ")")
            if !v.ok { print(String(v.output.suffix(500))) }
        } catch {
            print("  ошибка валидации: \(error.localizedDescription)")
        }

        guard let tunnel = state.tunnels.first else {
            print("\nнет туннелей для теста")
            return
        }

        print("\nтест туннеля «\(tunnel.name)»:")
        let r = await engine.testTunnel(tunnel, settings: state.settings)
        if r.ok {
            print("  ✓ ip=\(r.ip ?? "?") loc=\(r.loc ?? "?") latency=\(r.latencyMs ?? -1)ms")
        } else {
            print("  ✗ \(r.error ?? "неизвестная ошибка")")
        }

        // Полный запуск движка и живой трафик через локальный прокси.
        if let proxy = state.proxies.first(where: \.enabled) {
            print("\nполный запуск движка:")
            do {
                try await engine.start(state: state, settings: state.settings)
                try? await Task.sleep(nanoseconds: 1_500_000_000)
                let st = await engine.status()
                print("  запущен: \(st.running), pid=\(st.pid.map(String.init) ?? "-")")

                let curl = Process()
                curl.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
                curl.arguments = [
                    "-s", "-m", "15",
                    "--socks5-hostname", proxy.address,
                    "http://cp.cloudflare.com/cdn-cgi/trace",
                ]
                let pipe = Pipe()
                curl.standardOutput = pipe
                try curl.run()
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                curl.waitUntilExit()
                let body = String(data: data, encoding: .utf8) ?? ""
                let line = body.components(separatedBy: .newlines)
                    .filter { $0.hasPrefix("ip=") || $0.hasPrefix("loc=") }
                    .joined(separator: " ")
                print(line.isEmpty ? "  ✗ трафик через \(proxy.url) не прошёл" : "  ✓ через \(proxy.url): \(line)")
            } catch {
                print("  ✗ не запустился: \(error.localizedDescription)")
            }
            await engine.stop()
        }

        // Контрольная проверка: привязка к туннелю должна ломать связь —
        // это доказывает, что sockopt.interface реально управляет маршрутом.
        if let tun = info.status.tunnels.first {
            print("\nконтроль: принудительная привязка к \(tun.name) (ожидается провал)")
            var forced = state.settings
            forced.bypassInterface = tun.name
            let bad = await engine.testTunnel(tunnel, settings: forced)
            print(bad.ok ? "  ⚠ неожиданно сработало ip=\(bad.ip ?? "?")" : "  ✓ ожидаемо не прошло: \(bad.error ?? "")")
        }
    }
}

extension LiveChecks {
    static func validateHotRoutingAPI() async -> Bool {
        guard let xrayPath = Engine(workDir: FileManager.default.temporaryDirectory)
            .resolveXrayPath(preferred: nil),
              let apiPort = freeLoopbackPort(),
              let healthPort = freeLoopbackPort() else {
            print("hot routing: Xray или свободный порт не найден")
            return false
        }

        let workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("waypoint-hot-routing-\(UUID().uuidString)", isDirectory: true)
        do {
            try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        } catch {
            print("hot routing: \(error.localizedDescription)")
            return false
        }
        defer { try? FileManager.default.removeItem(at: workDir) }

        let config: JSONValue = .object([
            "log": .object(["loglevel": .string("warning")]),
            "inbounds": .array([.object([
                "tag": .string(XrayConfig.vpnAPIInboundTag),
                "listen": .string("127.0.0.1"),
                "port": .int(apiPort),
                "protocol": .string("dokodemo-door"),
                "settings": .object(["address": .string("127.0.0.1")]),
            ])]),
            "outbounds": .array([
                .object(["tag": .string("direct"), "protocol": .string("freedom")]),
                .object(["tag": .string("block"), "protocol": .string("blackhole")]),
            ]),
            "routing": .object(["rules": .array([
                .object([
                    "type": .string("field"),
                    "inboundTag": .array([.string(XrayConfig.vpnAPIInboundTag)]),
                    "outboundTag": .string(XrayConfig.vpnAPITag),
                ]),
                .object([
                    "type": .string("field"),
                    "inboundTag": .array([.string("in-test")]),
                    "outboundTag": .string("direct"),
                    "ruleTag": .string("test-route"),
                ]),
            ])]),
            "api": .object([
                "tag": .string(XrayConfig.vpnAPITag),
                "services": .array([.string("RoutingService"), .string("HandlerService")]),
            ]),
        ])
        let configURL = workDir.appendingPathComponent("config.json")
        let routingURL = workDir.appendingPathComponent("routing.json")
        let healthInboundURL = workDir.appendingPathComponent("health-inbound.json")
        let healthRuleURL = workDir.appendingPathComponent("health-rule.json")
        do {
            try XrayConfig.encode(config).write(to: configURL)
            try XrayConfig.encode(.object(["routing": .object(["rules": .array([
                .object([
                    "type": .string("field"),
                    "inboundTag": .array([.string(XrayConfig.vpnAPIInboundTag)]),
                    "outboundTag": .string(XrayConfig.vpnAPITag),
                ]),
                .object([
                    "type": .string("field"),
                    "inboundTag": .array([.string("in-test")]),
                    "outboundTag": .string("block"),
                    "ruleTag": .string("test-route"),
                ]),
            ])])])).write(to: routingURL)
            try XrayConfig.encode(.object(["inbounds": .array([.object([
                "tag": .string("health-in"),
                "listen": .string("127.0.0.1"),
                "port": .int(healthPort),
                "protocol": .string("http"),
                "settings": .object([:]),
            ])])])).write(to: healthInboundURL)
            try XrayConfig.encode(.object(["routing": .object(["rules": .array([.object([
                "type": .string("field"),
                "inboundTag": .array([.string("health-in")]),
                "outboundTag": .string("direct"),
                "ruleTag": .string("health-rule"),
            ])])])])).write(to: healthRuleURL)
        } catch {
            print("hot routing: не удалось записать fixture: \(error.localizedDescription)")
            return false
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: xrayPath)
        process.arguments = ["run", "-config", configURL.path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do { try process.run() } catch {
            print("hot routing: Xray не запустился: \(error.localizedDescription)")
            return false
        }
        defer {
            if process.isRunning { process.terminate() }
            process.waitUntilExit()
        }

        guard await waitLoopbackPort(apiPort, timeout: 3) else {
            print("hot routing: API не открыл порт")
            return false
        }
        let pid = process.processIdentifier
        let applied = runProcess(
            xrayPath,
            [
                "api", "adrules", "--server=127.0.0.1:\(apiPort)",
                "--timeout=2", routingURL.path,
            ]
        )
        let listed = runProcess(
            xrayPath,
            [
                "api", "lsrules", "--server=127.0.0.1:\(apiPort)",
                "--timeout=2",
            ]
        )
        let inboundAdded = runProcess(
            xrayPath,
            [
                "api", "adi", "--server=127.0.0.1:\(apiPort)",
                "--timeout=2", healthInboundURL.path,
            ]
        )
        let healthRuleAdded = runProcess(
            xrayPath,
            [
                "api", "adrules", "--server=127.0.0.1:\(apiPort)",
                "--timeout=2", "-append", healthRuleURL.path,
            ]
        )
        let healthCurl = runProcess(
            "/usr/bin/curl",
            [
                "--silent", "--show-error", "--output", "/dev/null",
                "--write-out", "%{http_code}", "--max-time", "7",
                "--proxy", "http://127.0.0.1:\(healthPort)",
                XrayConfig.connectivityProbeURL,
            ]
        )
        _ = runProcess(
            xrayPath,
            [
                "api", "rmrules", "--server=127.0.0.1:\(apiPort)",
                "--timeout=2", "health-rule",
            ]
        )
        _ = runProcess(
            xrayPath,
            [
                "api", "rmi", "--server=127.0.0.1:\(apiPort)",
                "--timeout=2", "health-in",
            ]
        )
        let ok = applied.code == 0
            && listed.code == 0
            && listed.output.contains("block")
            && inboundAdded.code == 0
            && healthRuleAdded.code == 0
            && healthCurl.code == 0
            && healthCurl.output == "204"
            && process.isRunning
            && process.processIdentifier == pid
        print(ok
            ? "hot routing: правила заменены без смены Xray pid=\(pid)"
            : "hot routing: FAIL apply=\(applied.code) list=\(listed.code) health=\(healthCurl.code)/\(healthCurl.output) output=\(listed.output)")
        return ok
    }

    private static func runProcess(_ executable: String, _ arguments: [String]) -> (code: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        do { try process.run() } catch { return (-1, error.localizedDescription) }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }

    private static func freeLoopbackPort() -> Int? {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        guard withUnsafePointer(to: &address, {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }) == 0 else { return nil }
        var actual = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        guard withUnsafeMutablePointer(to: &actual, {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(descriptor, $0, &length)
            }
        }) == 0 else { return nil }
        return Int(UInt16(bigEndian: actual.sin_port))
    }

    private static func waitLoopbackPort(_ port: Int, timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let descriptor = socket(AF_INET, SOCK_STREAM, 0)
            if descriptor >= 0 {
                var address = sockaddr_in()
                address.sin_family = sa_family_t(AF_INET)
                address.sin_port = UInt16(port).bigEndian
                address.sin_addr.s_addr = inet_addr("127.0.0.1")
                address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                let connected = withUnsafePointer(to: &address) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        connect(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                } == 0
                close(descriptor)
                if connected { return true }
            }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return false
    }

    /// Пакетная проверка того же механизма, который заполняет latency-badge в UI.
    static func runTunnelLatencies() async -> Bool {
        let store = Store()
        let state = store.snapshot()
        let limit = ProcessInfo.processInfo.environment["WAYPOINT_LATENCY_LIMIT"].flatMap(Int.init)
        let tunnels = limit.map { Array(state.tunnels.prefix(max(0, $0))) } ?? state.tunnels
        guard !tunnels.isEmpty else {
            print("latency live: нет туннелей")
            return false
        }

        let workDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("waypoint-latency-live-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: workDir) }
        let engine = Engine(workDir: workDir)
        let started = Date()
        let results = await engine.testTunnels(tunnels, settings: state.settings) { id, result in
            let readyAfter = Date().timeIntervalSince(started)
            print(
                "latency live: готов \(id) за \(String(format: "%.1f", readyAfter)) сек. "
                + "(\(result.latencyMs ?? -1) ms)"
            )
        }
        let elapsed = Date().timeIntervalSince(started)

        var successful = 0
        for tunnel in tunnels {
            guard let result = results[tunnel.id] else {
                print("latency live: \(tunnel.name): нет результата")
                continue
            }
            if result.ok, let latency = result.latencyMs {
                successful += 1
                print("latency live: \(tunnel.name): \(latency) ms · \(result.ip ?? "?") · \(result.loc ?? "?")")
            } else {
                print("latency live: \(tunnel.name): FAIL · \(result.error ?? "неизвестная ошибка")")
            }
        }
        print(
            "latency live: получено \(results.count)/\(tunnels.count), "
            + "доступно \(successful), время \(String(format: "%.1f", elapsed)) сек."
        )
        return results.count == tunnels.count && successful > 0
    }

    /// Сквозная диагностика системного VPN. В отличие от обычных тестов она
    /// действительно вызывает root-helper, проверяет маршруты и HTTPS, а затем
    /// штатно снимает маршруты. Helper также следит за PID этого процесса и
    /// выполнит cleanup, если диагностический процесс будет аварийно завершён.
    static func runSystemVPN() async -> Bool {
        let store = Store()
        let state = store.snapshot()
        var diagnosticSettings = state.settings
        diagnosticSettings.logLevel = "debug"
        // Persistent daemon по дизайну принимает только канонический каталог
        // приложения; временный /tmp workdir корректно отклоняется как malformed.
        let workDir = store.workDir
        let bundlePath = ProcessInfo.processInfo.environment["WAYPOINT_SYSTEM_VPN_BUNDLE"]
            ?? URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent("build/Waypoint.app", isDirectory: true).path
        let bundleHelpers = URL(fileURLWithPath: bundlePath)
            .appendingPathComponent("Contents/Helpers", isDirectory: true)
        let bundledHelper = bundleHelpers.appendingPathComponent(SystemVPNRuntime.helperName).path
        let bundledLauncher = bundleHelpers.appendingPathComponent(SystemVPNRuntime.launcherName).path
        let fm = FileManager.default
        let engine = Engine(
            workDir: workDir,
            vpnHelperPathOverride: fm.isExecutableFile(atPath: bundledHelper) ? bundledHelper : nil,
            vpnLauncherPathOverride: fm.isExecutableFile(atPath: bundledLauncher) ? bundledLauncher : nil
        )

        guard let target = state.systemVPN.target,
              state.systemVPNMainRouteIssue() == nil else {
            print("system VPN: основной маршрут отсутствует или недоступен")
            return false
        }

        let selectedName: String
        switch target.kind {
        case .tunnel:
            selectedName = state.tunnel(id: target.referenceId)?.name ?? "туннель недоступен"
        case .chain:
            selectedName = state.vpnTunnelChain(id: target.referenceId)?.name ?? "цепочка недоступна"
        case .fallback:
            selectedName = state.vpnFallbackGroup(id: target.referenceId)?.name ?? "fallback недоступен"
        case .direct, .block:
            selectedName = target.kind.rawValue
        }
        print("system VPN: основной маршрут=\(selectedName)")
        print("system VPN: запускаю helper; подтверди запрос macOS…")

        do {
            try await engine.startSystemVPN(state: state, settings: diagnosticSettings)
        } catch {
            print("system VPN: ошибка старта: \(error.localizedDescription)")
            return false
        }

        var printedLogs = 0
        var readyStatus: EngineStatus?
        let deadline = Date().addingTimeInterval(75)
        while Date() < deadline {
            try? await Task.sleep(for: .milliseconds(250))

            let entries = await engine.allLogs()
            if entries.count > printedLogs {
                for entry in entries.dropFirst(printedLogs) {
                    print("  \(entry.text)")
                }
                printedLogs = entries.count
            }

            let status = await engine.status()
            if status.ready {
                readyStatus = status
                break
            }
            if !status.running {
                print("system VPN: helper завершился до готовности: \(status.lastError ?? "без подробностей")")
                break
            }
        }

        var passed = false
        if let status = readyStatus, let interface = status.vpnInterface {
            print("system VPN: READY, interface=\(interface), xray_pid=\(status.pid.map(String.init) ?? "-")")

            let lowRoute = capture("/sbin/route", ["-n", "get", "1.1.1.1"], timeout: 4)
            let highRoute = capture("/sbin/route", ["-n", "get", "200.1.1.1"], timeout: 4)
            let lowOK = lowRoute.contains("interface: \(interface)")
            let highOK = highRoute.contains("interface: \(interface)")
            print("system VPN: route 1.1.1.1 -> \(routeInterface(lowRoute) ?? "?")")
            print("system VPN: route 200.1.1.1 -> \(routeInterface(highRoute) ?? "?")")

            let https = capture(
                "/usr/bin/curl",
                ["-4", "-fsS", "--connect-timeout", "10", "--max-time", "25",
                 "https://cp.cloudflare.com/cdn-cgi/trace"],
                timeout: 30,
                includeStandardError: true
            )
            let trace = https.components(separatedBy: .newlines)
                .filter { $0.hasPrefix("ip=") || $0.hasPrefix("loc=") }
                .joined(separator: " ")
            let httpsOK = !trace.isEmpty
            print(httpsOK ? "system VPN: HTTPS OK: \(trace)" : "system VPN: HTTPS FAIL: \(https.suffix(800))")

            // В единой архитектуре TUN и локальные SOCKS/HTTP — inbound одного
            // Xray. Проверяем оба пути в одном процессе, а не только system route.
            var localProxyOK = true
            if let proxy = state.proxies.first(where: { $0.enabled && $0.port > 0 }) {
                let host = proxy.listen == "0.0.0.0" || proxy.listen == "::"
                    ? "127.0.0.1"
                    : proxy.listen
                var proxyArguments = [
                    "-4", "-fsS", "--connect-timeout", "10", "--max-time", "25",
                ]
                if proxy.kind == .socks {
                    proxyArguments += ["--socks5-hostname", "\(host):\(proxy.port)"]
                } else {
                    proxyArguments += ["--proxy", "http://\(host):\(proxy.port)"]
                }
                if let auth = proxy.auth, !auth.isEmpty {
                    proxyArguments += ["--proxy-user", "\(auth.user):\(auth.pass)"]
                }
                proxyArguments.append("https://cp.cloudflare.com/cdn-cgi/trace")
                let proxyHTTPS = capture(
                    "/usr/bin/curl",
                    proxyArguments,
                    timeout: 30,
                    includeStandardError: true
                )
                let proxyTrace = proxyHTTPS.components(separatedBy: .newlines)
                    .filter { $0.hasPrefix("ip=") || $0.hasPrefix("loc=") }
                    .joined(separator: " ")
                localProxyOK = !proxyTrace.isEmpty
                print(
                    localProxyOK
                        ? "system VPN: тот же Xray, \(proxy.kind.label) OK: \(proxyTrace)"
                        : "system VPN: локальный \(proxy.kind.label) FAIL: \(proxyHTTPS.suffix(800))"
                )
            }

            // Симулируем network-path event на текущем интерфейсе. Во время
            // rebind часто снимаем route: ни один sample не должен уйти с utun.
            // Xray обновляется внутри того же helper, чтобы stale transport-
            // сокеты предыдущей Wi-Fi сети не оставались жить.
            let routeSampler = Task.detached(priority: .utility) {
                var interfaces: [String] = []
                for _ in 0..<80 {
                    let route = capture("/sbin/route", ["-n", "get", "1.1.1.1"], timeout: 2)
                    interfaces.append(routeInterface(route) ?? "?")
                    usleep(10_000)
                }
                return interfaces
            }
            var rebindError: String?
            let rebindStartedAt = Date()
            do {
                try await engine.reconnectForNetworkChange(
                    state: state,
                    settings: diagnosticSettings
                )
            } catch {
                rebindError = error.localizedDescription
            }
            let rebindDuration = Date().timeIntervalSince(rebindStartedAt)
            let sampledInterfaces = await routeSampler.value
            let reboundStatus = await engine.status()
            let rebindOK = rebindError == nil
                && reboundStatus.ready
                && reboundStatus.vpnInterface == interface
                && reboundStatus.pid != nil
                && reboundStatus.pid != status.pid
                && sampledInterfaces.allSatisfy { $0 == interface }
                && rebindDuration < 3
            if rebindOK {
                print(
                    "system VPN: network rebind OK за "
                    + String(format: "%.2f", rebindDuration)
                    + " с; utun сохранён, Xray transport обновлён, Direct samples=0"
                )
            } else {
                let directSamples = sampledInterfaces.filter { $0 != interface }
                print(
                    "system VPN: network rebind FAIL за "
                    + String(format: "%.2f", rebindDuration)
                    + " с: \(rebindError ?? "pid/route changed"), non-utun=\(directSamples)"
                )
            }

            let reboundHTTPS = capture(
                "/usr/bin/curl",
                ["-4", "-fsS", "-o", "/dev/null", "--connect-timeout", "10", "--max-time", "25",
                 "https://cp.cloudflare.com/generate_204"],
                timeout: 30,
                includeStandardError: true
            )
            let reboundHTTPSOK = reboundHTTPS.isEmpty
            print(reboundHTTPSOK ? "system VPN: HTTPS после rebind OK" : "system VPN: HTTPS после rebind FAIL")
            passed = lowOK && highOK && httpsOK && localProxyOK && rebindOK && reboundHTTPSOK

            if let rawHold = ProcessInfo.processInfo.environment["WAYPOINT_SYSTEM_VPN_HOLD_SECONDS"],
               let holdSeconds = UInt64(rawHold), holdSeconds > 0 {
                print("system VPN: держу подключение ещё \(holdSeconds) сек. для проверки браузера")
                try? await Task.sleep(for: .seconds(holdSeconds))
            }
        } else if Date() >= deadline {
            print("system VPN: таймаут ожидания готовности")
        }

        await engine.stop()
        try? await Task.sleep(for: .milliseconds(300))
        let cleanupRoute = capture("/sbin/route", ["-n", "get", "1.1.1.1"], timeout: 4)
        print("system VPN: остановлен, route 1.1.1.1 -> \(routeInterface(cleanupRoute) ?? "?")")
        return passed
    }

    private static func capture(
        _ executable: String,
        _ arguments: [String],
        timeout: TimeInterval,
        includeStandardError: Bool = false
    ) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = includeStandardError ? pipe : FileHandle.nullDevice

        do {
            try process.run()
        } catch {
            return "launch error: \(error.localizedDescription)"
        }

        let handle = pipe.fileHandleForReading
        let collected = LockedData()
        let reader = Thread {
            collected.store(handle.readDataToEndOfFile())
        }
        reader.start()
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning, Date() < deadline { usleep(10_000) }
        if process.isRunning { process.terminate() }
        let readDeadline = Date().addingTimeInterval(1)
        while !reader.isFinished, Date() < readDeadline { usleep(2_000) }
        let data = collected.load()
        return String(data: data, encoding: .utf8) ?? ""
    }

    private static func routeInterface(_ output: String) -> String? {
        output.components(separatedBy: .newlines)
            .first { $0.trimmingCharacters(in: .whitespaces).hasPrefix("interface:") }?
            .split(separator: ":", maxSplits: 1)
            .last
            .map { $0.trimmingCharacters(in: .whitespaces) }
    }

    /// Проверяет новый RU-split на реальном установленном xray, не меняя
    /// сохранённый state.json и не запуская локальные порты.
    static func validateRoutingProfile() async -> Bool {
        let store = Store()
        var state = store.snapshot()
        guard let tunnel = state.tunnels.first else {
            print("routing validation: нет туннелей")
            return false
        }

        if state.proxies.isEmpty {
            state.proxies = [
                LocalProxy(
                    id: "p_routing_validation",
                    name: "Routing validation",
                    kind: .socks,
                    port: 10998,
                    tunnelId: tunnel.id,
                    routingMode: .directRussia
                )
            ]
        } else {
            state.proxies[0].enabled = true
            state.proxies[0].tunnelId = tunnel.id
            state.proxies[0].routingMode = .directRussia
        }
        state.persistentRoutes = [PersistentRoute(
            id: "r_validation",
            name: "Routing validation override",
            targets: "example.com\n1.1.1.0/24",
            tunnelId: tunnel.id,
            appliesToSystemVPN: false,
            appliesToLocalProxies: true
        )]

        state.systemVPN = SystemVPNConfiguration(tunnelId: tunnel.id)
        state.vpnRoutingPolicies = [
            VPNRoutingPolicy(
                id: "vr_runtime_validation",
                name: "Runtime policy validation",
                targets: "geosite:category-ru\ngeoip:ru",
                target: .tunnel(tunnel.id)
            )
        ]

        if state.tunnels.count >= 2 {
            let second = state.tunnels[1]
            let chain = VPNTunnelChain(
                id: "vc_runtime_validation",
                name: "Runtime chain validation",
                tunnelIds: [tunnel.id, second.id]
            )
            state.vpnTunnelChains = [chain]
            state.vpnFallbackGroups = [
                VPNFallbackGroup(
                    id: "vf_runtime_validation",
                    name: "Runtime fallback validation",
                    members: [
                        VPNFallbackMember(id: "fm_runtime_primary", target: .tunnel(tunnel.id)),
                        VPNFallbackMember(id: "fm_runtime_chain", target: .chain(chain.id)),
                    ],
                    maxLatencyMs: 1200,
                    finalAction: .block
                )
            ]
            state.vpnRoutingPolicies.append(contentsOf: [
                VPNRoutingPolicy(
                    id: "vr_runtime_chain",
                    name: "Runtime chain rule",
                    targets: "chain-validation.example",
                    target: .chain(chain.id)
                ),
                VPNRoutingPolicy(
                    id: "vr_runtime_fallback",
                    name: "Runtime fallback rule",
                    targets: "fallback-validation.example",
                    target: .fallback("vf_runtime_validation")
                ),
            ])
            // Тем же реальным `xray run -test` проверяем, что fallback можно
            // назначить непосредственно локальному proxy inbound.
            state.proxies[0].target = .fallback("vf_runtime_validation")
        }

        let workDir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("waypoint-routing-validation")
        let engine = Engine(workDir: workDir)
        do {
            let result = try await engine.validate(
                state: state,
                settings: state.settings,
                systemVPNInterface: "utun99"
            )
            print(result.ok ? "routing validation: Configuration OK" : result.output)
            return result.ok
        } catch {
            print("routing validation: \(error.localizedDescription)")
            return false
        }
    }

    static func dumpTestConfig() {
        let store = Store()
        let state = store.snapshot()
        guard let t = state.tunnels.first else { return }
        let cfg = XrayConfig.buildTest(tunnel: t, port: 10999, bypassInterface: "en0")
        if let data = try? XrayConfig.encode(cfg), let s = String(data: data, encoding: .utf8) {
            print(s)
        }
    }
}
