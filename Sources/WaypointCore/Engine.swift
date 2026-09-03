import Foundation

/// Запись в журнале движка.
public struct LogEntry: Identifiable, Sendable, Equatable {
    public let id = UUID()
    public let date: Date
    public let text: String

    public init(_ text: String, date: Date = Date()) {
        self.text = text
        self.date = date
    }

    public var timestamp: String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss"
        return f.string(from: date)
    }
}

public enum EngineMode: String, Sendable, Equatable {
    case localProxy
    case systemVPN
}

public enum VPNConfigurationState: String, Sendable, Equatable {
    case stable
    case switching
    case recovered
    case degraded
}

public struct EngineStatus: Sendable, Equatable {
    public var running: Bool
    public var pid: Int32?
    public var xrayPath: String?
    public var lastError: String?
    public var mode: EngineMode?
    public var ready: Bool
    public var vpnInterface: String?
    public var vpnConfigurationState: VPNConfigurationState

    public init(
        running: Bool = false,
        pid: Int32? = nil,
        xrayPath: String? = nil,
        lastError: String? = nil,
        mode: EngineMode? = nil,
        ready: Bool = false,
        vpnInterface: String? = nil,
        vpnConfigurationState: VPNConfigurationState = .stable
    ) {
        self.running = running
        self.pid = pid
        self.xrayPath = xrayPath
        self.lastError = lastError
        self.mode = mode
        self.ready = ready
        self.vpnInterface = vpnInterface
        self.vpnConfigurationState = vpnConfigurationState
    }
}

public struct BypassInfo: Sendable, Equatable {
    public var enabled: Bool
    public var active: String?
    public var override: String?
    public var status: NetworkInterface.BypassStatus

    public init(
        enabled: Bool,
        active: String?,
        override: String?,
        status: NetworkInterface.BypassStatus
    ) {
        self.enabled = enabled
        self.active = active
        self.override = override
        self.status = status
    }
}

public enum EngineError: LocalizedError {
    case xrayNotFound
    case noProxies
    case invalidSystemVPNRoute(String)
    case noPhysicalInterface
    case vpnHelperNotFound
    case vpnLauncherNotFound
    case noFreeVPNInterface
    case startFailed(String)
    case testFailed(String)

    public var errorDescription: String? {
        switch self {
        case .xrayNotFound:
            return "Не найден бинарник xray. Установи: brew install xray"
        case .noProxies:
            return "Нет активных локальных прокси для запуска"
        case .invalidSystemVPNRoute(let issue):
            return "Основной маршрут VPN недоступен: \(issue)"
        case .noPhysicalInterface:
            return "Не найден активный физический сетевой интерфейс"
        case .vpnHelperNotFound:
            return "VPN helper не найден. Пересобери приложение через make install"
        case .vpnLauncherNotFound:
            return "VPN launcher не найден. Пересобери приложение через make install"
        case .noFreeVPNInterface:
            return "Не удалось найти свободный системный utun-интерфейс"
        case .startFailed(let m):
            return m
        case .testFailed(let m):
            return m
        }
    }
}

/// Управление процессом xray.
///
/// Actor: процесс, журнал и статус меняются и из UI, и из фоновых задач
/// (наблюдатель за сетью, тест туннеля) — actor сериализует доступ без ручных
/// блокировок.
public actor Engine {
    private let workDir: URL
    private let vpnHelperPathOverride: String?
    private let vpnLauncherPathOverride: String?
    private var process: Process?
    private var latencyProcess: Process?
    private var activeMode: EngineMode?
    private var vpnReady = false
    private var vpnInterfaceName: String?
    private var vpnXrayPID: Int32?
    private var vpnMonitorTask: Task<Void, Never>?
    private var vpnFallbackMonitorTask: Task<Void, Never>?
    private var vpnConfigurationMutationBusy = false
    private var vpnConfigurationMutationWaiters: [CheckedContinuation<Void, Never>] = []
    private var vpnAPIPort: Int?
    private var vpnMetricsPort: Int?
    private var vpnActiveConfig: JSONValue?
    private var vpnRuntimeOutbounds: [String: JSONValue] = [:]
    private var vpnHotUpdateDirty = false
    private var vpnConfigurationState: VPNConfigurationState = .stable
    private var vpnReadyAt: Date?
    private var vpnTerminalOverrides: Set<String> = []
    private var monitoredFallbackGroups: [VPNFallbackGroup] = []
    private var vpnFallbackSelectors: [String: VPNFallbackStableSelector] = [:]
    private var vpnFallbackOverridesReady = false
    private var vpnRuntimePreparationBusy = false
    private var vpnRuntimeToken = UUID()
    private var vpnWarmedOutboundTags: Set<String> = []
    private var fallbackRuntimeStatuses: [String: VPNFallbackRuntimeStatus] = [:]
    private var vpnLogOffset: UInt64 = 0
    private var logs: [LogEntry] = []
    private var logFlushTask: Task<Void, Never>?
    private var lastError: String?
    private var resolvedXrayPath: String?

    private static let maxLogLines = 400
    private static let logFlushDelay: Duration = .milliseconds(100)

    /// Куда уходят новые строки журнала и смены статуса.
    private var logHandler: (@Sendable ([LogEntry]) -> Void)?
    private var statusHandler: (@Sendable (EngineStatus) -> Void)?
    private var fallbackStatusHandler: (@Sendable ([String: VPNFallbackRuntimeStatus]) -> Void)?

    public init(
        workDir: URL,
        vpnHelperPathOverride: String? = nil,
        vpnLauncherPathOverride: String? = nil
    ) {
        self.workDir = workDir
        self.vpnHelperPathOverride = vpnHelperPathOverride
        self.vpnLauncherPathOverride = vpnLauncherPathOverride
        try? FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
    }

    public func onLogs(_ handler: @escaping @Sendable ([LogEntry]) -> Void) {
        logHandler = handler
        handler(logs)
    }

    public func onStatus(_ handler: @escaping @Sendable (EngineStatus) -> Void) {
        statusHandler = handler
        handler(status())
    }

    public func onFallbackStatuses(
        _ handler: @escaping @Sendable ([String: VPNFallbackRuntimeStatus]) -> Void
    ) {
        fallbackStatusHandler = handler
        handler(fallbackRuntimeStatuses)
    }

    // MARK: - xray

    /// Поиск бинарника xray в стандартных местах.
    public nonisolated func resolveXrayPath(preferred: String?) -> String? {
        var candidates: [String] = []
        if let preferred, !preferred.isEmpty { candidates.append(preferred) }
        candidates += ["/opt/homebrew/bin/xray", "/usr/local/bin/xray", "/usr/bin/xray"]

        let fm = FileManager.default
        for path in candidates where fm.isExecutableFile(atPath: path) {
            return path
        }
        // Последняя попытка — PATH.
        if let out = Shell.run("/usr/bin/which", ["xray"], timeout: 3) {
            let p = out.trimmingCharacters(in: .whitespacesAndNewlines)
            if !p.isEmpty, fm.isExecutableFile(atPath: p) { return p }
        }
        return nil
    }

    public nonisolated func version(of xrayPath: String) -> String? {
        guard let out = Shell.run(xrayPath, ["version"], timeout: 4) else { return nil }
        return out.components(separatedBy: .newlines).first?.trimmingCharacters(in: .whitespaces)
    }

    // MARK: - Обход туннелей

    /// Интерфейс для обхода системных туннелей, либо nil если обход выключен.
    public nonisolated func bypassInterface(for settings: Settings) -> String? {
        guard settings.bypassTunnels else { return nil }
        if !settings.bypassInterface.isEmpty { return settings.bypassInterface }
        return NetworkInterface.detectPhysical()
    }

    public nonisolated func bypassInfo(for settings: Settings) -> BypassInfo {
        BypassInfo(
            enabled: settings.bypassTunnels,
            active: bypassInterface(for: settings),
            override: settings.bypassInterface.isEmpty ? nil : settings.bypassInterface,
            status: NetworkInterface.bypassStatus()
        )
    }

    // MARK: - Статус и журнал

    public func status() -> EngineStatus {
        let processRunning = process?.isRunning ?? false
        return EngineStatus(
            running: processRunning,
            pid: activeMode == .systemVPN ? vpnXrayPID : process?.processIdentifier,
            xrayPath: resolvedXrayPath,
            lastError: lastError,
            mode: processRunning ? activeMode : nil,
            ready: processRunning && (activeMode != .systemVPN || vpnReady),
            vpnInterface: activeMode == .systemVPN ? vpnInterfaceName : nil,
            vpnConfigurationState: activeMode == .systemVPN ? vpnConfigurationState : .stable
        )
    }

    public func isRunning() -> Bool { process?.isRunning ?? false }

    public func allLogs() -> [LogEntry] { logs }

    public func clearLogs() {
        logFlushTask?.cancel()
        logFlushTask = nil
        logs.removeAll()
        logHandler?(logs)
    }

    private func log(_ text: String) {
        logs.append(LogEntry(text))
        trimLogs()
        scheduleLogFlush()
    }

    private func trimLogs() {
        guard logs.count > Self.maxLogLines else { return }
        logs.removeFirst(logs.count - Self.maxLogLines)
    }

    /// Xray может выдать сотни строк за секунду. Передача полного массива в
    /// SwiftUI на каждую строку создаёт очередь обновлений и подвешивает окно,
    /// поэтому объединяем события в короткие пачки.
    private func scheduleLogFlush() {
        guard logFlushTask == nil else { return }
        logFlushTask = Task { [weak self] in
            try? await Task.sleep(for: Self.logFlushDelay)
            guard !Task.isCancelled else { return }
            await self?.flushLogs()
        }
    }

    private func flushLogs() {
        logFlushTask = nil
        logHandler?(logs)
    }

    private func emitStatus() {
        statusHandler?(status())
    }

    // MARK: - Запуск

    /// Проверка конфига через `xray run -test`.
    public func validate(
        state: AppState,
        settings: Settings,
        systemVPNInterface: String? = nil
    ) throws -> (ok: Bool, output: String) {
        guard let xrayPath = resolveXrayPath(preferred: settings.xrayPath) else {
            throw EngineError.xrayNotFound
        }
        let config = XrayConfig.build(
            state: state,
            logLevel: settings.logLevel,
            bypassInterface: bypassInterface(for: settings),
            systemVPNInterface: systemVPNInterface
        )
        return try validate(config: config, xrayPath: xrayPath, systemVPNInterface: systemVPNInterface)
    }

    private func validate(
        config sourceConfig: JSONValue,
        xrayPath: String,
        systemVPNInterface: String?
    ) throws -> (ok: Bool, output: String) {
        var config = sourceConfig
        if systemVPNInterface != nil,
           var inbounds = config["inbounds"]?.arrayValue,
           let index = inbounds.firstIndex(where: {
               $0["tag"]?.stringValue == XrayConfig.systemVPNTag
           }) {
            guard let validationPort = Net.freePort() else {
                return (false, "Не удалось открыть локальный порт проверки Xray")
            }
            // `xray run -test` на macOS всё равно пытается создать TUN и без
            // root возвращает EPERM. Для schema-проверки routing/outbounds
            // подменяем только validation-inbound, сохраняя тот же tag.
            inbounds[index] = .object([
                "tag": .string(XrayConfig.systemVPNTag),
                "listen": .string("127.0.0.1"),
                "port": .int(validationPort),
                "protocol": .string("socks"),
                "settings": .object(["auth": .string("noauth"), "udp": .bool(true)]),
                "sniffing": .object([
                    "enabled": .bool(true),
                    "destOverride": .array([.string("http"), .string("tls"), .string("quic")]),
                ]),
            ])
            config["inbounds"] = .array(inbounds)
        }
        let tmp = workDir.appendingPathComponent("xray-validate-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: tmp) }
        try XrayConfig.encode(config).write(to: tmp)

        guard let result = Shell.runResult(
            xrayPath,
            ["run", "-test", "-config", tmp.path],
            timeout: 15
        ) else {
            return (false, "Не удалось запустить проверку Xray")
        }
        return (
            result.succeeded && result.output.contains("Configuration OK"),
            result.output
        )
    }

    public func start(state: AppState, settings: Settings) throws {
        stopLatencyProcess()
        if process?.isRunning == true {
            stop()
            guard process?.isRunning != true else {
                throw EngineError.startFailed("Предыдущий процесс ещё останавливается")
            }
        }
        lastError = nil

        guard let xrayPath = resolveXrayPath(preferred: settings.xrayPath) else {
            lastError = EngineError.xrayNotFound.errorDescription
            emitStatus()
            throw EngineError.xrayNotFound
        }
        resolvedXrayPath = xrayPath

        let bypass = bypassInterface(for: settings)
        let config = XrayConfig.build(state: state, logLevel: settings.logLevel, bypassInterface: bypass)

        guard let inbounds = config["inbounds"]?.arrayValue, !inbounds.isEmpty else {
            throw EngineError.noProxies
        }

        let configPath = workDir.appendingPathComponent("xray-config.json")
        try XrayConfig.encode(config).write(to: configPath)

        log("▶ Запуск xray (\(xrayPath))")
        if let bypass {
            let names = NetworkInterface.activeTunnels().map(\.name).joined(separator: ", ")
            log("⇄ Обход туннелей: трафик привязан к \(bypass)" +
                (names.isEmpty ? " (активных туннелей нет)" : " (активные туннели: \(names))"))
        } else {
            log("⇄ Обход туннелей выключен — трафик идёт по системным маршрутам")
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: xrayPath)
        proc.arguments = ["run", "-config", configPath.path]
        proc.currentDirectoryURL = workDir

        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe

        // Вывод xray читаем построчно и складываем в журнал.
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            let lines = text.components(separatedBy: .newlines)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            guard !lines.isEmpty, let self else { return }
            Task { await self.appendLines(lines) }
        }

        proc.terminationHandler = { [weak self] p in
            guard let self else { return }
            Task { await self.handleExit(processID: p.processIdentifier, code: p.terminationStatus) }
        }

        do {
            try proc.run()
        } catch {
            lastError = error.localizedDescription
            log("Ошибка запуска: \(error.localizedDescription)")
            emitStatus()
            throw EngineError.startFailed(error.localizedDescription)
        }

        process = proc
        activeMode = .localProxy
        vpnReady = false
        vpnInterfaceName = nil
        vpnXrayPID = nil
        clearSystemVPNRuntimeState()
        emitStatus()
    }

    private func appendLines(_ lines: [String]) {
        guard !lines.isEmpty else { return }
        var statusChanged = false
        for line in lines {
            logs.append(LogEntry(line))
            if activeMode == .systemVPN,
               let authorizationError = SystemVPNRuntime.authorizationError(from: line) {
                lastError = authorizationError
                statusChanged = true
            }
        }
        trimLogs()
        scheduleLogFlush()
        if statusChanged { emitStatus() }
    }

    private func handleExit(processID: Int32, code: Int32) {
        guard process?.processIdentifier == processID else { return }
        if activeMode == .systemVPN {
            pollVPNRuntime()
            log("■ Системный VPN завершился (code=\(code))")
            if code != 0, lastError == nil {
                lastError = "Не удалось запустить или удержать системный VPN (code=\(code))"
            }
        } else {
            log("■ xray завершился (code=\(code))")
            if code != 0 { lastError = "xray завершился с кодом \(code)" }
        }
        vpnMonitorTask?.cancel()
        vpnMonitorTask = nil
        stopVPNFallbackMonitoring()
        process = nil
        activeMode = nil
        vpnReady = false
        vpnInterfaceName = nil
        vpnXrayPID = nil
        clearSystemVPNRuntimeState()
        emitStatus()
    }

    public func stop() {
        stopLatencyProcess()
        guard let proc = process else { return }

        if activeMode == .systemVPN {
            log("■ Остановка системного VPN…")
            let files = SystemVPNFiles(workDir: workDir)
            FileManager.default.createFile(atPath: files.stop.path, contents: Data())

            // Helper сначала убирает маршруты, затем завершает xray. Не убиваем
            // osascript напрямую: это могло бы оставить root-helper сиротой.
            let deadline = Date().addingTimeInterval(6)
            while proc.isRunning, Date() < deadline {
                usleep(50_000)
            }
            if proc.isRunning {
                // До успешной авторизации root-shell ещё не создавал лог.
                // В этом состоянии stop-файл некому прочитать, поэтому можно
                // безопасно отменить только osascript и закрыть скрытый диалог.
                if !FileManager.default.fileExists(atPath: files.log.path) {
                    proc.terminate()
                    let cancelDeadline = Date().addingTimeInterval(1)
                    while proc.isRunning, Date() < cancelDeadline {
                        usleep(20_000)
                    }
                    if proc.isRunning { kill(proc.processIdentifier, SIGKILL) }
                    log("■ Запрос авторизации VPN отменён")
                } else {
                    // Если лог уже создан, helper мог владеть маршрутами. Его
                    // нельзя осиротить принудительным завершением osascript.
                    lastError = "VPN helper не ответил на остановку; маршруты будут сняты при завершении приложения"
                    log("⚠ \(lastError!)")
                    emitStatus()
                    return
                }
            }
        }

        if let pipe = proc.standardOutput as? Pipe {
            pipe.fileHandleForReading.readabilityHandler = nil
        }
        proc.terminationHandler = nil

        if proc.isRunning {
            proc.terminate()
            // Дать процессу закрыться штатно, иначе добиваем.
            let deadline = Date().addingTimeInterval(1.5)
            while proc.isRunning, Date() < deadline {
                usleep(20_000)
            }
            if proc.isRunning {
                kill(proc.processIdentifier, SIGKILL)
            }
        }
        vpnMonitorTask?.cancel()
        vpnMonitorTask = nil
        stopVPNFallbackMonitoring()
        pollVPNRuntime()
        process = nil
        activeMode = nil
        vpnReady = false
        vpnInterfaceName = nil
        vpnXrayPID = nil
        clearSystemVPNRuntimeState()
        emitStatus()
    }

    public func restart(state: AppState, settings: Settings) async throws {
        guard process?.isRunning == true else { return }
        log("↻ Перезапуск из-за изменения конфигурации")
        if activeMode == .systemVPN {
            await acquireVPNConfigurationMutation()
            defer { releaseVPNConfigurationMutation() }
            // Пока вызов ждал предыдущий reload, пользователь мог выключить
            // VPN. В таком случае устаревшую конфигурацию применять нельзя.
            guard process?.isRunning == true, activeMode == .systemVPN else { return }
            try await reloadSystemVPN(state: state, settings: settings)
            return
        }
        stop()
        try start(state: state, settings: settings)
    }

    private func acquireVPNConfigurationMutation() async {
        if !vpnConfigurationMutationBusy {
            vpnConfigurationMutationBusy = true
            return
        }
        await withCheckedContinuation { continuation in
            vpnConfigurationMutationWaiters.append(continuation)
        }
    }

    private func releaseVPNConfigurationMutation() {
        if vpnConfigurationMutationWaiters.isEmpty {
            vpnConfigurationMutationBusy = false
        } else {
            vpnConfigurationMutationWaiters.removeFirst().resume()
        }
    }

    /// Смена Wi-Fi/Ethernet требует заново получить physical gateway и scoped
    /// default route. Root-helper держит /1 kill-switch маршруты на utun во время
    /// обновления, поэтому системный трафик не получает окна для прямого выхода.
    public func reconnectForNetworkChange(state: AppState, settings: Settings) async throws {
        guard process?.isRunning == true else { return }
        if activeMode == .systemVPN {
            await acquireVPNConfigurationMutation()
            defer { releaseVPNConfigurationMutation() }
            guard process?.isRunning == true, activeMode == .systemVPN else { return }
            log("↻ Сеть изменилась; безопасно переносим VPN без снятия kill-switch")
            try await reloadSystemVPN(state: state, settings: settings, networkRebind: true)
            return
        }
        try await restart(state: state, settings: settings)
    }

    // MARK: - Системный VPN

    /// Для полного маршрута bypass обязателен независимо от пользовательского
    /// переключателя: иначе исходящие соединения xray снова попадут в utun.
    private nonisolated func systemVPNBypassInterface(for settings: Settings) -> String? {
        if !settings.bypassInterface.isEmpty { return settings.bypassInterface }
        return NetworkInterface.detectPhysical()
    }

    private func validateSystemVPNState(_ state: AppState) throws {
        if let issue = state.systemVPNMainRouteIssue() {
            throw EngineError.invalidSystemVPNRoute(issue)
        }
    }

    private nonisolated static func outboundsByTag(in config: JSONValue) -> [String: JSONValue] {
        Dictionary(uniqueKeysWithValues: (config["outbounds"]?.arrayValue ?? []).compactMap {
            guard let tag = $0["tag"]?.stringValue else { return nil }
            return (tag, $0)
        })
    }

    public func startSystemVPN(state: AppState, settings: Settings) throws {
        stopLatencyProcess()
        if process?.isRunning == true {
            stop()
            guard process?.isRunning != true else {
                throw EngineError.startFailed("Предыдущий процесс ещё останавливается")
            }
        }
        lastError = nil
        try validateSystemVPNState(state)

        guard let xrayPath = resolveXrayPath(preferred: settings.xrayPath) else {
            throw EngineError.xrayNotFound
        }
        guard let bypass = systemVPNBypassInterface(for: settings) else {
            throw EngineError.noPhysicalInterface
        }
        guard let helperPath = vpnHelperPathOverride ?? SystemVPNRuntime.resolveHelperPath() else {
            throw EngineError.vpnHelperNotFound
        }
        guard let launcherPath = vpnLauncherPathOverride ?? SystemVPNRuntime.resolveLauncherPath() else {
            throw EngineError.vpnLauncherNotFound
        }
        guard let interfaceName = SystemVPNRuntime.availableInterfaceName() else {
            throw EngineError.noFreeVPNInterface
        }

        let fallbackIDs = state.usedVPNFallbackGroupIDs()
        let fallbackGroups = fallbackIDs.compactMap { state.vpnFallbackGroup(id: $0) }
        guard let controlPorts = Net.freePorts(count: 2), controlPorts.count == 2 else {
            throw EngineError.startFailed("Не удалось открыть локальные порты управления VPN")
        }
        let apiPort = controlPorts[0]
        let metricsPort = controlPorts[1]

        let files = SystemVPNFiles(workDir: workDir)
        let config = XrayConfig.build(
            state: state,
            logLevel: settings.logLevel,
            bypassInterface: bypass,
            systemVPNInterface: interfaceName,
            systemVPNAPIPort: apiPort,
            systemVPNMetricsPort: metricsPort
        )
        let validation = try validate(
            config: config,
            xrayPath: xrayPath,
            systemVPNInterface: interfaceName
        )
        guard validation.ok else {
            let detail = validation.output.components(separatedBy: .newlines)
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .last(where: { !$0.isEmpty }) ?? "Xray отверг конфигурацию"
            throw EngineError.startFailed("VPN-конфигурация отклонена до запуска: \(detail)")
        }
        try XrayConfig.encode(config).write(to: files.config, options: .atomic)

        let fm = FileManager.default
        for url in [
            files.stop, files.reload, files.ready, files.result,
            files.candidate, files.rollback, files.log,
        ] {
            try? fm.removeItem(at: url)
        }

        let arguments = SystemVPNRuntime.helperArguments(
            xrayPath: xrayPath,
            helperFiles: files,
            interfaceName: interfaceName,
            workDir: workDir,
            bypassInterface: bypass
        )
        let launcherArguments = SystemVPNRuntime.launcherArguments(
            helperPath: helperPath,
            arguments: arguments,
            files: files
        )

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: launcherPath)
        proc.arguments = launcherArguments
        proc.currentDirectoryURL = workDir

        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty, let text = String(data: data, encoding: .utf8) else { return }
            let lines = text.components(separatedBy: .newlines)
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }
            guard !lines.isEmpty, let self else { return }
            Task { await self.appendLines(lines) }
        }
        proc.terminationHandler = { [weak self] p in
            guard let self else { return }
            Task { await self.handleExit(processID: p.processIdentifier, code: p.terminationStatus) }
        }

        log("▶ Запрос системного VPN через \(interfaceName)")
        log("⇄ Внешние соединения xray привязаны к \(bypass)")
        log("🔐 При первом подключении macOS один раз установит VPN-сервис с правами администратора")

        do {
            try proc.run()
        } catch {
            lastError = error.localizedDescription
            log("Ошибка запуска VPN helper: \(error.localizedDescription)")
            emitStatus()
            throw EngineError.startFailed(error.localizedDescription)
        }

        resolvedXrayPath = xrayPath
        process = proc
        activeMode = .systemVPN
        vpnReady = false
        vpnInterfaceName = interfaceName
        vpnXrayPID = nil
        vpnLogOffset = 0
        vpnAPIPort = apiPort
        vpnMetricsPort = metricsPort
        vpnActiveConfig = config
        vpnRuntimeOutbounds = Self.outboundsByTag(in: config)
        vpnHotUpdateDirty = false
        vpnConfigurationState = .stable
        vpnReadyAt = nil
        vpnTerminalOverrides.removeAll()
        monitoredFallbackGroups = fallbackGroups
        vpnFallbackSelectors = Dictionary(uniqueKeysWithValues: fallbackGroups.map {
            ($0.id, VPNFallbackStableSelector(group: $0))
        })
        vpnFallbackOverridesReady = fallbackGroups.isEmpty
        vpnRuntimeToken = UUID()
        vpnWarmedOutboundTags.removeAll()
        fallbackRuntimeStatuses.removeAll()
        fallbackStatusHandler?(fallbackRuntimeStatuses)
        startVPNMonitor()
        startVPNFallbackMonitor()
        emitStatus()
    }

    private func reloadSystemVPN(
        state: AppState,
        settings: Settings,
        networkRebind: Bool = false
    ) async throws {
        try validateSystemVPNState(state)
        guard let interfaceName = vpnInterfaceName else {
            throw EngineError.startFailed("Неизвестен активный utun-интерфейс")
        }
        guard let bypass = systemVPNBypassInterface(for: settings) else {
            throw EngineError.noPhysicalInterface
        }
        let fallbackIDs = state.usedVPNFallbackGroupIDs()
        let fallbackGroups = fallbackIDs.compactMap { state.vpnFallbackGroup(id: $0) }
        guard let apiPort = vpnAPIPort,
              let metricsPort = vpnMetricsPort,
              let xrayPath = resolvedXrayPath,
              let activeConfig = vpnActiveConfig else {
            throw EngineError.startFailed("Активный VPN runtime не готов к обновлению")
        }
        let files = SystemVPNFiles(workDir: workDir)
        let config = XrayConfig.build(
            state: state,
            logLevel: settings.logLevel,
            bypassInterface: bypass,
            systemVPNInterface: interfaceName,
            systemVPNAPIPort: apiPort,
            systemVPNMetricsPort: metricsPort
        )
        let validation = try validate(
            config: config,
            xrayPath: xrayPath,
            systemVPNInterface: interfaceName
        )
        guard validation.ok else {
            let detail = validation.output.components(separatedBy: .newlines)
                .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
                .last(where: { !$0.isEmpty }) ?? "Xray отверг конфигурацию"
            log("⚠ Новая VPN-конфигурация отклонена до переключения: \(detail)")
            throw EngineError.startFailed("Изменения не применены; VPN продолжает работать: \(detail)")
        }

        var transitionBase = activeConfig
        transitionBase["outbounds"] = .array(Array(vpnRuntimeOutbounds.values))
        let plan = SystemVPNConfigTransition.plan(from: transitionBase, to: config)
        if !networkRebind, !vpnHotUpdateDirty, case .hot(let update) = plan {
            vpnConfigurationState = .switching
            emitStatus()
            do {
                try await applyHotSystemVPNUpdate(
                    update,
                    activeConfig: activeConfig,
                    candidateConfig: config,
                    xrayPath: xrayPath,
                    apiPort: apiPort,
                    files: files
                )
            } catch {
                if vpnConfigurationState == .switching {
                    markVPNRecovered()
                } else {
                    emitStatus()
                }
                throw error
            }
            activateSystemVPNConfig(
                config,
                fallbackGroups: fallbackGroups,
                resetWarmup: false,
                resetRuntimeDrift: false
            )
            vpnConfigurationState = .stable
            log("✓ Маршруты VPN переключены без перезапуска Xray")
            emitStatus()
            return
        }

        try XrayConfig.encode(config).write(to: files.candidate, options: .atomic)
        try? FileManager.default.removeItem(at: files.result)
        let generation = UUID().uuidString.lowercased()
        let request = try SystemVPNReloadRequest(
            generation: generation,
            bypassInterface: networkRebind ? bypass : nil,
            routeOnly: networkRebind && config == activeConfig
        )
        try Data(request.encodedText.utf8).write(to: files.reload, options: .atomic)
        let previousXrayPID = vpnXrayPID
        vpnConfigurationState = .switching
        if networkRebind {
            log("↻ Новый physical route передан helper; системные VPN-маршруты остаются активны")
        } else {
            log("↻ Проверенная VPN-конфигурация передана helper; текущий маршрут сохранён для recovery")
        }
        emitStatus()

        guard let result = await waitForReloadResult(
            generation: generation,
            files: files,
            timeout: 12
        ) else {
            if let installed = try? JSONDecoder().decode(
                    JSONValue.self,
                    from: Data(contentsOf: files.config)
               ), let readyPID = systemVPNReadyPID(files: files), childAlive(readyPID) {
                vpnXrayPID = readyPID
                if installed == config {
                    activateSystemVPNConfig(
                        config,
                        fallbackGroups: fallbackGroups,
                        resetWarmup: true
                    )
                    vpnConfigurationState = .stable
                    log("✓ Helper принял конфигурацию; result-файл был восстановлен по active config")
                    emitStatus()
                    return
                }
                if installed == activeConfig {
                    markVPNRecovered()
                    throw EngineError.startFailed("Helper восстановил предыдущий VPN-маршрут без result-файла")
                }
            }
            vpnConfigurationState = .degraded
            emitStatus()
            throw EngineError.startFailed("Helper не подтвердил переключение; текущий VPN не остановлен принудительно")
        }

        if result.processID > 0 { vpnXrayPID = result.processID }
        switch result.outcome {
        case .accepted:
            let xrayRestarted = previousXrayPID != result.processID
            activateSystemVPNConfig(
                config,
                fallbackGroups: fallbackGroups,
                resetWarmup: xrayRestarted
            )
            vpnConfigurationState = .stable
            if networkRebind {
                log("✓ VPN перенесён на (bypass); utun и kill-switch не отключались")
            } else {
                log("✓ Новая VPN-конфигурация принята; utun и системные маршруты сохранены")
            }
        case .recovered, .rejected:
            markVPNRecovered()
            log("↩ Новая конфигурация отклонена; предыдущий Xray автоматически восстановлен")
            throw EngineError.startFailed("Изменения отклонены, предыдущий VPN-маршрут уже восстановлен")
        case .fatal:
            vpnConfigurationState = .degraded
            emitStatus()
            throw EngineError.startFailed("Новая и предыдущая VPN-конфигурации не запустились")
        }
        emitStatus()
    }

    private func applyHotSystemVPNUpdate(
        _ update: SystemVPNHotUpdate,
        activeConfig: JSONValue,
        candidateConfig: JSONValue,
        xrayPath: String,
        apiPort: Int,
        files: SystemVPNFiles
    ) async throws {
        let added = update.addedOutbounds.filter {
            guard let tag = $0["tag"]?.stringValue else { return false }
            return vpnRuntimeOutbounds[tag] == nil
        }
        if !added.isEmpty {
            let payload = workDir.appendingPathComponent("xray-system-vpn.hot-outbounds.json")
            try XrayConfig.encode(.object(["outbounds": .array(added)]))
                .write(to: payload, options: .atomic)
            let result = await runXrayAPI(
                xrayPath: xrayPath,
                apiPort: apiPort,
                arguments: ["ado", payload.path]
            )
            guard result?.succeeded == true else {
                vpnHotUpdateDirty = true
                let detail = result?.output.trimmingCharacters(in: .whitespacesAndNewlines) ?? "нет ответа"
                throw EngineError.startFailed("Не удалось подготовить новый VPN-маршрут: \(detail)")
            }
            for outbound in added {
                if let tag = outbound["tag"]?.stringValue {
                    vpnRuntimeOutbounds[tag] = outbound
                }
            }
        }


        let healthTargets = SystemVPNConfigTransition.healthCheckOutboundTags(
            from: activeConfig["routing"] ?? .object([:]),
            to: update.routing
        )
        for tag in healthTargets {
            let healthy = await probeSystemVPNOutbound(
                tag,
                xrayPath: xrayPath,
                apiPort: apiPort
            )
            guard healthy else {
                markVPNRecovered()
                throw EngineError.startFailed(
                    "Маршрут \(tag) не прошёл проверку связи; текущий VPN оставлен без изменений"
                )
            }
        }

        let routingPayload = workDir.appendingPathComponent("xray-system-vpn.hot-routing.json")
        let rollbackPayload = workDir.appendingPathComponent("xray-system-vpn.hot-routing-rollback.json")
        try XrayConfig.encode(.object(["routing": update.routing]))
            .write(to: routingPayload, options: .atomic)
        guard let activeRouting = activeConfig["routing"] else {
            vpnHotUpdateDirty = true
            throw EngineError.startFailed("Активная конфигурация не содержит routing")
        }
        try XrayConfig.encode(.object(["routing": activeRouting]))
            .write(to: rollbackPayload, options: .atomic)

        let applyResult = await runXrayAPI(
            xrayPath: xrayPath,
            apiPort: apiPort,
            arguments: ["adrules", routingPayload.path]
        )
        guard applyResult?.succeeded == true else {
            let rollbackResult = await runXrayAPI(
                xrayPath: xrayPath,
                apiPort: apiPort,
                arguments: ["adrules", rollbackPayload.path]
            )
            if rollbackResult?.succeeded != true {
                vpnHotUpdateDirty = true
                vpnConfigurationState = .degraded
            }
            let detail = applyResult?.output.trimmingCharacters(in: .whitespacesAndNewlines) ?? "нет ответа"
            throw EngineError.startFailed("Горячее обновление маршрутов отклонено: \(detail)")
        }

        do {
            try XrayConfig.encode(candidateConfig).write(to: files.config, options: .atomic)
        } catch {
            // Runtime уже увидел candidate routing. Если active config нельзя
            // атомарно закрепить на диске, немедленно возвращаем старые правила,
            // иначе crash recovery поднял бы другую конфигурацию.
            let rollbackResult = await runXrayAPI(
                xrayPath: xrayPath,
                apiPort: apiPort,
                arguments: ["adrules", rollbackPayload.path]
            )
            if rollbackResult?.succeeded != true {
                vpnHotUpdateDirty = true
                vpnConfigurationState = .degraded
            }
            throw EngineError.startFailed(
                "Маршрут не закреплён на диске; предыдущая конфигурация восстановлена"
            )
        }
    }

    private func probeSystemVPNOutbound(
        _ outboundTag: String,
        xrayPath: String,
        apiPort: Int
    ) async -> Bool {
        guard let port = Net.freePort() else { return false }
        let token = UUID().uuidString.lowercased()
        let inboundTag = "vpn-health-\(token)"
        let ruleTag = "vpn-health-rule-\(token)"
        let inboundPayload = workDir.appendingPathComponent("xray-system-vpn.health-inbound-\(token).json")
        let rulePayload = workDir.appendingPathComponent("xray-system-vpn.health-rule-\(token).json")
        defer {
            try? FileManager.default.removeItem(at: inboundPayload)
            try? FileManager.default.removeItem(at: rulePayload)
        }
        do {
            try XrayConfig.encode(.object(["inbounds": .array([.object([
                "tag": .string(inboundTag),
                "listen": .string("127.0.0.1"),
                "port": .int(port),
                "protocol": .string("http"),
                "settings": .object([:]),
            ])])])).write(to: inboundPayload, options: .atomic)
            try XrayConfig.encode(.object(["routing": .object(["rules": .array([.object([
                "type": .string("field"),
                "inboundTag": .array([.string(inboundTag)]),
                "outboundTag": .string(outboundTag),
                "ruleTag": .string(ruleTag),
            ])])])])).write(to: rulePayload, options: .atomic)
        } catch {
            return false
        }

        let inboundAdded = await runXrayAPI(
            xrayPath: xrayPath,
            apiPort: apiPort,
            arguments: ["adi", inboundPayload.path]
        )?.succeeded == true
        guard inboundAdded else { return false }

        let ruleAdded = await runXrayAPI(
            xrayPath: xrayPath,
            apiPort: apiPort,
            arguments: ["adrules", "-append", rulePayload.path]
        )?.succeeded == true
        guard ruleAdded else {
            let removed = await runXrayAPI(
                xrayPath: xrayPath,
                apiPort: apiPort,
                arguments: ["rmi", inboundTag]
            )
            if removed?.succeeded != true { vpnHotUpdateDirty = true }
            return false
        }

        let curl = await Task.detached(priority: .utility) {
            Shell.runResult(
                "/usr/bin/curl",
                [
                    "--silent", "--show-error", "--output", "/dev/null",
                    "--write-out", "%{http_code}",
                    "--connect-timeout", "4", "--max-time", "7",
                    "--proxy", "http://127.0.0.1:\(port)",
                    "https://www.gstatic.com/generate_204",
                ],
                timeout: 9
            )
        }.value

        let removedRule = await runXrayAPI(
            xrayPath: xrayPath,
            apiPort: apiPort,
            arguments: ["rmrules", ruleTag]
        )
        let removedInbound = await runXrayAPI(
            xrayPath: xrayPath,
            apiPort: apiPort,
            arguments: ["rmi", inboundTag]
        )
        if removedRule?.succeeded != true || removedInbound?.succeeded != true {
            vpnHotUpdateDirty = true
        }
        return curl?.succeeded == true
            && curl?.output.trimmingCharacters(in: .whitespacesAndNewlines) == "204"
    }

    private func runXrayAPI(
        xrayPath: String,
        apiPort: Int,
        arguments: [String]
    ) async -> Shell.Result? {
        guard let command = arguments.first else { return nil }
        let commandArguments = Array(arguments.dropFirst())
        return await Task.detached(priority: .utility) {
            Shell.runResult(
                xrayPath,
                ["api", command,
                    "--server=127.0.0.1:\(apiPort)",
                    "--timeout=3",
                ] + commandArguments,
                timeout: 5
            )
        }.value
    }

    private func waitForReloadResult(
        generation: String,
        files: SystemVPNFiles,
        timeout: TimeInterval
    ) async -> SystemVPNReloadResult? {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let text = try? String(contentsOf: files.result, encoding: .utf8),
               let result = SystemVPNReloadResult.parse(text),
               result.generation == generation {
                return result
            }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return nil
    }

    private func systemVPNReadyPID(files: SystemVPNFiles) -> Int32? {
        guard let text = try? String(contentsOf: files.ready, encoding: .utf8) else { return nil }
        return Int32(text.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private func childAlive(_ processID: Int32) -> Bool {
        processID > 0 && (kill(processID, 0) == 0 || errno == EPERM)
    }

    private func activateSystemVPNConfig(
        _ config: JSONValue,
        fallbackGroups: [VPNFallbackGroup],
        resetWarmup: Bool,
        resetRuntimeDrift: Bool = true
    ) {
        vpnActiveConfig = config
        for (tag, outbound) in Self.outboundsByTag(in: config) {
            vpnRuntimeOutbounds[tag] = outbound
        }
        if resetRuntimeDrift { vpnHotUpdateDirty = false }
        vpnRuntimeToken = UUID()
        monitoredFallbackGroups = fallbackGroups
        // Full routing replacement rebuilds Xray balancers and clears their
        // in-memory overrides even on the hot path. Reapply our sticky choice
        // before consuming another observation round.
        vpnTerminalOverrides.removeAll()
        if resetWarmup {
            vpnReadyAt = Date()
            vpnFallbackSelectors = Dictionary(uniqueKeysWithValues: fallbackGroups.map {
                ($0.id, VPNFallbackStableSelector(group: $0))
            })
            vpnWarmedOutboundTags.removeAll()
        } else {
            let validIDs = Set(fallbackGroups.map(\.id))
            vpnFallbackSelectors = vpnFallbackSelectors.filter { validIDs.contains($0.key) }
            for group in fallbackGroups where vpnFallbackSelectors[group.id] == nil {
                vpnFallbackSelectors[group.id] = VPNFallbackStableSelector(group: group)
            }
        }
        vpnFallbackOverridesReady = fallbackGroups.isEmpty
        fallbackRuntimeStatuses.removeAll()
        fallbackStatusHandler?(fallbackRuntimeStatuses)
        if vpnReady {
            Task { [weak self] in await self?.prepareVPNRuntimeAfterReady() }
        }
    }

    private func markVPNRecovered() {
        vpnConfigurationState = .recovered
        emitStatus()
        Task { [weak self] in
            try? await Task.sleep(for: .seconds(5))
            await self?.settleRecoveredVPNState()
        }
    }

    private func settleRecoveredVPNState() {
        guard vpnConfigurationState == .recovered else { return }
        vpnConfigurationState = .stable
        emitStatus()
    }

    private func startVPNMonitor() {
        vpnMonitorTask?.cancel()
        vpnMonitorTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(250))
                guard let self else { return }
                await self.pollVPNRuntime()
            }
        }
    }

    private func startVPNFallbackMonitor() {
        vpnFallbackMonitorTask?.cancel()
        vpnFallbackMonitorTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(2))
                guard !Task.isCancelled, let self else { return }
                await self.pollVPNFallbackRuntime()
            }
        }
    }

    private func stopVPNFallbackMonitoring() {
        vpnFallbackMonitorTask?.cancel()
        vpnFallbackMonitorTask = nil
        vpnAPIPort = nil
        vpnMetricsPort = nil
        monitoredFallbackGroups.removeAll()
        vpnFallbackSelectors.removeAll()
        vpnFallbackOverridesReady = false
        if !fallbackRuntimeStatuses.isEmpty {
            fallbackRuntimeStatuses.removeAll()
            fallbackStatusHandler?(fallbackRuntimeStatuses)
        }
    }

    private func clearSystemVPNRuntimeState() {
        vpnActiveConfig = nil
        vpnRuntimeOutbounds.removeAll()
        vpnHotUpdateDirty = false
        vpnConfigurationState = .stable
        vpnReadyAt = nil
        vpnTerminalOverrides.removeAll()
        vpnRuntimeToken = UUID()
        vpnWarmedOutboundTags.removeAll()
    }

    /// Pins configured priority 1 before health optimization, then warms every
    /// WireGuard handler in the background. Neither step blocks VPN readiness.
    private func prepareVPNRuntimeAfterReady() async {
        guard !vpnRuntimePreparationBusy,
              activeMode == .systemVPN,
              process?.isRunning == true,
              vpnReady,
              let xrayPath = resolvedXrayPath,
              let apiPort = vpnAPIPort else { return }
        let runtimeToken = vpnRuntimeToken
        vpnRuntimePreparationBusy = true
        defer {
            vpnRuntimePreparationBusy = false
            if activeMode == .systemVPN, vpnReady, !vpnFallbackOverridesReady {
                Task { [weak self] in
                    try? await Task.sleep(for: .seconds(2))
                    await self?.prepareVPNRuntimeAfterReady()
                }
            }
        }

        var allOverridesApplied = true
        var bootstrapStatuses = fallbackRuntimeStatuses
        let now = Date()
        for group in monitoredFallbackGroups {
            guard activeMode == .systemVPN,
                  vpnAPIPort == apiPort,
                  vpnRuntimeToken == runtimeToken else { return }
            let selector = vpnFallbackSelectors[group.id]
                ?? VPNFallbackStableSelector(group: group)
            vpnFallbackSelectors[group.id] = selector
            let applied = await runXrayAPI(
                xrayPath: xrayPath,
                apiPort: apiPort,
                arguments: [
                    "bo", "-b", XrayConfig.vpnFallbackTag(group.id), selector.selectedOutboundTag,
                ]
            )
            guard applied?.succeeded == true else {
                allOverridesApplied = false
                continue
            }
            let phase: VPNFallbackRuntimePhase = selector.selectedOutboundTag == "direct"
                || selector.selectedOutboundTag == "block" ? .terminal : .warming
            bootstrapStatuses[group.id] = stableFallbackStatus(
                group: group,
                outboundTag: selector.selectedOutboundTag,
                phase: phase,
                now: now,
                previous: bootstrapStatuses[group.id]
            )
        }
        guard activeMode == .systemVPN,
              vpnAPIPort == apiPort,
              vpnRuntimeToken == runtimeToken else { return }
        vpnFallbackOverridesReady = allOverridesApplied
        if bootstrapStatuses != fallbackRuntimeStatuses {
            fallbackRuntimeStatuses = bootstrapStatuses
            fallbackStatusHandler?(fallbackRuntimeStatuses)
        }
        guard allOverridesApplied else { return }

        await warmWireGuardOutbounds(
            xrayPath: xrayPath,
            apiPort: apiPort,
            runtimeToken: runtimeToken
        )
    }

    private func warmWireGuardOutbounds(
        xrayPath: String,
        apiPort: Int,
        runtimeToken: UUID
    ) async {
        let tags = (vpnActiveConfig?["outbounds"]?.arrayValue ?? []).compactMap { outbound in
            guard outbound["protocol"]?.stringValue == "wireguard" else { return nil }
            return outbound["tag"]?.stringValue
        }.filter { !vpnWarmedOutboundTags.contains($0) }
        guard !tags.isEmpty else { return }

        var warmed = 0
        for tag in tags {
            await acquireVPNConfigurationMutation()
            let runtimeStillMatches = activeMode == .systemVPN
                && vpnAPIPort == apiPort
                && vpnRuntimeToken == runtimeToken
                && vpnActiveConfig?["outbounds"]?.arrayValue?.contains(where: {
                    $0["tag"]?.stringValue == tag && $0["protocol"]?.stringValue == "wireguard"
                }) == true
            if runtimeStillMatches {
                let healthy = await probeSystemVPNOutbound(
                    tag,
                    xrayPath: xrayPath,
                    apiPort: apiPort
                )
                if healthy {
                    vpnWarmedOutboundTags.insert(tag)
                    warmed += 1
                }
            }
            releaseVPNConfigurationMutation()
            guard activeMode == .systemVPN,
                  vpnAPIPort == apiPort,
                  vpnRuntimeToken == runtimeToken else { return }
        }
        if warmed > 0 {
            log("✓ WireGuard: прогрето каналов \(warmed), keepalive удерживает сессии активными")
        }
    }

    private func pollVPNFallbackRuntime() async {
        guard activeMode == .systemVPN,
              process?.isRunning == true,
              vpnReady,
              vpnFallbackOverridesReady,
              let xrayPath = resolvedXrayPath,
              let apiPort = vpnAPIPort,
              let metricsPort = vpnMetricsPort,
              !monitoredFallbackGroups.isEmpty else { return }

        guard let payload = await fetchVPNObservatoryMetrics(port: metricsPort) else { return }
        let observations = VPNFallbackMetricsParser.parse(payload)
        guard !observations.isEmpty else { return }

        // Конфигурация могла перезагрузиться, пока curl читал metrics.
        guard activeMode == .systemVPN,
              vpnAPIPort == apiPort,
              vpnMetricsPort == metricsPort else { return }

        let now = Date()
        var next = fallbackRuntimeStatuses
        for group in monitoredFallbackGroups {
            var selector = vpnFallbackSelectors[group.id]
                ?? VPNFallbackStableSelector(group: group)
            let previousTag = selector.selectedOutboundTag
            let decision = selector.consume(observations)

            if let decision {
                let applied = await runXrayAPI(
                    xrayPath: xrayPath,
                    apiPort: apiPort,
                    arguments: [
                        "bo", "-b", XrayConfig.vpnFallbackTag(group.id), decision.outboundTag,
                    ]
                )
                guard applied?.succeeded == true else {
                    // Не подтверждаем выбор локально: следующий poll повторит
                    // ту же безопасную transition, а старый override останется.
                    continue
                }
                vpnFallbackSelectors[group.id] = selector
                if case .terminal(let tag) = decision {
                    vpnTerminalOverrides.insert(group.id)
                    log("⚠ Fallback «\(group.name)»: подтверждён отказ всех каналов, применено \(tag)")
                } else {
                    vpnTerminalOverrides.remove(group.id)
                    if previousTag != decision.outboundTag {
                        log("⇄ Fallback «\(group.name)»: подтверждён канал \(fallbackMemberName(group: group, outboundTag: decision.outboundTag))")
                    }
                }
            } else {
                vpnFallbackSelectors[group.id] = selector
            }

            let phase: VPNFallbackRuntimePhase = selector.selectedOutboundTag == "direct"
                || selector.selectedOutboundTag == "block" ? .terminal : .active
            next[group.id] = stableFallbackStatus(
                group: group,
                outboundTag: selector.selectedOutboundTag,
                phase: phase,
                now: now,
                previous: next[group.id]
            )
        }
        guard next != fallbackRuntimeStatuses else { return }
        fallbackRuntimeStatuses = next
        fallbackStatusHandler?(fallbackRuntimeStatuses)
    }

    private func fetchVPNObservatoryMetrics(port: Int) async -> Data? {
        await Task.detached(priority: .utility) {
            guard let result = Shell.runResult(
                "/usr/bin/curl",
                [
                    "--silent", "--show-error", "--fail",
                    "--max-time", "1",
                    "http://127.0.0.1:\(port)/debug/vars",
                ],
                timeout: 2
            ), result.succeeded else { return nil }
            return result.output.data(using: .utf8)
        }.value
    }

    private func stableFallbackStatus(
        group: VPNFallbackGroup,
        outboundTag: String,
        phase: VPNFallbackRuntimePhase,
        now: Date,
        previous: VPNFallbackRuntimeStatus?
    ) -> VPNFallbackRuntimeStatus {
        let memberID = group.members.enumerated().first { index, member in
            XrayConfig.vpnFallbackMemberOutboundTag(member) == outboundTag
        }?.element.id
        if let previous,
           previous.selectedMemberID == memberID,
           previous.selectedOutboundTag == outboundTag,
           previous.phase == phase {
            return previous
        }
        return VPNFallbackRuntimeStatus(
            groupID: group.id,
            selectedMemberID: memberID,
            selectedOutboundTag: outboundTag,
            updatedAt: now,
            phase: phase
        )
    }

    private func fallbackMemberName(group: VPNFallbackGroup, outboundTag: String) -> String {
        guard let index = group.members.enumerated().first(where: { index, member in
            XrayConfig.vpnFallbackMemberOutboundTag(member) == outboundTag
        })?.offset else { return outboundTag }
        return "№\(index + 1)"
    }

    private func terminalFallbackStatus(
        group: VPNFallbackGroup,
        now: Date
    ) -> VPNFallbackRuntimeStatus {
        VPNFallbackRuntimeStatus(
            groupID: group.id,
            selectedMemberID: nil,
            selectedOutboundTag: group.finalAction == .direct ? "direct" : "block",
            updatedAt: now,
            phase: .terminal
        )
    }

    private func pollVPNRuntime() {
        let files = SystemVPNFiles(workDir: workDir)
        if let attributes = try? FileManager.default.attributesOfItem(atPath: files.log.path),
           let size = attributes[.size] as? NSNumber {
            // Launcher обрезает достигший лимита файл и пишет свежий хвост с
            // начала. Сбрасываем offset, иначе монитор больше ничего не увидит.
            if size.uint64Value < vpnLogOffset {
                vpnLogOffset = 0
            }
        }
        if let attributes = try? FileManager.default.attributesOfItem(atPath: files.log.path),
           let size = attributes[.size] as? NSNumber,
           size.uint64Value > vpnLogOffset,
           let handle = try? FileHandle(forReadingFrom: files.log) {
            do {
                try handle.seek(toOffset: vpnLogOffset)
                let data = try handle.readToEnd() ?? Data()
                vpnLogOffset += UInt64(data.count)
                if let text = String(data: data, encoding: .utf8) {
                    let lines = text.components(separatedBy: .newlines)
                        .map { $0.trimmingCharacters(in: .whitespaces) }
                        .filter { !$0.isEmpty }
                    appendLines(lines)
                }
            } catch {
                // Следующая итерация повторит чтение после завершения записи.
            }
            try? handle.close()
        }

        guard activeMode == .systemVPN,
              process?.isRunning == true,
              FileManager.default.fileExists(atPath: files.ready.path) else { return }

        if let text = try? String(contentsOf: files.ready, encoding: .utf8),
           let pid = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines)) {
            vpnXrayPID = pid
        }
        if !vpnReady {
            vpnReady = true
            vpnReadyAt = Date()
            vpnConfigurationState = .stable
            log("✓ Системный VPN активен: весь IPv4/IPv6 TCP/UDP-трафик направлен в \(vpnInterfaceName ?? "utun")")
            emitStatus()
            Task { [weak self] in await self?.prepareVPNRuntimeAfterReady() }
        }
    }

    // MARK: - Тест туннеля

    /// Совместимость для одиночной проверки из карточки туннеля.
    public func testTunnel(_ tunnel: Tunnel, settings: Settings) async -> TunnelTestResult {
        await testTunnels([tunnel], settings: settings)[tunnel.id]
            ?? TunnelTestResult(ok: false, error: "Проверка не вернула результат")
    }

    /// Поднимает один временный Xray для всех выбранных outbound и выполняет
    /// ограниченное число параллельных URL-тестов. Если основной runtime уже
    /// работает, второй Xray не запускается — это важно для WireGuard-ключей.
    public func testTunnels(
        _ tunnels: [Tunnel],
        settings: Settings,
        onResult: (@Sendable (String, TunnelTestResult) async -> Void)? = nil
    ) async -> [String: TunnelTestResult] {
        guard !tunnels.isEmpty else { return [:] }
        guard process?.isRunning != true else {
            let results = Self.failedLatencyResults(
                for: tunnels,
                message: "Остановите VPN или прокси для обновления задержки"
            )
            await Self.emitLatencyResults(results, for: tunnels, to: onResult)
            return results
        }
        guard let xrayPath = resolveXrayPath(preferred: settings.xrayPath) else {
            let results = Self.failedLatencyResults(
                for: tunnels,
                message: EngineError.xrayNotFound.errorDescription ?? "Xray не найден"
            )
            await Self.emitLatencyResults(results, for: tunnels, to: onResult)
            return results
        }
        guard let allocatedPorts = Net.freePorts(count: tunnels.count) else {
            let results = Self.failedLatencyResults(
                for: tunnels,
                message: "Не удалось выделить порты для проверки"
            )
            await Self.emitLatencyResults(results, for: tunnels, to: onResult)
            return results
        }

        stopLatencyProcess()
        let ports = Dictionary(uniqueKeysWithValues: zip(tunnels.map(\.id), allocatedPorts))
        let config = XrayConfig.buildLatencyTests(
            tunnels: tunnels,
            ports: ports,
            bypassInterface: bypassInterface(for: settings)
        )
        let tmp = workDir.appendingPathComponent("xray-latency-\(UUID().uuidString).json")
        do {
            try XrayConfig.encode(config).write(to: tmp)
        } catch {
            let results = Self.failedLatencyResults(for: tunnels, message: error.localizedDescription)
            await Self.emitLatencyResults(results, for: tunnels, to: onResult)
            return results
        }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: xrayPath)
        proc.arguments = ["run", "-config", tmp.path]
        proc.standardOutput = FileHandle.nullDevice
        proc.standardError = FileHandle.nullDevice

        do {
            try proc.run()
        } catch {
            try? FileManager.default.removeItem(at: tmp)
            let results = Self.failedLatencyResults(for: tunnels, message: error.localizedDescription)
            await Self.emitLatencyResults(results, for: tunnels, to: onResult)
            return results
        }
        latencyProcess = proc

        defer {
            if proc.isRunning { proc.terminate() }
            if latencyProcess === proc { latencyProcess = nil }
            try? FileManager.default.removeItem(at: tmp)
        }

        let readiness = await withTaskGroup(of: (String, Bool).self) { group in
            for tunnel in tunnels {
                guard let port = ports[tunnel.id] else { continue }
                group.addTask {
                    let ready = await Net.waitPortOpen(
                        host: "127.0.0.1",
                        port: port,
                        timeout: 5
                    )
                    return (tunnel.id, ready)
                }
            }

            var values: [String: Bool] = [:]
            for await (id, ready) in group { values[id] = ready }
            return values
        }

        guard !Task.isCancelled, proc.isRunning, process?.isRunning != true else {
            return Self.failedLatencyResults(for: tunnels, message: "Проверка отменена")
        }

        var results: [String: TunnelTestResult] = [:]
        let readyTunnels = tunnels.compactMap { tunnel -> (String, Int)? in
            guard readiness[tunnel.id] == true, let port = ports[tunnel.id] else {
                results[tunnel.id] = TunnelTestResult(
                    ok: false,
                    error: "Туннель не открыл тестовый порт"
                )
                return nil
            }
            return (tunnel.id, port)
        }

        if let onResult {
            for tunnel in tunnels where readiness[tunnel.id] != true {
                if let result = results[tunnel.id] {
                    await onResult(tunnel.id, result)
                }
            }
        }

        await withTaskGroup(of: (String, TunnelTestResult).self) { group in
            var iterator = readyTunnels.makeIterator()

            func addNext() {
                guard let (id, port) = iterator.next() else { return }
                group.addTask {
                    (id, await Self.measureLatency(through: port))
                }
            }

            for _ in 0..<min(6, readyTunnels.count) { addNext() }
            while let (id, result) = await group.next() {
                results[id] = result
                if let onResult { await onResult(id, result) }
                addNext()
            }
        }

        return results
    }

    public func cancelTunnelTests() {
        stopLatencyProcess()
    }

    private func stopLatencyProcess() {
        guard let proc = latencyProcess else { return }
        latencyProcess = nil
        guard proc.isRunning else { return }
        proc.terminate()
        let deadline = Date().addingTimeInterval(0.8)
        while proc.isRunning, Date() < deadline {
            usleep(10_000)
        }
        if proc.isRunning { kill(proc.processIdentifier, SIGKILL) }
    }

    private nonisolated static func measureLatency(through port: Int) async -> TunnelTestResult {
        guard !Task.isCancelled else {
            return TunnelTestResult(ok: false, error: "Проверка отменена")
        }

        let started = Date()
        do {
            let body = try await Net.fetchThroughHTTPProxy(
                proxyHost: "127.0.0.1",
                proxyPort: port,
                url: "http://cp.cloudflare.com/cdn-cgi/trace",
                timeout: 8
            )
            let latency = max(1, Int(Date().timeIntervalSince(started) * 1000))
            var ip: String?
            var loc: String?
            for line in body.components(separatedBy: .newlines) {
                if line.hasPrefix("ip=") { ip = String(line.dropFirst(3)) }
                if line.hasPrefix("loc=") { loc = String(line.dropFirst(4)) }
            }
            return TunnelTestResult(ok: true, ip: ip, loc: loc, latencyMs: latency)
        } catch {
            return TunnelTestResult(ok: false, error: error.localizedDescription)
        }
    }

    private nonisolated static func failedLatencyResults(
        for tunnels: [Tunnel],
        message: String
    ) -> [String: TunnelTestResult] {
        Dictionary(uniqueKeysWithValues: tunnels.map {
            ($0.id, TunnelTestResult(ok: false, error: message))
        })
    }

    private nonisolated static func emitLatencyResults(
        _ results: [String: TunnelTestResult],
        for tunnels: [Tunnel],
        to handler: (@Sendable (String, TunnelTestResult) async -> Void)?
    ) async {
        guard let handler else { return }
        for tunnel in tunnels {
            if let result = results[tunnel.id] {
                await handler(tunnel.id, result)
            }
        }
    }

    // MARK: - Подписка

    public func fetchSubscription(url: String) async throws -> ParseResult {
        let body = try await Net.get(url: url, timeout: 20)
        return Parsers.parseSubscriptionBody(body)
    }
}
