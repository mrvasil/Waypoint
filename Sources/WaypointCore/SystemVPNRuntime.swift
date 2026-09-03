import Foundation
import Darwin

/// Имена служебных файлов одного запуска системного VPN.
public struct SystemVPNFiles: Sendable, Equatable {
    public let config: URL
    public let candidate: URL
    public let rollback: URL
    public let stop: URL
    public let reload: URL
    public let ready: URL
    public let result: URL
    public let log: URL

    public init(workDir: URL) {
        config = workDir.appendingPathComponent("xray-system-vpn.json")
        candidate = workDir.appendingPathComponent("xray-system-vpn.candidate.json")
        rollback = workDir.appendingPathComponent("xray-system-vpn.rollback.json")
        stop = workDir.appendingPathComponent("system-vpn.stop")
        reload = workDir.appendingPathComponent("system-vpn.reload")
        ready = workDir.appendingPathComponent("system-vpn.ready")
        result = workDir.appendingPathComponent("system-vpn.result")
        log = workDir.appendingPathComponent("system-vpn.log")
    }
}

public enum SystemVPNReloadOutcome: String, Sendable, Equatable {
    case accepted
    case recovered
    case rejected
    case fatal
}

public struct SystemVPNReloadResult: Sendable, Equatable {
    public var generation: String
    public var outcome: SystemVPNReloadOutcome
    public var processID: Int32

    public init(generation: String, outcome: SystemVPNReloadOutcome, processID: Int32) {
        self.generation = generation
        self.outcome = outcome
        self.processID = processID
    }

    public static func parse(_ text: String) -> SystemVPNReloadResult? {
        let fields = text.split(whereSeparator: \Character.isWhitespace)
        guard fields.count == 3 else { return nil }
        let generation = String(fields[0])
        guard !generation.isEmpty,
              generation.count <= 64,
              generation.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }),
              let outcome = SystemVPNReloadOutcome(rawValue: String(fields[1])),
              let processID = Int32(fields[2]),
              processID >= 0 else { return nil }
        return SystemVPNReloadResult(
            generation: generation,
            outcome: outcome,
            processID: processID
        )
    }
}

public struct SystemVPNReloadRequest: Sendable, Equatable {
    public var generation: String
    public var bypassInterface: String?
    public var routeOnly: Bool

    public init(
        generation: String,
        bypassInterface: String? = nil,
        routeOnly: Bool = false
    ) throws {
        guard !generation.isEmpty,
              generation.count <= 64,
              generation.allSatisfy({
                  $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-")
              }) else {
            throw EngineError.startFailed("Некорректный идентификатор обновления VPN")
        }
        if let bypassInterface {
            guard !bypassInterface.isEmpty,
                  bypassInterface.utf8.count < Int(IFNAMSIZ),
                  bypassInterface.allSatisfy({
                      $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-")
                  }) else {
                throw EngineError.startFailed("Некорректное имя физического интерфейса")
            }
        }
        guard !routeOnly || bypassInterface != nil else {
            throw EngineError.startFailed("Route-only обновление требует физический интерфейс")
        }
        self.generation = generation
        self.bypassInterface = bypassInterface
        self.routeOnly = routeOnly
    }

    public var encodedText: String {
        if let bypassInterface {
            return "\(generation) \(bypassInterface)\(routeOnly ? " route" : "")\n"
        }
        return "\(generation)\n"
    }
}

/// Подготовка безопасного запуска минимального root-helper через постоянный
/// LaunchDaemon. Штатный диалог macOS нужен только для его первой установки. Helper
/// держит utun и маршруты, а xray после fork сбрасывает права обратно до
/// uid/gid пользователя приложения.
public enum SystemVPNRuntime {
    public static let helperName = "WaypointVPNHelper"
    public static let launcherName = "WaypointVPNLauncher"
    public static let mtu = 1500

    /// Берём заведомо высокий свободный номер, чтобы не пересекаться с обычными
    /// Network Extension VPN. Ядро всё равно проверит отсутствие гонки.
    public static func availableInterfaceName() -> String? {
        for index in 90...127 {
            let name = "utun\(index)"
            if if_nametoindex(name) == 0 { return name }
        }
        return nil
    }

    public static func resolveHelperPath(mainExecutable: URL? = Bundle.main.executableURL) -> String? {
        resolveBundledExecutable(named: helperName, mainExecutable: mainExecutable)
    }

    public static func resolveLauncherPath(mainExecutable: URL? = Bundle.main.executableURL) -> String? {
        resolveBundledExecutable(named: launcherName, mainExecutable: mainExecutable)
    }

    private static func resolveBundledExecutable(named name: String, mainExecutable: URL?) -> String? {
        var candidates: [URL] = []
        if let bundleHelper = Bundle.main.builtInPlugInsURL?
            .deletingLastPathComponent()
            .appendingPathComponent("Helpers", isDirectory: true)
            .appendingPathComponent(name) {
            candidates.append(bundleHelper)
        }
        if let mainExecutable {
            candidates.append(mainExecutable.deletingLastPathComponent().appendingPathComponent(name))
        }

        let fm = FileManager.default
        return candidates.first(where: { fm.isExecutableFile(atPath: $0.path) })?.path
    }

    /// Homebrew xray ищет geoip.dat/geosite.dat и сам, но root-helper получает
    /// другое окружение. Передаём явный каталог, если он найден.
    public static func assetDirectory(forXrayPath path: String) -> String? {
        let fm = FileManager.default
        let candidates = [
            "/opt/homebrew/share/xray",
            "/usr/local/share/xray",
            URL(fileURLWithPath: path)
                .deletingLastPathComponent()
                .deletingLastPathComponent()
                .appendingPathComponent("share/xray").path,
        ]
        return candidates.first(where: {
            fm.fileExists(atPath: URL(fileURLWithPath: $0).appendingPathComponent("geoip.dat").path)
                && fm.fileExists(atPath: URL(fileURLWithPath: $0).appendingPathComponent("geosite.dat").path)
        })
    }

    public static func helperArguments(
        xrayPath: String,
        helperFiles: SystemVPNFiles,
        interfaceName: String,
        workDir: URL,
        bypassInterface: String,
        userID: uid_t = getuid(),
        groupID: gid_t = getgid(),
        appPID: pid_t = getpid()
    ) -> [String] {
        [
            "--xray", xrayPath,
            "--config", helperFiles.config.path,
            "--candidate", helperFiles.candidate.path,
            "--rollback", helperFiles.rollback.path,
            "--stop", helperFiles.stop.path,
            "--reload", helperFiles.reload.path,
            "--ready", helperFiles.ready.path,
            "--result", helperFiles.result.path,
            "--interface", interfaceName,
            "--bypass-interface", bypassInterface,
            "--uid", String(userID),
            "--gid", String(groupID),
            "--app-pid", String(appPID),
            "--mtu", String(mtu),
            "--workdir", workDir.path,
            "--asset-dir", assetDirectory(forXrayPath: xrayPath) ?? "-",
        ]
    }

    /// Аргументы передаются launcher напрямую, без shell-интерпретации.
    public static func launcherArguments(
        helperPath: String,
        arguments: [String],
        files: SystemVPNFiles
    ) -> [String] {
        [
            "--helper", helperPath,
            "--log", files.log.path,
            "--ready", files.ready.path,
            "--",
        ] + arguments
    }

    /// При первой установке сервиса launcher пишет ошибки Authorization Services уже
    /// после того, как запуск вернул управление UI. Преобразуем известные коды в понятный текст.
    public static func authorizationError(from line: String) -> String? {
        if line.contains("(-60005)") {
            return "macOS отклонила установку VPN-сервиса. Проверь пароль администратора Mac."
        }
        if line.contains("(-60006)") || line.contains("(-128)") {
            return "Установка VPN-сервиса отменена. Без одноразового подтверждения VPN не сможет запускаться без пароля."
        }
        if line.contains("(-60007)") {
            return "macOS не смогла показать запрос администратора. Открой приложение и повтори подключение."
        }
        if line.contains("(-60008)") {
            return "macOS отклонила VPN launcher. Переустанови приложение в /Applications и повтори подключение."
        }
        return nil
    }

}
