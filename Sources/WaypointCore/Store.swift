import Foundation

/// JSON-хранилище состояния приложения.
///
/// При первом запуске Waypoint переносит только постоянный `state.json` из
/// каталога предыдущей версии. Runtime-файлы Xray не копируются и создаются
/// заново, поэтому старый незавершённый сеанс не может повлиять на новый.
public final class Store: @unchecked Sendable {
    public let fileURL: URL
    public let workDir: URL
    private let lock = NSLock()
    private var state: AppState

    public static func defaultWorkDir() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("Waypoint", isDirectory: true)
    }

    public static func legacyWorkDir() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("tunnel-proxy-hub", isDirectory: true)
    }

    /// Копирует состояние предыдущей версии, не удаляя оригинал. Возвращает
    /// `true`, только когда новый файл действительно был создан.
    @discardableResult
    public static func migrateLegacyStateIfNeeded(from legacyWorkDir: URL, to workDir: URL) -> Bool {
        let fm = FileManager.default
        let source = legacyWorkDir.appendingPathComponent("state.json")
        let destination = workDir.appendingPathComponent("state.json")
        guard !fm.fileExists(atPath: destination.path),
              let values = try? source.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]),
              values.isRegularFile == true,
              values.isSymbolicLink != true else { return false }

        do {
            try fm.createDirectory(at: workDir, withIntermediateDirectories: true)
            let temporary = workDir.appendingPathComponent("state.json.migrating-\(UUID().uuidString)")
            defer { try? fm.removeItem(at: temporary) }
            try fm.copyItem(at: source, to: temporary)
            try fm.moveItem(at: temporary, to: destination)
            return true
        } catch {
            NSLog("Не удалось перенести состояние в Waypoint: \(error.localizedDescription)")
            return false
        }
    }

    public init(workDir: URL = Store.defaultWorkDir()) {
        if workDir.standardizedFileURL == Store.defaultWorkDir().standardizedFileURL {
            Store.migrateLegacyStateIfNeeded(from: Store.legacyWorkDir(), to: workDir)
        }
        self.workDir = workDir
        self.fileURL = workDir.appendingPathComponent("state.json")
        try? FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
        self.state = Store.load(from: fileURL)
    }

    private static func load(from url: URL) -> AppState {
        guard let data = try? Data(contentsOf: url) else { return AppState() }
        do {
            return try JSONDecoder().decode(AppState.self, from: data)
        } catch {
            // Файл повреждён или от несовместимой версии — начинаем с чистого
            // состояния, но не затираем файл до первой осознанной записи.
            return AppState()
        }
    }

    public func snapshot() -> AppState {
        lock.lock(); defer { lock.unlock() }
        return state
    }

    /// Меняет состояние и сохраняет его на диск.
    @discardableResult
    public func mutate<T>(_ body: (inout AppState) -> T) -> T {
        lock.lock()
        let result = body(&state)
        let toSave = state
        lock.unlock()
        save(toSave)
        return result
    }

    /// Возвращает подтверждённый снимок после отклонённой runtime-конфигурации.
    /// Используется только с generation-проверкой AppModel, чтобы поздний
    /// callback не перезаписал более новые действия пользователя.
    public func replace(with replacement: AppState) {
        lock.lock()
        state = replacement
        lock.unlock()
        save(replacement)
    }

    private func save(_ state: AppState) {
        do {
            try FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(state)
            // Атомарная запись: обрыв на середине не должен оставить битый файл,
            // из которого потом не поднимутся туннели.
            try data.write(to: fileURL, options: .atomic)
        } catch {
            NSLog("Не удалось сохранить состояние: \(error.localizedDescription)")
        }
    }
}
