import Foundation

/// JSON-хранилище состояния приложения.
///
/// Читает и пишет тот же state.json, что и Electron-версия: файл лежит в
/// Application Support/tunnel-proxy-hub, поэтому туннели и прокси переносятся
/// без миграции.
public final class Store: @unchecked Sendable {
    public let fileURL: URL
    public let workDir: URL
    private let lock = NSLock()
    private var state: AppState

    /// Рабочий каталог Electron-версии — общий, чтобы данные не разошлись.
    public static func defaultWorkDir() -> URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("tunnel-proxy-hub", isDirectory: true)
    }

    public init(workDir: URL = Store.defaultWorkDir()) {
        self.workDir = workDir
        self.fileURL = workDir.appendingPathComponent("state.json")
        self.state = Store.load(from: fileURL)
        try? FileManager.default.createDirectory(at: workDir, withIntermediateDirectories: true)
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
