import Foundation

/// Запуск коротких системных команд с таймаутом.
enum Shell {
    private final class OutputBuffer: @unchecked Sendable {
        private let lock = NSLock()
        private var data = Data()

        func replace(with value: Data) {
            lock.lock()
            data = value
            lock.unlock()
        }

        func snapshot() -> Data {
            lock.lock()
            defer { lock.unlock() }
            return data
        }
    }

    struct Result: Sendable, Equatable {
        var output: String
        var exitCode: Int32
        var timedOut: Bool

        var succeeded: Bool { !timedOut && exitCode == 0 }
    }

    /// Возвращает stdout команды, либо nil при ошибке или таймауте.
    ///
    /// Вывод читается в фоне до завершения процесса: если ждать waitUntilExit
    /// раньше чтения, процесс с выводом больше размера буфера пайпа зависнет
    /// навсегда, заблокировав вызывающий поток.
    static func run(_ path: String, _ args: [String], timeout: TimeInterval) -> String? {
        guard let result = runResult(path, args, timeout: timeout), result.succeeded else {
            return nil
        }
        return result.output
    }

    /// Команды управления Xray обязаны различать пустой успешный ответ, ошибку
    /// и таймаут. stdout/stderr объединяются: CLI пишет диагностику в оба потока.
    static func runResult(_ path: String, _ args: [String], timeout: TimeInterval) -> Result? {
        guard FileManager.default.isExecutableFile(atPath: path) else { return nil }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = args

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
        } catch {
            return nil
        }

        let handle = pipe.fileHandleForReading
        let outputBuffer = OutputBuffer()

        let reader = Thread {
            let data = handle.readDataToEndOfFile()
            outputBuffer.replace(with: data)
        }
        reader.start()

        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning, Date() < deadline {
            usleep(5_000)
        }
        let timedOut = process.isRunning
        if timedOut {
            process.terminate()
            let terminateDeadline = Date().addingTimeInterval(0.5)
            while process.isRunning, Date() < terminateDeadline { usleep(5_000) }
            if process.isRunning {
                kill(process.processIdentifier, SIGKILL)
                let killDeadline = Date().addingTimeInterval(0.5)
                while process.isRunning, Date() < killDeadline { usleep(5_000) }
            }
        }

        // Дать читающему потоку дойти до EOF после выхода процесса.
        let readDeadline = Date().addingTimeInterval(1)
        while !reader.isFinished, Date() < readDeadline {
            usleep(2_000)
        }

        let data = outputBuffer.snapshot()
        return Result(
            output: String(data: data, encoding: .utf8) ?? "",
            exitCode: process.isRunning ? -1 : process.terminationStatus,
            timedOut: timedOut
        )
    }
}
