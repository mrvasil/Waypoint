import Foundation

/// Минимальный тестовый каркас.
///
/// XCTest и swift-testing доступны только с полным Xcode; здесь только
/// Command Line Tools, поэтому проверки оформлены отдельным бинарником.
public final class Harness {
    private var passed = 0
    private var failed = 0
    private var currentSuite = ""

    public init() {}

    public func suite(_ name: String) {
        currentSuite = name
        print("\n\(name):")
    }

    public func check(_ name: String, _ body: () throws -> Void) {
        do {
            try body()
            passed += 1
            print("  ✓ \(name)")
        } catch {
            failed += 1
            print("  ✗ \(name)")
            print("    \(error)")
        }
    }

    public func finish() -> Never {
        print("\nпройдено: \(passed), провалено: \(failed)")
        if failed > 0 {
            print("ЕСТЬ ОШИБКИ")
            exit(1)
        }
        print("OK")
        exit(0)
    }
}

public struct Failure: Error, CustomStringConvertible {
    public let description: String
    public init(_ message: String) { description = message }
}

public func expect(
    _ condition: Bool,
    _ message: @autoclosure () -> String = "условие не выполнено",
    file: StaticString = #file, line: UInt = #line
) throws {
    if !condition {
        throw Failure("\(message()) (строка \(line))")
    }
}

public func expectEqual<T: Equatable>(
    _ actual: T?, _ expected: T?,
    _ label: String = "",
    file: StaticString = #file, line: UInt = #line
) throws {
    if actual != expected {
        let what = label.isEmpty ? "" : "\(label): "
        throw Failure("\(what)получено \(String(describing: actual)), ожидалось \(String(describing: expected)) (строка \(line))")
    }
}

public func expectThrows(
    _ label: String = "должно бросить исключение",
    file: StaticString = #file, line: UInt = #line,
    _ body: () throws -> Void
) throws {
    do {
        try body()
        throw Failure("\(label) — но исключения не было (строка \(line))")
    } catch is Failure {
        throw Failure("\(label) — но исключения не было (строка \(line))")
    } catch {
        // ожидаемо
    }
}
