import AppKit
import SwiftUI

/// Разовый снимок главного окна для проверки вёрстки.
/// Включается переменной окружения WAYPOINT_SHOT=/путь/файл.png.
///
/// Снимает только главное окно: содержимое .sheet живёт в отдельном окне,
/// которое ни cacheDisplay, ни рендер слоя не захватывают — SwiftUI рисует
/// его через отдельный путь композиции.
@MainActor
enum Diagnostics {
    static func captureIfRequested() {
        let environment = ProcessInfo.processInfo.environment
        guard let path = environment["WAYPOINT_SHOT"] else { return }
        let delay = Double(environment["WAYPOINT_SHOT_DELAY"] ?? "2") ?? 2

        Task { @MainActor in
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            shoot(path)
        }
    }

    private static func shoot(_ path: String) {
        guard let window = NSApp.windows.first(where: { $0.isVisible && $0.canBecomeMain }),
              let view = window.contentView,
              let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else {
            print("[diag] окно недоступно")
            NSApp.terminate(nil)
            return
        }
        view.cacheDisplay(in: view.bounds, to: rep)
        if let data = rep.representation(using: .png, properties: [:]) {
            try? data.write(to: URL(fileURLWithPath: path))
            print("[diag] снимок сохранён: \(path)")
        }
        if ProcessInfo.processInfo.environment["WAYPOINT_SHOT_QUIT"] != nil {
            NSApp.terminate(nil)
        }
    }
}
