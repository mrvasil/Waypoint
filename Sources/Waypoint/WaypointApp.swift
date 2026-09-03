import SwiftUI
import WaypointCore
import OSLog

@main
struct WaypointApp: App {
    @State private var model = AppModel()
    @AppStorage(AppLanguage.storageKey) private var appLanguageValue = AppLanguage.system.rawValue
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    private var appLanguage: AppLanguage {
        AppLanguage(rawValue: appLanguageValue) ?? .system
    }

    var body: some Scene {
        WindowGroup("Waypoint") {
            ContentView()
                .environment(model)
                .environment(\.locale, appLanguage.locale)
                .task {
                    delegate.configureGlobalVPNShortcut {
                        model.toggleSystemVPN()
                    }
                }
        }
        .defaultSize(width: 980, height: 680)
        .windowResizability(.contentMinSize)
        .defaultLaunchBehavior(.presented)
        .commands {
            CommandMenu(L10n.string("Подключение")) {
                Button(L10n.string(model.isSystemVPNActive ? "Отключить VPN" : "Включить VPN")) {
                    model.toggleSystemVPN()
                }
                .keyboardShortcut("v", modifiers: [.command, .shift])

                Button(L10n.string(model.localProxyRequested ? "Отключить прокси" : "Включить прокси")) {
                    model.toggleLocalProxy()
                }

                Divider()

                Button(L10n.string("Проверить конфиг")) { model.validate() }
                    .keyboardShortcut("t", modifiers: .command)
            }
        }

        // Иконка в строке меню: статус и переключение без открытия окна.
        MenuBarExtra {
            MenuBarContent {
                delegate.openMainWindow()
            }
                .environment(model)
                .environment(\.locale, appLanguage.locale)
        } label: {
            MenuBarIcon(active: model.isRunning)
        }
        .menuBarExtraStyle(.menu)
    }
}

/// Приложение остаётся в Dock и живёт, пока открыто окно или есть менюбар.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var mainWindow: NSWindow?
    private let globalVPNHotKey = GlobalHotKeyController()
    private let logger = Logger(
        subsystem: Bundle.main.bundleIdentifier ?? "ru.mrvasil.waypoint",
        category: "Windowing"
    )

    func applicationDidFinishLaunching(_ notification: Notification) {
        logger.info("Application finished launching")
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
        Diagnostics.captureIfRequested()
        Task { @MainActor [weak self] in
            for _ in 0..<20 {
                if self?.captureMainWindow() == true {
                    _ = self?.showMainWindow()
                    return
                }
                try? await Task.sleep(for: .milliseconds(100))
            }
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        globalVPNHotKey.invalidate()
    }

    func configureGlobalVPNShortcut(action: @escaping @MainActor () -> Void) {
        do {
            try globalVPNHotKey.registerVPNAction(action)
            logger.info("Registered global VPN shortcut Command-Shift-V")
        } catch {
            logger.error("Global VPN shortcut unavailable: \(error.localizedDescription, privacy: .public)")
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        // Окно закрыли — приложение продолжает работать в строке меню.
        false
    }

    /// SwiftUI освобождает единственное закрытое окно WindowGroup. Держим его
    /// живым, чтобы пункт строки меню мог мгновенно вернуть тот же интерфейс и
    /// его scene-scoped состояние.
    @MainActor
    @discardableResult
    func captureMainWindow() -> Bool {
        guard let window = NSApp.windows.first(where: { $0.canBecomeMain && $0.isVisible }) else {
            logger.debug("No visible main window available to capture")
            return false
        }
        window.isReleasedWhenClosed = false
        mainWindow = window
        logger.info("Captured main window")
        return true
    }

    @MainActor
    @discardableResult
    func showMainWindow() -> Bool {
        guard let mainWindow else {
            logger.info("No captured window available to show")
            return false
        }
        mainWindow.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        logger.info("Requested captured window front; visible=\(mainWindow.isVisible, privacy: .public)")
        return mainWindow.isVisible
    }

    /// После настоящего Close SwiftUI завершает scene. В этом случае создаём
    /// новую через ту же responder-команду, что использует File → New Window.
    @MainActor
    func openMainWindow() {
        logger.info("Open main window action received")
        if showMainWindow() { return }

        NSApp.activate(ignoringOtherApps: true)
        let allMenuItems = NSApp.mainMenu?.items
            .compactMap(\.submenu)
            .flatMap(\.items) ?? []
        let newWindowItem = allMenuItems.first(where: {
            $0.keyEquivalent.lowercased() == "n" && $0.action != nil
        }) ?? NSApp.mainMenu?.items.dropFirst().first?.submenu?.items.first(where: {
            !$0.isSeparatorItem && $0.isEnabled && $0.action != nil
        })

        guard let newWindowItem, let action = newWindowItem.action else {
            logger.error("New window command was not found")
            return
        }

        logger.info("Sending new window command")
        NSApp.sendAction(action, to: newWindowItem.target, from: newWindowItem)
        Task { @MainActor [weak self] in
            for _ in 0..<20 {
                try? await Task.sleep(for: .milliseconds(100))
                if self?.captureMainWindow() == true {
                    _ = self?.showMainWindow()
                    return
                }
            }
        }
    }
}
