import SwiftUI
import WaypointCore
import OSLog

private let menuBarLogger = Logger(
    subsystem: Bundle.main.bundleIdentifier ?? "ru.mrvasil.waypoint",
    category: "MenuBar"
)

/// Содержимое меню в строке меню: статус, быстрый запуск, список прокси.
struct MenuBarContent: View {
    @Environment(AppModel.self) private var model
    let openMainWindow: () -> Void

    var body: some View {
        Label(
            "VPN · \(vpnStatusTitle)",
            systemImage: model.isSystemVPNReady
                ? "shield.fill"
                : (model.isSystemVPNActive ? "clock" : "shield")
        )

        Label(
            "Прокси · \(proxyStatusTitle)",
            systemImage: model.isLocalProxyActive
                ? "arrow.triangle.branch"
                : (model.isLocalProxyConnecting ? "clock" : "circle.dashed")
        )

        if let iface = model.bypass?.active {
            Label("Обход через \(iface)", systemImage: "network")
        }

        Divider()

        Button {
            model.toggleSystemVPN()
        } label: {
            Label(
                model.isSystemVPNActive ? "Отключить VPN" : "Включить VPN",
                systemImage: model.isSystemVPNActive ? "shield.slash" : "shield"
            )
        }
        .disabled(
            model.xrayPath == nil
                || (!model.isSystemVPNActive && model.state.systemVPNMainRouteIssue() != nil)
        )

        Button {
            model.toggleLocalProxy()
        } label: {
            Label(
                model.localProxyRequested ? "Отключить прокси" : "Включить прокси",
                systemImage: model.localProxyRequested ? "pause.circle" : "arrow.triangle.branch"
            )
        }
        .disabled(
            model.xrayPath == nil
                || model.state.proxies.filter(\.enabled).isEmpty
                || (model.isSystemVPNActive && !model.isSystemVPNReady)
        )

        if !model.state.proxies.isEmpty {
            Divider()
            ForEach(model.state.proxies.filter(\.enabled)) { proxy in
                Button {
                    model.copyToClipboard(proxy.address)
                } label: {
                    Label("Копировать \(proxy.address)", systemImage: "doc.on.doc")
                }
            }
        }

        Divider()

        Button {
            menuBarLogger.info("Open window requested")
            openMainWindow()
        } label: {
            Label("Открыть окно", systemImage: "macwindow")
        }

        Button {
            NSApp.terminate(nil)
        } label: {
            Label("Завершить", systemImage: "power")
        }
        .keyboardShortcut("q")
    }

    private var vpnStatusTitle: String {
        if model.isSystemVPNReady { return "включён" }
        if model.isSystemVPNActive { return "подключается" }
        return "выключен"
    }

    private var proxyStatusTitle: String {
        if model.isLocalProxyActive {
            return "включён (\(model.state.proxies.filter(\.enabled).count))"
        }
        if model.isLocalProxyConnecting { return "запускается" }
        return "выключен"
    }
}
