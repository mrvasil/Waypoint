import SwiftUI
import WaypointCore

enum AppSection: String, CaseIterable, Identifiable {
    case overview
    case tunnels
    case proxies
    case routing
    case logs

    var id: String { rawValue }

    var title: String {
        switch self {
        case .overview: L10n.string("Обзор")
        case .tunnels: L10n.string("Туннели")
        case .proxies: L10n.string("Прокси")
        case .routing: "VPN"
        case .logs: L10n.string("Журнал")
        }
    }

    var symbol: String {
        switch self {
        case .overview: "rectangle.grid.2x2.fill"
        case .tunnels: "point.3.connected.trianglepath.dotted"
        case .proxies: "arrow.triangle.branch"
        case .routing: "shield.fill"
        case .logs: "text.alignleft"
        }
    }

    var color: Color {
        switch self {
        case .overview: .blue
        case .tunnels: .cyan
        case .proxies: .indigo
        case .routing: .blue
        case .logs: .gray
        }
    }
}

struct AppSidebar: View {
    @Environment(AppModel.self) private var model
    @Binding var selection: String

    var body: some View {
        List(selection: $selection) {
            Section {
                ForEach(AppSection.allCases) { section in
                    Label {
                        Text(section.title)
                    } icon: {
                        SymbolTile(symbol: section.symbol, color: section.color, size: 24)
                    }
                    .tag(section.rawValue)
                }
            }

            Section("Состояние") {
                SidebarConnectionStatusRow(
                    title: "VPN",
                    detail: vpnDetail,
                    symbol: model.isSystemVPNReady ? "shield.fill" : "shield",
                    state: vpnState
                )

                SidebarConnectionStatusRow(
                    title: "Прокси",
                    detail: proxyDetail,
                    symbol: "arrow.triangle.branch",
                    state: proxyState
                )
            }
        }
        .listStyle(.sidebar)
        .padding(.top, 8)
        .padding(.horizontal, 8)
        .navigationSplitViewColumnWidth(min: 190, ideal: 215, max: 260)
    }

    private var vpnState: SidebarConnectionStatusRow.State {
        guard model.isSystemVPNActive else { return .inactive }
        return model.isSystemVPNReady ? .active : .connecting
    }

    private var proxyState: SidebarConnectionStatusRow.State {
        if model.isLocalProxyActive { return .active }
        return model.isLocalProxyConnecting ? .connecting : .inactive
    }

    private var vpnDetail: String {
        if model.isSystemVPNReady {
            return L10n.format("Через %@", model.status.vpnInterface ?? "utun")
        }
        if model.isSystemVPNActive { return L10n.string("Подключение…") }
        if let issue = model.state.systemVPNMainRouteIssue() { return issue }
        return model.state.vpnMainRoutePresentation().name
    }

    private var proxyDetail: String {
        let count = model.state.proxies.filter(\.enabled).count
        if model.isLocalProxyActive { return L10n.format("%lld локальных адресов", count) }
        if model.isLocalProxyConnecting { return L10n.string("Запуск…") }
        return count == 0 ? L10n.string("Нет адресов") : L10n.format("%lld настроено", count)
    }
}

private struct SidebarConnectionStatusRow: View {
    enum State {
        case inactive
        case connecting
        case active

        var color: Color {
            switch self {
            case .inactive: .secondary
            case .connecting: .orange
            case .active: .green
            }
        }

        var title: String {
            switch self {
            case .inactive: L10n.string("выключен")
            case .connecting: L10n.string("подключается")
            case .active: L10n.string("включён")
            }
        }
    }

    let title: String
    let detail: String
    let symbol: String
    let state: State

    var body: some View {
        HStack(spacing: 9) {
            Image(systemName: symbol)
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(state.color)
                .frame(width: 18)

            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 5) {
                    Text(L10n.string(title))
                    Circle()
                        .fill(state.color)
                        .frame(width: 6, height: 6)
                }

                Text(L10n.string(detail))
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(
            L10n.format("%@, %@, %@", L10n.string(title), state.title, L10n.string(detail))
        )
    }
}
