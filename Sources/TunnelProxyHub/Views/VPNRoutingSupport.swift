import SwiftUI
import TPHCore

enum VPNFallbackRuntimeTone: Equatable {
    case idle
    case waiting
    case active
    case unused

    var color: Color {
        switch self {
        case .active: Theme.accentGreen
        case .waiting: .orange
        case .idle, .unused: .secondary
        }
    }

    var symbol: String {
        switch self {
        case .active: "circle.fill"
        case .waiting: "waveform.path.ecg"
        case .idle: "arrow.right"
        case .unused: "circle.dashed"
        }
    }
}

struct VPNFallbackRuntimePresentation: Equatable {
    let text: String
    let tone: VPNFallbackRuntimeTone
}

extension AppModel {
    /// Единое отображение фактического выбора fallback во всех экранах.
    /// Xray выбирает outbound для новых соединений; существующие потоки не
    /// переносятся между кандидатами после смены выбора.
    func vpnFallbackRuntimePresentation(
        for group: VPNFallbackGroup,
        idleText: String
    ) -> VPNFallbackRuntimePresentation {
        guard isSystemVPNActive else {
            return VPNFallbackRuntimePresentation(text: idleText, tone: .idle)
        }
        guard state.usedVPNFallbackGroupIDs().contains(group.id) else {
            return VPNFallbackRuntimePresentation(
                text: "Не используется текущим VPN",
                tone: .unused
            )
        }
        guard isSystemVPNReady else {
            return VPNFallbackRuntimePresentation(
                text: "Запускаем проверку маршрутов…",
                tone: .waiting
            )
        }
        guard let status = fallbackRuntimeStatuses[group.id] else {
            return VPNFallbackRuntimePresentation(
                text: "Определяем активный маршрут…",
                tone: .waiting
            )
        }

        let name = state.vpnFallbackRuntimeName(group: group, status: status)
        guard name != "Маршрут определяется" else {
            return VPNFallbackRuntimePresentation(
                text: "Определяем активный маршрут…",
                tone: .waiting
            )
        }
        if status.phase == .warming {
            return VPNFallbackRuntimePresentation(
                text: "Сразу через: \(name) · проверяем резерв",
                tone: .waiting
            )
        }
        return VPNFallbackRuntimePresentation(
            text: "Сейчас: \(name)",
            tone: status.phase == .terminal ? .waiting : .active
        )
    }
}

struct VPNFallbackRuntimeLabel: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    let group: VPNFallbackGroup
    let idleText: String
    var emphasized = false

    private var presentation: VPNFallbackRuntimePresentation {
        model.vpnFallbackRuntimePresentation(for: group, idleText: idleText)
    }

    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: presentation.tone.symbol)
                .font(.system(size: emphasized ? 8 : 7, weight: .bold))
                .symbolEffect(
                    .pulse,
                    options: .repeating,
                    isActive: presentation.tone == .waiting && !reduceMotion
                )
                .contentTransition(.symbolEffect(.replace))

            Text(presentation.text)
                .lineLimit(1)
                .contentTransition(.opacity)
        }
        .font(emphasized ? .caption.weight(.semibold) : .caption)
        .foregroundStyle(presentation.tone.color)
        .padding(.horizontal, emphasized ? 8 : 0)
        .padding(.vertical, emphasized ? 4 : 0)
        .background(
            emphasized ? presentation.tone.color.opacity(0.1) : Color.clear,
            in: Capsule()
        )
        .animation(
            reduceMotion ? nil : .easeInOut(duration: 0.18),
            value: presentation
        )
        .help("Текущий выбор Xray для новых соединений. Уже открытые соединения продолжают идти по прежнему маршруту.")
        .accessibilityLabel("\(presentation.text). Выбор применяется к новым соединениям")
    }
}

extension Tunnel {
    var routingSymbol: String {
        switch type.lowercased() {
        case "wireguard": "shield.lefthalf.filled"
        case "vless", "vmess": "point.3.connected.trianglepath.dotted"
        case "trojan": "bolt.shield.fill"
        case "shadowsocks", "ss": "lock.shield.fill"
        case "socks", "http": "network"
        default: "link"
        }
    }

    var routingColor: Color {
        switch type.lowercased() {
        case "wireguard": .blue
        case "vless", "vmess": .cyan
        case "trojan": .purple
        case "shadowsocks", "ss": .indigo
        case "socks", "http": .orange
        default: .gray
        }
    }
}

extension VPNRouteTarget.Kind {
    var routingTitle: String {
        switch self {
        case .direct: "Напрямую"
        case .block: "Блокировать"
        case .tunnel: "Туннель"
        case .chain: "Цепочка"
        case .fallback: "Fallback"
        }
    }

    var routingSymbol: String {
        switch self {
        case .direct: "arrow.up.right"
        case .block: "hand.raised.fill"
        case .tunnel: "shield.lefthalf.filled"
        case .chain: "link"
        case .fallback: "arrow.trianglehead.branch"
        }
    }

    var routingColor: Color {
        switch self {
        case .direct: .green
        case .block: .red
        case .tunnel: .blue
        case .chain: .cyan
        case .fallback: .orange
        }
    }
}

extension VPNFallbackFinalAction {
    var routingTitle: String {
        switch self {
        case .block: "Блокировать трафик"
        case .direct: "Выпустить напрямую"
        }
    }

    var routingSymbol: String {
        self == .block ? "hand.raised.fill" : "arrow.up.right"
    }
}

extension AppState {
    func vpnRouteTargetName(_ target: VPNRouteTarget) -> String {
        switch target.kind {
        case .direct:
            return "Напрямую"
        case .block:
            return "Блокировать"
        case .tunnel:
            return tunnel(id: target.referenceId)?.name ?? "Туннель недоступен"
        case .chain:
            return vpnTunnelChain(id: target.referenceId)?.name ?? "Цепочка недоступна"
        case .fallback:
            return vpnFallbackGroup(id: target.referenceId)?.name ?? "Fallback недоступен"
        }
    }

    func vpnFallbackCandidateName(_ target: VPNRouteTarget) -> String {
        switch target.kind {
        case .tunnel:
            tunnel(id: target.referenceId)?.name ?? "Туннель недоступен"
        case .chain:
            vpnTunnelChain(id: target.referenceId)?.name ?? "Цепочка недоступна"
        default:
            target.kind.routingTitle
        }
    }

    func vpnFallbackRuntimeName(
        group: VPNFallbackGroup,
        status: VPNFallbackRuntimeStatus
    ) -> String {
        if let memberID = status.selectedMemberID,
           let member = group.members.first(where: { $0.id == memberID }) {
            return vpnFallbackCandidateName(member.target)
        }
        switch status.selectedOutboundTag {
        case "direct":
            return "Напрямую · резервное действие"
        case "block":
            return "Блокировка · резервное действие"
        default:
            return "Маршрут определяется"
        }
    }

    func vpnMainRoutePresentation() -> VPNMainRoutePresentation {
        guard let target = systemVPN.target else {
            return VPNMainRoutePresentation(
                name: "Маршрут не выбран",
                detail: "Выберите туннель, цепочку или fallback",
                symbol: "point.3.connected.trianglepath.dotted",
                color: .gray
            )
        }

        switch target.kind {
        case .tunnel:
            guard let tunnel = tunnel(id: target.referenceId) else {
                return VPNMainRoutePresentation(
                    name: "Туннель недоступен",
                    detail: "Выберите другой основной маршрут",
                    symbol: "exclamationmark.triangle.fill",
                    color: .orange
                )
            }
            return VPNMainRoutePresentation(
                name: tunnel.name,
                detail: "Обычный туннель · \(tunnel.type.uppercased())",
                symbol: tunnel.routingSymbol,
                color: tunnel.routingColor
            )
        case .chain:
            guard let chain = vpnTunnelChain(id: target.referenceId) else {
                return VPNMainRoutePresentation(
                    name: "Цепочка недоступна",
                    detail: "Выберите другой основной маршрут",
                    symbol: "exclamationmark.triangle.fill",
                    color: .orange
                )
            }
            return VPNMainRoutePresentation(
                name: chain.name,
                detail: "Цепочка · \(chain.tunnelIds.count) узла",
                symbol: "link",
                color: .cyan
            )
        case .fallback:
            guard let group = vpnFallbackGroup(id: target.referenceId) else {
                return VPNMainRoutePresentation(
                    name: "Fallback недоступен",
                    detail: "Выберите другой основной маршрут",
                    symbol: "exclamationmark.triangle.fill",
                    color: .orange
                )
            }
            return VPNMainRoutePresentation(
                name: group.name,
                detail: "Fallback · \(group.members.count) варианта",
                symbol: "arrow.trianglehead.branch",
                color: .orange
            )
        case .direct, .block:
            return VPNMainRoutePresentation(
                name: "Маршрут недоступен",
                detail: "Основной маршрут должен вести в туннель",
                symbol: "exclamationmark.triangle.fill",
                color: .orange
            )
        }
    }
}

struct VPNMainRoutePresentation {
    let name: String
    let detail: String
    let symbol: String
    let color: Color
}

/// Компактный нативный picker для catch-all маршрута системного VPN. Direct и
/// Block здесь намеренно отсутствуют: для них существуют first-match политики.
struct VPNMainRoutePicker: View {
    @Environment(AppModel.self) private var model
    @Binding var selection: VPNRouteTarget?

    var body: some View {
        Picker("Основной маршрут", selection: $selection) {
            if let selection, model.state.systemVPNMainRouteIssue() != nil {
                Section("Текущее значение") {
                    Label(model.state.vpnRouteTargetName(selection), systemImage: "exclamationmark.triangle.fill")
                        .tag(Optional(selection))
                }
            }

            tunnelOptions
            chainOptions
            fallbackOptions

            if !hasAvailableRoutes {
                Text("Нет доступных маршрутов")
                    .tag(Optional<VPNRouteTarget>.none)
            }
        }
        .labelsHidden()
    }

    private var hasAvailableRoutes: Bool {
        !model.state.tunnels.isEmpty
            || model.state.vpnTunnelChains.contains { model.state.vpnTunnelChainIssue($0) == nil }
            || model.state.vpnFallbackGroups.contains { model.state.vpnFallbackGroupIssue($0) == nil }
    }

    @ViewBuilder
    private var tunnelOptions: some View {
        ForEach(model.state.subscriptions) { subscription in
            let tunnels = model.state.tunnels.filter { $0.subscriptionId == subscription.id }
            if !tunnels.isEmpty {
                Section(subscription.name) {
                    ForEach(tunnels) { tunnel in
                        Label(tunnel.name, systemImage: tunnel.routingSymbol)
                            .tag(Optional(VPNRouteTarget.tunnel(tunnel.id)))
                    }
                }
            }
        }

        let manual = model.state.tunnels.filter { $0.subscriptionId == nil }
        if !manual.isEmpty {
            Section("Мои туннели") {
                ForEach(manual) { tunnel in
                    Label(tunnel.name, systemImage: tunnel.routingSymbol)
                        .tag(Optional(VPNRouteTarget.tunnel(tunnel.id)))
                }
            }
        }
    }

    @ViewBuilder
    private var chainOptions: some View {
        let chains = model.state.vpnTunnelChains.filter { model.state.vpnTunnelChainIssue($0) == nil }
        if !chains.isEmpty {
            Section("Цепочки") {
                ForEach(chains) { chain in
                    Label(chain.name, systemImage: "link")
                        .tag(Optional(VPNRouteTarget.chain(chain.id)))
                }
            }
        }
    }

    @ViewBuilder
    private var fallbackOptions: some View {
        let groups = model.state.vpnFallbackGroups.filter { model.state.vpnFallbackGroupIssue($0) == nil }
        if !groups.isEmpty {
            Section("Fallback") {
                ForEach(groups) { group in
                    Label(group.name, systemImage: "arrow.trianglehead.branch")
                        .tag(Optional(VPNRouteTarget.fallback(group.id)))
                }
            }
        }
    }
}

/// Содержимое dashboard-меню использует те же группы, что и picker VPN-вкладки.
struct VPNMainRouteMenuItems: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ForEach(model.state.subscriptions) { subscription in
            let tunnels = model.state.tunnels.filter { $0.subscriptionId == subscription.id }
            if !tunnels.isEmpty {
                Section(compactName(subscription.name)) {
                    ForEach(tunnels) { tunnel in
                        routeButton(.tunnel(tunnel.id), title: tunnel.name, symbol: tunnel.routingSymbol)
                    }
                }
            }
        }

        let manual = model.state.tunnels.filter { $0.subscriptionId == nil }
        if !manual.isEmpty {
            Section("Мои туннели") {
                ForEach(manual) { tunnel in
                    routeButton(.tunnel(tunnel.id), title: tunnel.name, symbol: tunnel.routingSymbol)
                }
            }
        }

        let chains = model.state.vpnTunnelChains.filter { model.state.vpnTunnelChainIssue($0) == nil }
        if !chains.isEmpty {
            Section("Цепочки") {
                ForEach(chains) { chain in
                    routeButton(.chain(chain.id), title: chain.name, symbol: "link")
                }
            }
        }

        let groups = model.state.vpnFallbackGroups.filter { model.state.vpnFallbackGroupIssue($0) == nil }
        if !groups.isEmpty {
            Section("Fallback") {
                ForEach(groups) { group in
                    routeButton(.fallback(group.id), title: group.name, symbol: "arrow.trianglehead.branch")
                }
            }
        }
    }

    @ViewBuilder
    private func routeButton(_ target: VPNRouteTarget, title: String, symbol: String) -> some View {
        Button {
            model.setSystemVPNMainRoute(target)
        } label: {
            Label(compactName(title), systemImage: model.state.systemVPN.target == target ? "checkmark" : symbol)
        }
    }

    private func compactName(_ value: String) -> String {
        guard value.count > 30 else { return value }
        return String(value.prefix(29)) + "…"
    }
}

struct VPNRouteTargetPicker: View {
    @Environment(AppModel.self) private var model
    @Binding var selection: VPNRouteTarget

    var body: some View {
        Picker("Маршрут", selection: $selection) {
            if model.state.vpnRouteTargetIssue(selection) != nil {
                Section("Текущее значение") {
                    Label("Недоступный маршрут", systemImage: "exclamationmark.triangle.fill")
                        .tag(selection)
                }
            }

            Section("Действие") {
                Label("Напрямую", systemImage: "arrow.up.right")
                    .tag(VPNRouteTarget.direct)
                Label("Блокировать", systemImage: "hand.raised.fill")
                    .tag(VPNRouteTarget.block)
            }

            tunnelOptions

            if !model.state.vpnTunnelChains.isEmpty {
                Section("Цепочки") {
                    ForEach(model.state.vpnTunnelChains) { chain in
                        Label(chain.name, systemImage: "link")
                            .tag(VPNRouteTarget.chain(chain.id))
                    }
                }
            }

            if !model.state.vpnFallbackGroups.isEmpty {
                Section("Fallback") {
                    ForEach(model.state.vpnFallbackGroups) { group in
                        Label(group.name, systemImage: "arrow.trianglehead.branch")
                            .tag(VPNRouteTarget.fallback(group.id))
                    }
                }
            }
        }
        .labelsHidden()
    }

    @ViewBuilder
    private var tunnelOptions: some View {
        ForEach(model.state.subscriptions) { subscription in
            let tunnels = model.state.tunnels.filter { $0.subscriptionId == subscription.id }
            if !tunnels.isEmpty {
                Section(subscription.name) {
                    ForEach(tunnels) { tunnel in
                        Label(tunnel.name, systemImage: tunnel.routingSymbol)
                            .tag(VPNRouteTarget.tunnel(tunnel.id))
                    }
                }
            }
        }

        let manual = model.state.tunnels.filter { $0.subscriptionId == nil }
        if !manual.isEmpty {
            Section("Мои туннели") {
                ForEach(manual) { tunnel in
                    Label(tunnel.name, systemImage: tunnel.routingSymbol)
                        .tag(VPNRouteTarget.tunnel(tunnel.id))
                }
            }
        }
    }
}

struct VPNFallbackCandidatePicker: View {
    @Environment(AppModel.self) private var model
    @Binding var selection: VPNRouteTarget

    var body: some View {
        Picker("Маршрут", selection: $selection) {
            if model.state.vpnRouteTargetIssue(selection, allowFallback: false) != nil {
                Section("Текущее значение") {
                    Label("Недоступный маршрут", systemImage: "exclamationmark.triangle.fill")
                        .tag(selection)
                }
            }

            ForEach(model.state.subscriptions) { subscription in
                let tunnels = model.state.tunnels.filter { $0.subscriptionId == subscription.id }
                if !tunnels.isEmpty {
                    Section(subscription.name) {
                        ForEach(tunnels) { tunnel in
                            Label(tunnel.name, systemImage: tunnel.routingSymbol)
                                .tag(VPNRouteTarget.tunnel(tunnel.id))
                        }
                    }
                }
            }

            let manual = model.state.tunnels.filter { $0.subscriptionId == nil }
            if !manual.isEmpty {
                Section("Мои туннели") {
                    ForEach(manual) { tunnel in
                        Label(tunnel.name, systemImage: tunnel.routingSymbol)
                            .tag(VPNRouteTarget.tunnel(tunnel.id))
                    }
                }
            }

            if !model.state.vpnTunnelChains.isEmpty {
                Section("Цепочки") {
                    ForEach(model.state.vpnTunnelChains) { chain in
                        Label(chain.name, systemImage: "link")
                            .tag(VPNRouteTarget.chain(chain.id))
                    }
                }
            }
        }
        .labelsHidden()
    }
}
