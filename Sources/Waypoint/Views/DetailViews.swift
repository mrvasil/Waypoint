import SwiftUI
import WaypointCore

struct DashboardView: View {
    @Environment(AppModel.self) private var model
    let onAddTunnel: () -> Void
    let onAddProxy: () -> Void
    let onOpenSection: (AppSection) -> Void

    private var enabledProxies: [LocalProxy] {
        model.state.proxies.filter(\.enabled)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                controlCenter

                LazyVGrid(
                    columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 2),
                    spacing: 12
                ) {
                    DashboardMetricButton(
                        title: "Туннели",
                        value: String(model.state.tunnels.count),
                        detail: "Настроено",
                        symbol: "point.3.connected.trianglepath.dotted",
                        action: { onOpenSection(.tunnels) }
                    )
                    DashboardMetricButton(
                        title: "Прокси",
                        value: "\(enabledProxies.count)/\(model.state.proxies.count)",
                        detail: "Включено",
                        symbol: "arrow.triangle.branch",
                        action: { onOpenSection(.proxies) }
                    )
                }

                VStack(alignment: .leading, spacing: 12) {
                    SectionHeader(title: "Быстрый доступ")

                    if enabledProxies.isEmpty {
                        Card {
                            HStack(spacing: 14) {
                                SymbolTile(symbol: "arrow.triangle.branch", color: .accentColor, size: 38)
                                VStack(alignment: .leading, spacing: 3) {
                                    Text("Нет активных прокси")
                                        .font(.headline)
                                    Text("Создайте первый локальный адрес для приложений.")
                                        .font(.callout)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                Button("Создать", systemImage: "plus", action: onAddProxy)
                                    .buttonStyle(.borderedProminent)
                            }
                        }
                    } else {
                        GroupCard {
                            ForEach(Array(enabledProxies.enumerated()), id: \.element.id) { index, proxy in
                                DashboardProxyRow(proxy: proxy)
                                if index < enabledProxies.count - 1 {
                                    Divider().padding(.leading, 62)
                                }
                            }
                        }
                    }
                }
            }
            .frame(maxWidth: Theme.contentWidth)
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .background(.background)
    }

    private var controlCenter: some View {
        VStack(alignment: .leading, spacing: 14) {
            SectionHeader(
                title: "Подключения",
                subtitle: "VPN и локальный прокси работают независимо и могут быть включены одновременно"
            )

            LazyVGrid(
                columns: [GridItem(.adaptive(minimum: 320), spacing: 14)],
                spacing: 14
            ) {
                DashboardConnectionControl(
                    title: "Локальный прокси",
                    detail: proxyDetail,
                    actionTitle: model.localProxyRequested ? "Выключить" : "Включить",
                    symbol: "point.3.connected.trianglepath.dotted",
                    kind: .proxy,
                    state: proxyControlState,
                    disabled: model.xrayPath == nil
                        || enabledProxies.isEmpty
                        || (model.isSystemVPNActive && !model.isSystemVPNReady),
                    action: model.toggleLocalProxy
                )

                DashboardConnectionControl(
                    title: "Системный VPN",
                    detail: vpnDetail,
                    actionTitle: model.isSystemVPNActive ? "Выключить" : "Включить",
                    symbol: "globe",
                    kind: .vpn,
                    state: vpnControlState,
                    disabled: model.xrayPath == nil
                        || (!model.isSystemVPNActive && model.state.systemVPNMainRouteIssue() != nil),
                    action: model.toggleSystemVPN
                )
            }

            DashboardVPNRoutePicker(
                onAddTunnel: onAddTunnel,
                onOpenRoutes: { onOpenSection(.routing) }
            )
        }
    }

    private var proxyDetail: String {
        guard model.xrayPath != nil else { return "Xray не найден" }
        if model.isLocalProxyActive {
            return "Включено адресов: \(enabledProxies.count)"
        }
        if model.isLocalProxyConnecting {
            return "Добавление локальных адресов"
        }
        if enabledProxies.isEmpty {
            return "Нет включённых адресов"
        }
        return "Готово адресов: \(enabledProxies.count)"
    }

    private var vpnDetail: String {
        guard model.xrayPath != nil else { return "Xray не найден" }
        if model.isSystemVPNReady {
            return "Весь трафик · \(model.status.vpnInterface ?? "utun")"
        }
        if model.isSystemVPNActive {
            return "Запуск системного туннеля"
        }
        if let issue = model.state.systemVPNMainRouteIssue() {
            return issue
        }
        return model.state.vpnMainRoutePresentation().name
    }

    private var vpnControlState: DashboardConnectionControl.ControlState {
        guard model.isSystemVPNActive else { return .inactive }
        return model.isSystemVPNReady ? .active : .connecting
    }

    private var proxyControlState: DashboardConnectionControl.ControlState {
        if model.isLocalProxyActive { return .active }
        return model.isLocalProxyConnecting ? .connecting : .inactive
    }
}

struct TunnelsView: View {
    @Environment(AppModel.self) private var model
    let searchText: String
    let onAdd: () -> Void

    private var normalizedSearch: String {
        searchText.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func matches(_ tunnel: Tunnel) -> Bool {
        normalizedSearch.isEmpty ||
            [tunnel.name, tunnel.type, tunnel.host].contains { value in
                value.localizedCaseInsensitiveContains(normalizedSearch)
            }
    }

    private func tunnels(for subscription: Subscription) -> [Tunnel] {
        let all = model.state.tunnels.filter { $0.subscriptionId == subscription.id }
        let subscriptionMatches = [subscription.name, subscription.url].contains {
            $0.localizedCaseInsensitiveContains(normalizedSearch)
        }
        return normalizedSearch.isEmpty || subscriptionMatches ? all : all.filter(matches)
    }

    private var subscriptions: [Subscription] {
        model.state.subscriptions.filter { subscription in
            normalizedSearch.isEmpty
                || [subscription.name, subscription.url].contains {
                    $0.localizedCaseInsensitiveContains(normalizedSearch)
                }
                || !tunnels(for: subscription).isEmpty
        }
    }

    private var manualTunnels: [Tunnel] {
        model.state.tunnels.filter { $0.subscriptionId == nil && matches($0) }
    }

    private var hasResults: Bool {
        !subscriptions.isEmpty || !manualTunnels.isEmpty
    }

    private var tunnelIDs: [String] {
        model.state.tunnels.map(\.id)
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Theme.pageSpacing) {
                if !hasResults {
                    EmptyState(
                        symbol: searchText.isEmpty ? "point.3.connected.trianglepath.dotted" : "magnifyingglass",
                        title: searchText.isEmpty ? "Туннелей пока нет" : "Ничего не найдено",
                        description: searchText.isEmpty
                            ? "Добавьте ссылку, WireGuard-конфиг или URL подписки."
                            : "Попробуйте изменить поисковый запрос.",
                        actionTitle: searchText.isEmpty ? "Добавить туннель" : nil,
                        action: searchText.isEmpty ? onAdd : nil
                    )
                } else {
                    if !subscriptions.isEmpty {
                        SectionHeader(
                            title: "Подписки",
                            subtitle: "Автообновление каждые 15 минут",
                            actionTitle: "Обновить все",
                            action: { Task { await model.refreshAllSubscriptions(notify: true) } }
                        )

                        ForEach(subscriptions) { subscription in
                            SubscriptionCard(
                                subscription: subscription,
                                tunnels: tunnels(for: subscription)
                            )
                        }
                    }

                    if !manualTunnels.isEmpty {
                        SectionHeader(
                            title: "Мои туннели",
                            subtitle: "Добавлены вручную · \(manualTunnels.count)"
                        )

                        GroupCard {
                            ForEach(Array(manualTunnels.enumerated()), id: \.element.id) { index, tunnel in
                                TunnelRow(tunnel: tunnel)
                                if index < manualTunnels.count - 1 {
                                    Divider().padding(.leading, 72)
                                }
                            }
                        }
                    }
                }
            }
            .frame(maxWidth: Theme.contentWidth)
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .background(.background)
        .task(id: tunnelIDs) {
            model.refreshTunnelLatenciesIfNeeded()
        }
    }
}

private struct SubscriptionCard: View {
    @Environment(AppModel.self) private var model
    @State private var confirmingDelete = false

    let subscription: Subscription
    let tunnels: [Tunnel]

    private var isRefreshing: Bool {
        model.refreshingSubscriptionIds.contains(subscription.id)
    }

    var body: some View {
        GroupCard {
            VStack(spacing: 0) {
                HStack(spacing: 13) {
                    SymbolTile(symbol: "rectangle.stack.fill", color: .blue, size: 40)

                    VStack(alignment: .leading, spacing: 3) {
                        Text(subscription.name)
                            .font(.body.weight(.semibold))
                            .lineLimit(1)
                        Text(subscriptionHost)
                            .font(.caption.monospaced())
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }

                    Spacer(minLength: 12)

                    if isRefreshing {
                        ProgressView()
                            .controlSize(.small)
                            .help("Обновление подписки")
                    } else {
                        Button("Обновить", systemImage: "arrow.clockwise") {
                            Task { await model.refreshSubscription(subscription.id) }
                        }
                        .labelStyle(.iconOnly)
                        .buttonStyle(.borderless)
                        .help("Обновить подписку")
                    }

                    Menu {
                        Button("Скопировать URL", systemImage: "doc.on.doc") {
                            model.copyToClipboard(subscription.url)
                        }
                        Divider()
                        Button("Удалить подписку", systemImage: "trash", role: .destructive) {
                            confirmingDelete = true
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                            .foregroundStyle(.secondary)
                    }
                    .menuStyle(.borderlessButton)
                    .menuIndicator(.hidden)
                    .fixedSize()
                }
                .padding(16)

                Divider()

                if tunnels.isEmpty {
                    HStack(spacing: 8) {
                        Image(systemName: "tray")
                        Text("В этой группе нет подходящих узлов")
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(16)
                } else {
                    ForEach(Array(tunnels.enumerated()), id: \.element.id) { index, tunnel in
                        TunnelRow(tunnel: tunnel)
                        if index < tunnels.count - 1 {
                            Divider().padding(.leading, 72)
                        }
                    }
                }

                Divider()

                HStack(spacing: 6) {
                    if let error = model.subscriptionErrors[subscription.id] {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                        Text(error)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    } else {
                        Image(systemName: "checkmark.circle.fill")
                            .foregroundStyle(Theme.accentGreen)
                        Text(lastUpdatedText)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Text("\(tunnels.count) узл.")
                        .foregroundStyle(.tertiary)
                }
                .font(.caption)
                .padding(.horizontal, 16)
                .padding(.vertical, 10)
            }
        }
        .confirmationDialog(
            "Удалить подписку «\(subscription.name)»?",
            isPresented: $confirmingDelete
        ) {
            Button("Удалить подписку", role: .destructive) {
                model.removeSubscription(subscription.id)
            }
            Button("Отмена", role: .cancel) {}
        } message: {
            Text("Все её узлы будут удалены. Связанные прокси переключатся на прямой маршрут.")
        }
    }

    private var lastUpdatedText: String {
        guard let date = subscription.lastUpdatedAt else { return "Ещё не обновлялась" }
        return "Обновлено \(date.formatted(date: .abbreviated, time: .shortened))"
    }

    private var subscriptionHost: String {
        URL(string: subscription.url)?.host ?? "URL подписки"
    }
}

struct ProxiesView: View {
    @Environment(AppModel.self) private var model
    let searchText: String
    let onEdit: (LocalProxy) -> Void
    let onAdd: () -> Void

    private var proxies: [LocalProxy] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return model.state.proxies }
        return model.state.proxies.filter { proxy in
            let tunnelName = model.state.tunnel(id: proxy.tunnelId)?.name ?? ""
            return [
                proxy.name,
                proxy.kind.label,
                proxy.address,
                proxy.routingMode.label,
                tunnelName,
            ].contains { value in
                value.localizedCaseInsensitiveContains(query)
            }
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Theme.pageSpacing) {
                if proxies.isEmpty {
                    EmptyState(
                        symbol: searchText.isEmpty ? "arrow.triangle.branch" : "magnifyingglass",
                        title: searchText.isEmpty ? "Прокси пока нет" : "Ничего не найдено",
                        description: searchText.isEmpty
                            ? "Создайте SOCKS5 или HTTP-прокси и выберите туннель."
                            : "Попробуйте изменить поисковый запрос.",
                        actionTitle: searchText.isEmpty ? "Создать прокси" : nil,
                        action: searchText.isEmpty ? onAdd : nil
                    )
                } else {
                    SectionHeader(
                        title: "Локальные прокси",
                        subtitle: "Адрес, состояние и маршрутизация каждого порта"
                    )

                    VStack(spacing: 12) {
                        ForEach(proxies) { proxy in
                            RoutingProxyCard(proxy: proxy) {
                                onEdit(proxy)
                            }
                        }
                    }
                }
            }
            .frame(maxWidth: Theme.contentWidth)
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .background(.background)
    }
}

struct LogsView: View {
    @Environment(AppModel.self) private var model
    let searchText: String
    let onShowConfig: () -> Void

    private var entries: [LogEntry] {
        guard !searchText.isEmpty else { return model.logs }
        return model.logs.filter { $0.text.localizedCaseInsensitiveContains(searchText) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Button("Проверить", systemImage: "checkmark.shield") { model.validate() }
                Button("Конфиг", systemImage: "curlybraces") { onShowConfig() }
                Spacer()
                Button("Очистить", systemImage: "trash", role: .destructive) { model.clearLogs() }
            }

            LogView(entries: entries)
                .frame(maxHeight: .infinity)
        }
        .frame(maxWidth: Theme.contentWidth, maxHeight: .infinity, alignment: .top)
        .padding(28)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
        .background(.background)
    }
}

private struct DashboardVPNRoutePicker: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    let onAddTunnel: () -> Void
    let onOpenRoutes: () -> Void

    @State private var isHovering = false

    private var target: VPNRouteTarget? { model.state.systemVPN.target }

    private var route: VPNMainRoutePresentation {
        model.state.vpnMainRoutePresentation()
    }

    private var selectedTunnel: Tunnel? {
        guard target?.kind == .tunnel else { return nil }
        return model.state.tunnel(id: target?.referenceId)
    }

    private var fallbackGroup: VPNFallbackGroup? {
        guard target?.kind == .fallback else { return nil }
        return model.state.vpnFallbackGroup(id: target?.referenceId)
    }

    private var hasAvailableRoutes: Bool {
        !model.state.tunnels.isEmpty
            || model.state.vpnTunnelChains.contains { model.state.vpnTunnelChainIssue($0) == nil }
            || model.state.vpnFallbackGroups.contains { model.state.vpnFallbackGroupIssue($0) == nil }
    }

    var body: some View {
        HStack(spacing: 14) {
            SymbolTile(
                symbol: route.symbol,
                color: route.color,
                size: 42
            )

            VStack(alignment: .leading, spacing: 3) {
                Text("Основной маршрут VPN")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Text(route.name)
                    .font(.body.weight(.semibold))
                    .foregroundStyle(.primary)
                    .lineLimit(1)

                if let fallbackGroup {
                    VPNFallbackRuntimeLabel(
                        group: fallbackGroup,
                        idleText: routeDescription,
                        emphasized: model.isSystemVPNActive
                    )
                } else {
                    Text(routeDescription)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }

            Spacer(minLength: 12)

            if let selectedTunnel {
                if let latency = latencyText(for: selectedTunnel) {
                    Text(latency)
                        .font(.caption2.weight(.semibold).monospacedDigit())
                        .foregroundStyle(latencyColor(for: selectedTunnel))
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(latencyColor(for: selectedTunnel).opacity(0.10), in: Capsule())
                }

                Text(selectedTunnel.type.uppercased())
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 3)
                    .background(.quaternary, in: Capsule())
            } else if let target {
                Text(target.kind.routingTitle.uppercased())
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 7)
                    .padding(.vertical, 3)
                    .background(.quaternary, in: Capsule())
            }

            if !hasAvailableRoutes {
                Button("Добавить", systemImage: "plus", action: onAddTunnel)
                    .buttonStyle(.bordered)
                    .help("Добавить туннель для основного маршрута VPN")
            } else {
                Menu {
                    VPNMainRouteMenuItems()

                    Divider()
                    Button("Настроить VPN-маршруты", systemImage: "slider.horizontal.3") {
                        onOpenRoutes()
                    }
                } label: {
                    HStack(spacing: 6) {
                        Text("Выбрать")
                        Image(systemName: "chevron.up.chevron.down")
                            .font(.caption.weight(.semibold))
                    }
                }
                .menuStyle(.button)
                .menuIndicator(.hidden)
                .controlSize(.regular)
                .help("Выбрать основной маршрут системного VPN")
            }
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 13)
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(.rect(cornerRadius: Theme.corner))
        .background(
            isHovering ? Color.accentColor.opacity(0.055) : Theme.surface,
            in: .rect(cornerRadius: Theme.corner)
        )
        .overlay {
            RoundedRectangle(cornerRadius: Theme.corner, style: .continuous)
                .strokeBorder(
                    isHovering ? Color.accentColor.opacity(0.28) : Theme.separator.opacity(0.45),
                    lineWidth: 0.5
                )
        }
        .onHover { isHovering = $0 }
        .animation(reduceMotion ? nil : .easeOut(duration: 0.16), value: isHovering)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Основной маршрут системного VPN: \(route.name)")
    }

    private func latencyText(for tunnel: Tunnel) -> String? {
        guard let result = model.testResults[tunnel.id],
              result.ok,
              let milliseconds = result.latencyMs else { return nil }
        return "\(milliseconds) мс"
    }

    private func latencyColor(for tunnel: Tunnel) -> Color {
        guard let milliseconds = model.testResults[tunnel.id]?.latencyMs else { return .secondary }
        if milliseconds < 120 { return Theme.accentGreen }
        if milliseconds < 300 { return .orange }
        return .red
    }

    private var routeDescription: String {
        model.state.systemVPNMainRouteIssue() ?? "Трафик без совпавшей политики"
    }
}

private struct DashboardMetricButton: View {
    let title: String
    let value: String
    let detail: String
    let symbol: String
    let action: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var isHovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                SymbolTile(symbol: symbol, color: .accentColor, size: 36)
                VStack(alignment: .leading, spacing: 2) {
                    Text(value)
                        .font(.title2.weight(.semibold))
                        .lineLimit(1)
                    Text("\(title) · \(detail)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
                Image(systemName: "chevron.right")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.tertiary)
                    .offset(x: isHovering ? 2 : 0)
            }
            .padding(16)
            .background(
                isHovering ? Color.accentColor.opacity(0.08) : Theme.surface,
                in: .rect(cornerRadius: Theme.corner)
            )
            .overlay {
                RoundedRectangle(cornerRadius: Theme.corner, style: .continuous)
                    .strokeBorder(
                        isHovering ? Color.accentColor.opacity(0.28) : Theme.separator.opacity(0.45),
                        lineWidth: 0.5
                    )
            }
        }
        .buttonStyle(.plain)
        .onHover { isHovering = $0 }
        .animation(reduceMotion ? nil : .easeOut(duration: 0.16), value: isHovering)
        .accessibilityLabel("\(title): \(value), \(detail)")
        .accessibilityHint("Открыть раздел «\(title)»")
        .help("Открыть раздел «\(title)»")
    }
}

private struct DashboardProxyRow: View {
    @Environment(AppModel.self) private var model
    let proxy: LocalProxy

    var body: some View {
        HStack(spacing: 12) {
            SymbolTile(
                symbol: proxy.kind == .socks ? "network" : "globe",
                color: .indigo,
                size: 34
            )
            VStack(alignment: .leading, spacing: 3) {
                Text(proxy.name.isEmpty ? proxy.kind.label : proxy.name)
                    .fontWeight(.medium)
                Text(proxy.url)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button("Скопировать", systemImage: "doc.on.doc") {
                model.copyToClipboard(proxy.address)
            }
            .labelStyle(.iconOnly)
            .buttonStyle(.borderless)
            .help("Скопировать \(proxy.address)")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }
}

struct EmptyState: View {
    let symbol: String
    let title: String
    let description: String
    var actionTitle: String?
    var action: (() -> Void)?

    var body: some View {
        ContentUnavailableView {
            Label(title, systemImage: symbol)
        } description: {
            Text(description)
        } actions: {
            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .buttonStyle(.borderedProminent)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 320)
    }
}
