import SwiftUI
import WaypointCore

/// Профессиональное управление системным VPN: базовый маршрут, first-match
/// политики, переиспользуемые цепочки и health-aware fallback-группы.
struct RoutingView: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var editor: VPNEditorDestination?

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: Theme.pageSpacing) {
                VPNStatusHero()
                VPNRoutingMetrics()

                SectionHeader(
                    title: "Основной маршрут",
                    subtitle: "Для трафика, который не совпал ни с одной политикой"
                )
                VPNPrimaryRouteCard()

                SectionHeader(
                    title: "Политики трафика",
                    subtitle: "Проверяются сверху вниз — срабатывает первое совпадение",
                    actionTitle: "Новая политика",
                    action: { editor = .newPolicy }
                )
                VPNPoliciesSection(onEdit: { editor = .editPolicy($0) }, onAdd: { editor = .newPolicy })

                SectionHeader(
                    title: "Маршруты",
                    subtitle: "Собирайте цепочки и автоматические резервные группы"
                )
                ViewThatFits(in: .horizontal) {
                    HStack(alignment: .top, spacing: 14) {
                        VPNChainsPanel(
                            onAdd: { editor = .newChain },
                            onEdit: { editor = .editChain($0) }
                        )
                        VPNFallbacksPanel(
                            onAdd: { editor = .newFallback },
                            onEdit: { editor = .editFallback($0) }
                        )
                    }
                    VStack(spacing: 14) {
                        VPNChainsPanel(
                            onAdd: { editor = .newChain },
                            onEdit: { editor = .editChain($0) }
                        )
                        VPNFallbacksPanel(
                            onAdd: { editor = .newFallback },
                            onEdit: { editor = .editFallback($0) }
                        )
                    }
                }
            }
            .frame(maxWidth: 980)
            .padding(28)
            .frame(maxWidth: .infinity, alignment: .top)
        }
        .background(.background)
        .sheet(item: $editor) { destination in
            editorSheet(destination)
        }
        .animation(reduceMotion ? nil : .snappy(duration: 0.24), value: editor)
    }

    @ViewBuilder
    private func editorSheet(_ destination: VPNEditorDestination) -> some View {
        switch destination {
        case .newPolicy:
            VPNRoutingPolicySheet(policy: nil)
        case .editPolicy(let policy):
            VPNRoutingPolicySheet(policy: policy)
        case .newChain:
            VPNTunnelChainSheet(chain: nil)
        case .editChain(let chain):
            VPNTunnelChainSheet(chain: chain)
        case .newFallback:
            VPNFallbackGroupSheet(group: nil)
        case .editFallback(let group):
            VPNFallbackGroupSheet(group: group)
        }
    }
}

private enum VPNEditorDestination: Identifiable, Equatable {
    case newPolicy
    case editPolicy(VPNRoutingPolicy)
    case newChain
    case editChain(VPNTunnelChain)
    case newFallback
    case editFallback(VPNFallbackGroup)

    var id: String {
        switch self {
        case .newPolicy: "new-policy"
        case .editPolicy(let policy): "policy-\(policy.id)"
        case .newChain: "new-chain"
        case .editChain(let chain): "chain-\(chain.id)"
        case .newFallback: "new-fallback"
        case .editFallback(let group): "fallback-\(group.id)"
        }
    }
}

private struct VPNStatusHero: View {
    @Environment(AppModel.self) private var model

    private var routeIssue: String? { model.state.systemVPNMainRouteIssue() }

    var body: some View {
        GroupCard {
            HStack(spacing: 16) {
                SymbolTile(
                    symbol: model.isSystemVPNReady ? "shield.fill" : "shield",
                    color: model.isSystemVPNActive ? .blue : .gray,
                    size: 48
                )

                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 8) {
                        Text("Системный VPN")
                            .font(.title3.weight(.semibold))
                        Text(L10n.string(statusLabel))
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(statusColor)
                            .padding(.horizontal, 7)
                            .padding(.vertical, 3)
                            .background(statusColor.opacity(0.11), in: Capsule())
                    }
                    Text(L10n.string(statusDescription))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }

                Spacer(minLength: 16)

                Button(
                    L10n.string(model.isSystemVPNActive ? "Отключить" : "Подключить"),
                    systemImage: model.isSystemVPNActive ? "stop.fill" : "power",
                    action: model.toggleSystemVPN
                )
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .tint(model.isSystemVPNActive ? .red : .blue)
                .disabled(
                    model.xrayPath == nil
                        || (!model.isSystemVPNActive && routeIssue != nil)
                )
            }
            .padding(20)
        }
    }

    private var statusLabel: String {
        guard model.isSystemVPNActive else { return "ВЫКЛЮЧЕН" }
        if model.status.vpnConfigurationState == .switching { return "ПЕРЕКЛЮЧЕНИЕ" }
        if model.status.vpnConfigurationState == .recovered { return "ВОССТАНОВЛЕН" }
        if model.status.vpnConfigurationState == .degraded { return "ПРОВЕРЬТЕ" }
        return model.isSystemVPNReady ? "ПОДКЛЮЧЕН" : "ПОДКЛЮЧЕНИЕ"
    }

    private var statusColor: Color {
        guard model.isSystemVPNActive else { return .secondary }
        if model.status.vpnConfigurationState == .recovered { return .orange }
        if model.status.vpnConfigurationState == .degraded { return .red }
        return model.isSystemVPNReady ? .green : .orange
    }

    private var statusDescription: String {
        if model.status.vpnConfigurationState == .switching {
            return "Применяем новые маршруты; текущий канал остаётся доступен"
        }
        if model.status.vpnConfigurationState == .recovered {
            return "Новые настройки отклонены, предыдущий рабочий маршрут восстановлен"
        }
        if model.status.vpnConfigurationState == .degraded {
            return "Конфигурация требует внимания; текущий runtime не остановлен принудительно"
        }
        if model.isSystemVPNReady {
            return L10n.format(
                "Весь трафик Mac обрабатывается через %@",
                model.status.vpnInterface ?? "utun"
            )
        }
        if model.isSystemVPNActive { return "Xray поднимает системный маршрут" }
        return "Политики, цепочки и fallback применяются в одном процессе Xray"
    }
}

private struct VPNRoutingMetrics: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        Card(padding: 0) {
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 0) { metrics }
                VStack(spacing: 0) { metrics }
            }
        }
    }

    @ViewBuilder
    private var metrics: some View {
        VPNMetric(
            value: "\(model.state.vpnRoutingPolicies.filter(\.enabled).count)",
            title: "активных политик",
            symbol: "list.bullet.rectangle",
            color: .blue
        )
        Divider().frame(maxHeight: 42).padding(.vertical, 10)
        VPNMetric(
            value: "\(model.state.vpnTunnelChains.filter(\.enabled).count)",
            title: "цепочек",
            symbol: "link",
            color: .cyan
        )
        Divider().frame(maxHeight: 42).padding(.vertical, 10)
        VPNMetric(
            value: "\(model.state.vpnFallbackGroups.filter(\.enabled).count)",
            title: "fallback-групп",
            symbol: "arrow.trianglehead.branch",
            color: .orange
        )
        Divider().frame(maxHeight: 42).padding(.vertical, 10)
        VPNMetric(
            value: model.state.vpnFallbackGroups.contains(where: \.enabled) ? "10 с" : "—",
            title: "интервал проверки",
            symbol: "waveform.path.ecg",
            color: .green
        )
    }
}

private struct VPNMetric: View {
    let value: String
    let title: String
    let symbol: String
    let color: Color

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: symbol)
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(color)
                .frame(width: 30, height: 30)
                .background(color.opacity(0.1), in: .rect(cornerRadius: 9))
            VStack(alignment: .leading, spacing: 1) {
                Text(value)
                    .font(.headline.monospacedDigit())
                Text(L10n.string(title))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 4)
        }
        .padding(.horizontal, 15)
        .padding(.vertical, 11)
        .frame(maxWidth: .infinity)
    }
}

private struct VPNPrimaryRouteCard: View {
    @Environment(AppModel.self) private var model

    private var route: VPNMainRoutePresentation { model.state.vpnMainRoutePresentation() }
    private var routeIssue: String? { model.state.systemVPNMainRouteIssue() }
    private var fallbackGroup: VPNFallbackGroup? {
        guard model.state.systemVPN.target?.kind == .fallback else { return nil }
        return model.state.vpnFallbackGroup(id: model.state.systemVPN.target?.referenceId)
    }

    var body: some View {
        Card {
            HStack(spacing: 14) {
                SymbolTile(
                    symbol: route.symbol,
                    color: route.color,
                    size: 42
                )

                VStack(alignment: .leading, spacing: 3) {
                    Text("Остальной трафик")
                        .font(.body.weight(.semibold))
                    if let routeIssue {
                        Text(L10n.string(routeIssue))
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .lineLimit(1)
                    } else if let fallbackGroup {
                        VPNFallbackRuntimeLabel(
                            group: fallbackGroup,
                            idleText: route.detail,
                            emphasized: model.isSystemVPNActive
                        )
                    } else {
                        Text(L10n.string(route.detail))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }

                Spacer(minLength: 16)

                VPNMainRoutePicker(selection: routeBinding)
                    .controlSize(.regular)
                    .frame(maxWidth: 420)
                    .accessibilityLabel("Основной маршрут системного VPN")
            }
            .padding(2)
        }
    }

    private var routeBinding: Binding<VPNRouteTarget?> {
        Binding(
            get: { model.state.systemVPN.target },
            set: { target in
                if let target { model.setSystemVPNMainRoute(target) }
            }
        )
    }
}

private struct VPNPoliciesSection: View {
    @Environment(AppModel.self) private var model
    let onEdit: (VPNRoutingPolicy) -> Void
    let onAdd: () -> Void

    var body: some View {
        if model.state.vpnRoutingPolicies.isEmpty {
            Card {
                HStack(spacing: 15) {
                    SymbolTile(symbol: "list.bullet.rectangle", color: .blue, size: 40)
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Пока действует только основной маршрут")
                            .font(.headline)
                        Text("Создайте список доменов, подсетей, GeoSite или GeoIP и назначьте ему отдельный маршрут.")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer(minLength: 12)
                    Button("Создать", systemImage: "plus", action: onAdd)
                        .buttonStyle(.borderedProminent)
                }
            }
        } else {
            VStack(spacing: 10) {
                ForEach(Array(model.state.vpnRoutingPolicies.enumerated()), id: \.element.id) { index, policy in
                    VPNPolicyRow(
                        policy: policy,
                        priority: index + 1,
                        canMoveUp: index > 0,
                        canMoveDown: index < model.state.vpnRoutingPolicies.count - 1,
                        onEdit: { onEdit(policy) }
                    )
                }
            }
        }
    }
}

private struct VPNPolicyRow: View {
    @Environment(AppModel.self) private var model
    let policy: VPNRoutingPolicy
    let priority: Int
    let canMoveUp: Bool
    let canMoveDown: Bool
    let onEdit: () -> Void

    private var parsed: PersistentRouteTargets { PersistentRouteTargets.parse(policy.targets) }
    private var issue: String? {
        if parsed.isEmpty { return "Список пуст" }
        if !parsed.invalidLines.isEmpty { return "Есть нераспознанные строки" }
        return model.state.vpnRouteTargetIssue(policy.target)
    }

    var body: some View {
        GroupCard {
            HStack(spacing: 14) {
                Text("\(priority)")
                    .font(.callout.monospacedDigit().weight(.bold))
                    .foregroundStyle(priority == 1 ? Color.white : Color.secondary)
                    .frame(width: 30, height: 30)
                    .background(priority == 1 ? Color.accentColor : Color.secondary.opacity(0.12), in: Circle())

                SymbolTile(
                    symbol: policy.target.kind.routingSymbol,
                    color: issue == nil ? policy.target.kind.routingColor : .orange,
                    size: 38
                )

                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 7) {
                        Text(policy.name)
                            .font(.body.weight(.semibold))
                            .lineLimit(1)
                        if let issue {
                            Label(L10n.string(issue), systemImage: "exclamationmark.triangle.fill")
                                .font(.caption2.weight(.semibold))
                                .foregroundStyle(.orange)
                                .lineLimit(1)
                        }
                    }
                    HStack(spacing: 9) {
                        Label("\(parsed.domains.count)", systemImage: "globe")
                        Label("\(parsed.ips.count)", systemImage: "network")
                        Text("→").foregroundStyle(.tertiary)
                        Label(
                            model.state.vpnRouteTargetName(policy.target),
                            systemImage: policy.target.kind.routingSymbol
                        )
                        .foregroundStyle(issue == nil ? Color.secondary : Color.orange)
                        .lineLimit(1)
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }

                Spacer(minLength: 12)

                Toggle("Включить политику", isOn: Binding(
                    get: { policy.enabled },
                    set: { _ in model.toggleVPNRoutingPolicy(policy.id) }
                ))
                .toggleStyle(.switch)
                .labelsHidden()

                Menu {
                    Button("Изменить", systemImage: "pencil", action: onEdit)
                    Divider()
                    Button("Поднять приоритет", systemImage: "chevron.up") {
                        model.moveVPNRoutingPolicy(policy.id, offset: -1)
                    }
                    .disabled(!canMoveUp)
                    Button("Опустить приоритет", systemImage: "chevron.down") {
                        model.moveVPNRoutingPolicy(policy.id, offset: 1)
                    }
                    .disabled(!canMoveDown)
                    Divider()
                    Button("Удалить", systemImage: "trash", role: .destructive) {
                        model.removeVPNRoutingPolicy(policy.id)
                    }
                } label: {
                    Image(systemName: "ellipsis.circle").foregroundStyle(.secondary)
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .fixedSize()
            }
            .padding(15)
            .opacity(policy.enabled ? 1 : 0.62)
        }
        .contextMenu {
            Button("Изменить", action: onEdit)
            Button("Поднять", systemImage: "chevron.up") {
                model.moveVPNRoutingPolicy(policy.id, offset: -1)
            }
            .disabled(!canMoveUp)
            Button("Опустить", systemImage: "chevron.down") {
                model.moveVPNRoutingPolicy(policy.id, offset: 1)
            }
            .disabled(!canMoveDown)
        }
    }
}

private struct VPNChainsPanel: View {
    @Environment(AppModel.self) private var model
    let onAdd: () -> Void
    let onEdit: (VPNTunnelChain) -> Void

    var body: some View {
        GroupCard {
            VStack(spacing: 0) {
                topologyHeader(
                    title: "Цепочки",
                    subtitle: "Несколько туннелей подряд",
                    symbol: "link",
                    color: .cyan,
                    count: model.state.vpnTunnelChains.count,
                    action: onAdd
                )
                .padding(15)

                Divider()

                if model.state.vpnTunnelChains.isEmpty {
                    topologyEmpty(
                        title: "Нет цепочек",
                        description: "Например, WireGuard → VLESS",
                        action: onAdd
                    )
                } else {
                    VStack(spacing: 0) {
                        ForEach(Array(model.state.vpnTunnelChains.enumerated()), id: \.element.id) { index, chain in
                            VPNChainRow(chain: chain) { onEdit(chain) }
                            if index < model.state.vpnTunnelChains.count - 1 { Divider().padding(.leading, 50) }
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity)
    }
}

private struct VPNFallbacksPanel: View {
    @Environment(AppModel.self) private var model
    let onAdd: () -> Void
    let onEdit: (VPNFallbackGroup) -> Void

    var body: some View {
        GroupCard {
            VStack(spacing: 0) {
                topologyHeader(
                    title: "Fallback",
                    subtitle: "Замена медленных маршрутов",
                    symbol: "arrow.trianglehead.branch",
                    color: .orange,
                    count: model.state.vpnFallbackGroups.count,
                    action: onAdd
                )
                .padding(15)

                Divider()

                if model.state.vpnFallbackGroups.isEmpty {
                    topologyEmpty(
                        title: "Нет fallback-групп",
                        description: "Добавьте основной и резервные маршруты",
                        action: onAdd
                    )
                } else {
                    VStack(spacing: 0) {
                        ForEach(Array(model.state.vpnFallbackGroups.enumerated()), id: \.element.id) { index, group in
                            VPNFallbackRow(group: group) { onEdit(group) }
                            if index < model.state.vpnFallbackGroups.count - 1 { Divider().padding(.leading, 50) }
                        }
                    }
                }
            }
        }
        .frame(maxWidth: .infinity)
    }
}

@MainActor
private func topologyHeader(
    title: String,
    subtitle: String,
    symbol: String,
    color: Color,
    count: Int,
    action: @escaping () -> Void
) -> some View {
    HStack(spacing: 11) {
        SymbolTile(symbol: symbol, color: color, size: 34)
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 7) {
                Text(L10n.string(title)).font(.headline)
                Text("\(count)")
                    .font(.caption2.monospacedDigit().weight(.bold))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(.quaternary, in: Capsule())
            }
            Text(L10n.string(subtitle)).font(.caption).foregroundStyle(.secondary)
        }
        Spacer()
        Button("Добавить", systemImage: "plus", action: action)
            .labelStyle(.iconOnly)
            .buttonStyle(.borderless)
            .help("Добавить")
    }
}

@MainActor
private func topologyEmpty(title: String, description: String, action: @escaping () -> Void) -> some View {
    VStack(spacing: 7) {
        Text(L10n.string(title)).font(.callout.weight(.medium))
        Text(L10n.string(description))
            .font(.caption)
            .foregroundStyle(.secondary)
            .multilineTextAlignment(.center)
        Button("Создать", action: action)
            .controlSize(.small)
    }
    .frame(maxWidth: .infinity, minHeight: 106)
    .padding(14)
}

private struct VPNChainRow: View {
    @Environment(AppModel.self) private var model
    let chain: VPNTunnelChain
    let onEdit: () -> Void

    private var structuralIssue: String? {
        var candidate = chain
        candidate.enabled = true
        return model.state.vpnTunnelChainIssue(candidate)
    }

    private var path: String {
        chain.tunnelIds.map { model.state.tunnel(id: $0)?.name ?? "Недоступен" }
            .joined(separator: " → ")
    }

    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: structuralIssue == nil ? "link" : "exclamationmark.triangle.fill")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(structuralIssue == nil ? Color.cyan : Color.orange)
                .frame(width: 32, height: 32)
                .background((structuralIssue == nil ? Color.cyan : Color.orange).opacity(0.1), in: .rect(cornerRadius: 9))

            VStack(alignment: .leading, spacing: 3) {
                Text(chain.name).font(.callout.weight(.semibold)).lineLimit(1)
                Text(structuralIssue.map { L10n.string($0) } ?? path)
                    .font(.caption)
                    .foregroundStyle(structuralIssue == nil ? Color.secondary : Color.orange)
                    .lineLimit(1)
            }
            Spacer(minLength: 8)
            Text(L10n.format("%lld hop", chain.tunnelIds.count))
                .font(.caption2.monospacedDigit().weight(.semibold))
                .foregroundStyle(.secondary)
            Toggle("Включить цепочку", isOn: Binding(
                get: { chain.enabled },
                set: { _ in model.toggleVPNTunnelChain(chain.id) }
            ))
            .toggleStyle(.switch)
            .labelsHidden()
            .controlSize(.small)
            Menu {
                Button("Изменить", systemImage: "pencil", action: onEdit)
                Divider()
                Button("Удалить", systemImage: "trash", role: .destructive) {
                    model.removeVPNTunnelChain(chain.id)
                }
            } label: { Image(systemName: "ellipsis.circle").foregroundStyle(.secondary) }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
        }
        .padding(13)
        .opacity(chain.enabled ? 1 : 0.62)
    }
}

private struct VPNFallbackRow: View {
    @Environment(AppModel.self) private var model
    let group: VPNFallbackGroup
    let onEdit: () -> Void

    private var structuralIssue: String? {
        var candidate = group
        candidate.enabled = true
        return model.state.vpnFallbackGroupIssue(candidate)
    }

    private var path: String {
        group.members.prefix(3).map { model.state.vpnFallbackCandidateName($0.target) }
            .joined(separator: " → ")
    }

    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: structuralIssue == nil ? "arrow.trianglehead.branch" : "exclamationmark.triangle.fill")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(structuralIssue == nil ? Color.orange : Color.red)
                .frame(width: 32, height: 32)
                .background((structuralIssue == nil ? Color.orange : Color.red).opacity(0.1), in: .rect(cornerRadius: 9))

            VStack(alignment: .leading, spacing: 3) {
                Text(group.name).font(.callout.weight(.semibold)).lineLimit(1)
                if let structuralIssue {
                    Text(L10n.string(structuralIssue))
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .lineLimit(1)
                } else {
                    VPNFallbackRuntimeLabel(group: group, idleText: path)
                }
            }
            Spacer(minLength: 8)
            Text(L10n.format("≤ %lld мс", group.maxLatencyMs))
                .font(.caption2.monospacedDigit().weight(.semibold))
                .foregroundStyle(.secondary)
            Toggle("Включить fallback", isOn: Binding(
                get: { group.enabled },
                set: { _ in model.toggleVPNFallbackGroup(group.id) }
            ))
            .toggleStyle(.switch)
            .labelsHidden()
            .controlSize(.small)
            Menu {
                Button("Изменить", systemImage: "pencil", action: onEdit)
                Divider()
                Button("Удалить", systemImage: "trash", role: .destructive) {
                    model.removeVPNFallbackGroup(group.id)
                }
            } label: { Image(systemName: "ellipsis.circle").foregroundStyle(.secondary) }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
        }
        .padding(13)
        .opacity(group.enabled ? 1 : 0.62)
    }
}

struct RoutingProxyCard: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    let proxy: LocalProxy
    let onEdit: () -> Void

    private var tunnel: Tunnel? { model.state.tunnel(id: proxy.tunnelId) }
    private var needsTunnel: Bool { proxy.routingMode != .directAll }

    var body: some View {
        GroupCard {
            VStack(spacing: 0) {
                header
                    .padding(16)

                Divider()

                VStack(alignment: .leading, spacing: 14) {
                    Picker("Профиль маршрутизации", selection: routingModeBinding) {
                        ForEach(LocalProxy.RoutingMode.allCases, id: \.self) { mode in
                            Text(mode.shortLabel).tag(mode)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()

                    if needsTunnel {
                        tunnelSelection
                            .transition(.opacity.combined(with: .move(edge: .top)))
                    }

                    routePreview
                }
                .padding(16)
                .animation(reduceMotion ? nil : .snappy(duration: 0.24), value: proxy.routingMode)
            }
        }
    }

    private var header: some View {
        HStack(spacing: 13) {
            SymbolTile(
                symbol: proxy.kind == .socks ? "network" : "globe",
                color: proxy.enabled ? .indigo : .gray,
                size: 38
            )

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 7) {
                    Text(proxy.name.isEmpty ? proxy.kind.label : proxy.name)
                        .font(.body.weight(.semibold))
                        .lineLimit(1)
                    Text(L10n.string(proxy.enabled ? "АКТИВЕН" : "ВЫКЛЮЧЕН"))
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(proxy.enabled ? .green : .secondary)
                }
                Button(proxy.url) {
                    model.copyToClipboard(proxy.address)
                }
                .font(.caption.monospaced())
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
                .help("Скопировать адрес прокси")
            }

            Spacer(minLength: 12)

            Toggle("Включить прокси", isOn: Binding(
                get: { proxy.enabled },
                set: { _ in model.toggleProxy(proxy.id) }
            ))
            .toggleStyle(.switch)
            .labelsHidden()
            .help(L10n.string(proxy.enabled ? "Выключить прокси" : "Включить прокси"))

            Menu {
                Button("Изменить", systemImage: "pencil", action: onEdit)
                Button("Скопировать адрес", systemImage: "doc.on.doc") {
                    model.copyToClipboard(proxy.address)
                }
                Divider()
                Button("Удалить", systemImage: "trash", role: .destructive) {
                    model.removeProxy(proxy.id)
                }
            } label: {
                Image(systemName: "ellipsis.circle")
                    .foregroundStyle(.secondary)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
            .help("Действия с прокси")
        }
    }

    @ViewBuilder
    private var tunnelSelection: some View {
        if model.state.tunnels.isEmpty {
            Label("Сначала добавьте туннель", systemImage: "exclamationmark.triangle.fill")
                .font(.callout)
                .foregroundStyle(.orange)
        } else {
            HStack(spacing: 12) {
                Label("Основной туннель", systemImage: "point.3.connected.trianglepath.dotted")
                    .font(.callout.weight(.medium))
                Spacer()
                Picker("Основной туннель", selection: tunnelBinding) {
                    tunnelPickerOptions
                }
                .labelsHidden()
                .frame(maxWidth: 360)
            }

            if tunnel == nil {
                Label("Туннель не выбран — трафик временно пойдёт напрямую", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption)
                    .foregroundStyle(.orange)
            }
        }
    }

    private var routePreview: some View {
        VStack(spacing: 0) {
            switch proxy.routingMode {
            case .tunnelAll:
                RoutingFlowRow(
                    title: "Весь трафик",
                    detail: "Любые сайты и IP",
                    sourceSymbol: "arrow.triangle.branch",
                    destination: tunnel?.name ?? "Напрямую",
                    destinationSymbol: tunnel == nil ? "arrow.up.right" : "shield.lefthalf.filled",
                    destinationColor: tunnel == nil ? .green : .blue
                )
            case .directRussia:
                RoutingFlowRow(
                    title: "Россия",
                    detail: "geoip:ru + geosite:category-ru",
                    sourceSymbol: "globe.europe.africa.fill",
                    destination: "Напрямую",
                    destinationSymbol: "arrow.up.right",
                    destinationColor: .green
                )
                Divider().padding(.leading, 44)
                RoutingFlowRow(
                    title: "Остальной трафик",
                    detail: "Правило по умолчанию",
                    sourceSymbol: "globe",
                    destination: tunnel?.name ?? "Напрямую",
                    destinationSymbol: tunnel == nil ? "arrow.up.right" : "shield.lefthalf.filled",
                    destinationColor: tunnel == nil ? .green : .blue
                )
            case .directAll:
                RoutingFlowRow(
                    title: "Весь трафик",
                    detail: "Туннели не используются",
                    sourceSymbol: "arrow.triangle.branch",
                    destination: "Напрямую",
                    destinationSymbol: "arrow.up.right",
                    destinationColor: .green
                )
            }
        }
        .background(Theme.elevatedSurface, in: .rect(cornerRadius: Theme.compactCorner))
        .overlay {
            RoundedRectangle(cornerRadius: Theme.compactCorner, style: .continuous)
                .strokeBorder(Theme.separator.opacity(0.5), lineWidth: 0.5)
        }
    }

    private var routingModeBinding: Binding<LocalProxy.RoutingMode> {
        Binding(
            get: { proxy.routingMode },
            set: { model.setProxyRoutingMode(proxy.id, mode: $0) }
        )
    }

    private var tunnelBinding: Binding<String> {
        Binding(
            get: { tunnel?.id ?? model.state.tunnels.first?.id ?? "" },
            set: { model.setProxyTunnel(proxy.id, tunnelID: $0) }
        )
    }

    @ViewBuilder
    private var tunnelPickerOptions: some View {
        ForEach(model.state.subscriptions) { subscription in
            let tunnels = model.state.tunnels.filter { $0.subscriptionId == subscription.id }
            if !tunnels.isEmpty {
                Section(subscription.name) {
                    ForEach(tunnels) { tunnel in
                        Text(tunnel.name).tag(tunnel.id)
                    }
                }
            }
        }

        let manual = model.state.tunnels.filter { $0.subscriptionId == nil }
        if !manual.isEmpty {
            Section("Мои туннели") {
                ForEach(manual) { tunnel in
                    Text(tunnel.name).tag(tunnel.id)
                }
            }
        }
    }
}

private struct RoutingFlowRow: View {
    let title: String
    let detail: String
    let sourceSymbol: String
    let destination: String
    let destinationSymbol: String
    let destinationColor: Color

    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: sourceSymbol)
                .font(.system(size: 14, weight: .medium))
                .foregroundStyle(.secondary)
                .frame(width: 22)

            VStack(alignment: .leading, spacing: 2) {
                Text(L10n.string(title))
                    .font(.callout.weight(.medium))
                Text(L10n.string(detail))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer(minLength: 12)

            Image(systemName: "arrow.right")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.tertiary)

            Label(L10n.string(destination), systemImage: destinationSymbol)
                .font(.callout.weight(.medium))
                .foregroundStyle(destinationColor)
                .lineLimit(1)
                .frame(maxWidth: 230, alignment: .trailing)
        }
        .padding(.horizontal, 13)
        .padding(.vertical, 11)
    }
}

private extension LocalProxy.RoutingMode {
    var shortLabel: String {
        switch self {
        case .tunnelAll: L10n.string("В туннель")
        case .directRussia: L10n.string("RU напрямую")
        case .directAll: L10n.string("Напрямую")
        }
    }
}
