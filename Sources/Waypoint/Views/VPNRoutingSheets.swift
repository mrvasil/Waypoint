import SwiftUI
import WaypointCore

struct VPNRoutingPolicySheet: View {
    @Environment(AppModel.self) private var model
    let policy: VPNRoutingPolicy?

    @State private var name = ""
    @State private var targets = ""
    @State private var target = VPNRouteTarget.direct
    @State private var enabled = true
    @State private var didLoad = false

    private var parsedTargets: PersistentRouteTargets {
        PersistentRouteTargets.parse(targets)
    }

    private var cleanName: String {
        name.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var targetIssue: String? {
        model.state.vpnRouteTargetIssue(target)
    }

    private var canSave: Bool {
        !cleanName.isEmpty
            && !parsedTargets.isEmpty
            && parsedTargets.invalidLines.isEmpty
            && targetIssue == nil
    }

    var body: some View {
        SheetChrome(
            title: policy == nil ? "Новая политика" : "Изменить политику",
            symbol: "list.bullet.rectangle.portrait.fill",
            subtitle: "Первое совпавшее правило определяет маршрут",
            confirmTitle: policy == nil ? "Создать" : "Сохранить",
            confirmDisabled: !canSave,
            width: 650,
            onConfirm: save
        ) {
            VStack(spacing: 16) {
                FormGroup("Список трафика", symbol: "line.3.horizontal.decrease.circle.fill", color: .blue) {
                    LabeledField("Название") {
                        TextField("Например «Рабочие сервисы»", text: $name)
                            .textFieldStyle(.roundedBorder)
                    }

                    LabeledField("Домены, сети, GeoSite и GeoIP — по одному на строку") {
                        TextEditor(text: $targets)
                            .font(.body.monospaced())
                            .scrollContentBackground(.hidden)
                            .padding(8)
                            .frame(minHeight: 170)
                            .background(Theme.elevatedSurface, in: .rect(cornerRadius: Theme.compactCorner))
                            .overlay {
                                RoundedRectangle(cornerRadius: Theme.compactCorner, style: .continuous)
                                    .strokeBorder(Theme.separator.opacity(0.65), lineWidth: 0.5)
                            }
                    }

                    HStack(spacing: 12) {
                        Label(
                            L10n.format("%lld доменов", parsedTargets.domains.count),
                            systemImage: "globe"
                        )
                        Label(
                            L10n.format("%lld сетей", parsedTargets.ips.count),
                            systemImage: "network"
                        )
                        Spacer()
                        Text("Порядок строк внутри списка не меняет приоритет")
                            .foregroundStyle(.tertiary)
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)

                    if !parsedTargets.invalidLines.isEmpty {
                        Label(L10n.string(invalidTargetsDescription), systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }

                    Text("Поддерживаются example.com, domain:, full:, regexp:, IPv4/IPv6, CIDR, geosite: и geoip:. Строки с # — комментарии.")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                FormGroup("Назначение", symbol: "point.3.connected.trianglepath.dotted", color: .cyan) {
                    LabeledField("Куда отправлять совпавший трафик") {
                        VPNRouteTargetPicker(selection: $target)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }

                    HStack(spacing: 10) {
                        SymbolTile(
                            symbol: target.kind.routingSymbol,
                            color: targetIssue == nil ? target.kind.routingColor : .orange,
                            size: 32
                        )
                        VStack(alignment: .leading, spacing: 2) {
                            Text(model.state.vpnRouteTargetName(target))
                                .font(.callout.weight(.semibold))
                            Text(L10n.string(targetIssue ?? targetDescription))
                                .font(.caption)
                                .foregroundStyle(targetIssue == nil ? Color.secondary : Color.orange)
                        }
                        Spacer()
                    }
                    .padding(11)
                    .background(Theme.elevatedSurface, in: .rect(cornerRadius: Theme.compactCorner))

                    Divider()
                    Toggle("Политика включена", isOn: $enabled)
                }
            }
        }
        .onAppear(perform: load)
    }

    private var invalidTargetsDescription: String {
        let examples = parsedTargets.invalidLines.prefix(3).joined(separator: ", ")
        let suffix = parsedTargets.invalidLines.count > 3
            ? L10n.format(" и ещё %lld", parsedTargets.invalidLines.count - 3)
            : ""
        return L10n.format("Не удалось распознать: %@%@", examples, suffix)
    }

    private var targetDescription: String {
        switch target.kind {
        case .direct: "Обход всех туннелей"
        case .block: "Соединение будет отклонено"
        case .tunnel: "Один выходной туннель"
        case .chain: "Последовательный маршрут через несколько узлов"
        case .fallback: "Автоматический выбор доступного маршрута"
        }
    }

    private func load() {
        guard !didLoad else { return }
        didLoad = true
        if let policy {
            name = policy.name
            targets = policy.targets
            target = policy.target
            enabled = policy.enabled
        } else if let first = model.state.tunnels.first {
            target = .tunnel(first.id)
        }
    }

    private func save() {
        guard canSave else { return }
        if var policy {
            policy.name = cleanName
            policy.targets = targets
            policy.target = target
            policy.enabled = enabled
            model.updateVPNRoutingPolicy(policy)
        } else {
            model.addVPNRoutingPolicy(VPNRoutingPolicy(
                name: cleanName,
                targets: targets,
                target: target,
                enabled: enabled
            ))
        }
    }
}

struct VPNTunnelChainSheet: View {
    @Environment(AppModel.self) private var model
    let chain: VPNTunnelChain?

    @State private var name = ""
    @State private var tunnelIds: [String] = []
    @State private var enabled = true
    @State private var didLoad = false

    private var cleanName: String {
        name.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var validationIssue: String? {
        let candidate = VPNTunnelChain(
            id: chain?.id ?? "validation",
            name: cleanName,
            tunnelIds: tunnelIds,
            enabled: true
        )
        return model.state.vpnTunnelChainIssue(candidate)
    }

    private var canSave: Bool { !cleanName.isEmpty && validationIssue == nil }

    var body: some View {
        SheetChrome(
            title: chain == nil ? "Новая цепочка" : "Изменить цепочку",
            symbol: "link",
            subtitle: "Туннели идут от Mac к выходному узлу",
            confirmTitle: chain == nil ? "Создать" : "Сохранить",
            confirmDisabled: !canSave,
            width: 650,
            onConfirm: save
        ) {
            VStack(spacing: 16) {
                FormGroup("Цепочка", symbol: "link", color: .cyan) {
                    LabeledField("Название") {
                        TextField("Например «WG → VLESS Германия»", text: $name)
                            .textFieldStyle(.roundedBorder)
                    }

                    VStack(spacing: 8) {
                        ForEach(Array(tunnelIds.enumerated()), id: \.offset) { index, _ in
                            chainHopRow(index)
                        }
                    }

                    HStack {
                        Button("Добавить узел", systemImage: "plus") { addHop() }
                            .disabled(nextUnusedTunnelID == nil || tunnelIds.count >= 6)
                        Spacer()
                        Text("До 6 последовательных узлов")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }

                    if let validationIssue {
                        Label(L10n.string(validationIssue), systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }

                FormGroup("Как идёт трафик", symbol: "arrow.right", color: .blue) {
                    ScrollView(.horizontal) {
                        HStack(spacing: 8) {
                            pathToken("Mac", symbol: "desktopcomputer")
                            ForEach(Array(tunnelIds.enumerated()), id: \.offset) { index, id in
                                Image(systemName: "chevron.right")
                                    .font(.caption2.weight(.bold))
                                    .foregroundStyle(.tertiary)
                                pathToken(
                                    model.state.tunnel(id: id)?.name ?? "Недоступен",
                                    symbol: model.state.tunnel(id: id)?.routingSymbol ?? "exclamationmark.triangle.fill"
                                )
                            }
                            Image(systemName: "chevron.right")
                                .font(.caption2.weight(.bold))
                                .foregroundStyle(.tertiary)
                            pathToken("Интернет", symbol: "globe")
                        }
                    }
                    .scrollIndicators(.hidden)

                    Text("Последний узел становится выходом. Соединение каждого следующего туннеля устанавливается через предыдущий.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)

                    Divider()
                    Toggle("Цепочка включена", isOn: $enabled)
                }
            }
        }
        .onAppear(perform: load)
    }

    private func chainHopRow(_ index: Int) -> some View {
        HStack(spacing: 10) {
            Text("\(index + 1)")
                .font(.caption.monospacedDigit().weight(.bold))
                .foregroundStyle(.secondary)
                .frame(width: 24, height: 24)
                .background(.quaternary, in: Circle())

            Picker(L10n.format("Узел %lld", index + 1), selection: $tunnelIds[index]) {
                tunnelPickerOptions
            }
            .labelsHidden()
            .frame(maxWidth: .infinity)

            Button("Выше", systemImage: "chevron.up") { moveHop(index, by: -1) }
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
                .disabled(index == 0)
            Button("Ниже", systemImage: "chevron.down") { moveHop(index, by: 1) }
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
                .disabled(index == tunnelIds.count - 1)
            Button("Удалить", systemImage: "minus.circle") { tunnelIds.remove(at: index) }
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
                .foregroundStyle(.red)
        }
        .padding(10)
        .background(Theme.elevatedSurface, in: .rect(cornerRadius: Theme.compactCorner))
    }

    @ViewBuilder
    private var tunnelPickerOptions: some View {
        ForEach(model.state.subscriptions) { subscription in
            let tunnels = model.state.tunnels.filter { $0.subscriptionId == subscription.id }
            if !tunnels.isEmpty {
                Section(subscription.name) {
                    ForEach(tunnels) { tunnel in Text(tunnel.name).tag(tunnel.id) }
                }
            }
        }
        let manual = model.state.tunnels.filter { $0.subscriptionId == nil }
        if !manual.isEmpty {
            Section("Мои туннели") {
                ForEach(manual) { tunnel in Text(tunnel.name).tag(tunnel.id) }
            }
        }
    }

    private func pathToken(_ title: String, symbol: String) -> some View {
        Label(L10n.string(title), systemImage: symbol)
            .font(.caption.weight(.medium))
            .lineLimit(1)
            .padding(.horizontal, 9)
            .padding(.vertical, 6)
            .background(.quaternary, in: Capsule())
    }

    private var nextUnusedTunnelID: String? {
        model.state.tunnels.first { !tunnelIds.contains($0.id) }?.id
    }

    private func addHop() {
        guard let id = nextUnusedTunnelID else { return }
        tunnelIds.append(id)
    }

    private func moveHop(_ index: Int, by offset: Int) {
        let destination = index + offset
        guard tunnelIds.indices.contains(destination) else { return }
        tunnelIds.swapAt(index, destination)
    }

    private func load() {
        guard !didLoad else { return }
        didLoad = true
        if let chain {
            name = chain.name
            tunnelIds = chain.tunnelIds
            enabled = chain.enabled
        } else {
            tunnelIds = Array(model.state.tunnels.prefix(2).map(\.id))
        }
    }

    private func save() {
        guard canSave else { return }
        if var chain {
            chain.name = cleanName
            chain.tunnelIds = tunnelIds
            chain.enabled = enabled
            model.updateVPNTunnelChain(chain)
        } else {
            model.addVPNTunnelChain(VPNTunnelChain(
                name: cleanName,
                tunnelIds: tunnelIds,
                enabled: enabled
            ))
        }
    }
}

struct VPNFallbackGroupSheet: View {
    @Environment(AppModel.self) private var model
    let group: VPNFallbackGroup?

    @State private var name = ""
    @State private var members: [VPNFallbackMember] = []
    @State private var maxLatencyText = "1200"
    @State private var finalAction = VPNFallbackFinalAction.block
    @State private var enabled = true
    @State private var didLoad = false

    private var cleanName: String {
        name.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var maxLatency: Int? { Int(maxLatencyText) }

    private var validationIssue: String? {
        guard let maxLatency else { return "Введите порог задержки" }
        let candidate = VPNFallbackGroup(
            id: group?.id ?? "validation",
            name: cleanName,
            members: members,
            maxLatencyMs: maxLatency,
            finalAction: finalAction,
            enabled: true
        )
        return model.state.vpnFallbackGroupIssue(candidate)
    }

    private var canSave: Bool { !cleanName.isEmpty && validationIssue == nil }

    var body: some View {
        SheetChrome(
            title: group == nil ? "Новый fallback" : "Изменить fallback",
            symbol: "arrow.trianglehead.branch",
            subtitle: "Автоматическая замена медленного или недоступного маршрута",
            confirmTitle: group == nil ? "Создать" : "Сохранить",
            confirmDisabled: !canSave,
            width: 680,
            onConfirm: save
        ) {
            VStack(spacing: 16) {
                FormGroup("Предпочтительный порядок", symbol: "list.number", color: .orange) {
                    LabeledField("Название") {
                        TextField("Например «Основной + резерв»", text: $name)
                            .textFieldStyle(.roundedBorder)
                    }

                    VStack(spacing: 8) {
                        ForEach(Array(members.enumerated()), id: \.element.id) { index, _ in
                            fallbackMemberRow(index)
                        }
                    }

                    HStack {
                        Button("Добавить маршрут", systemImage: "plus") { addMember() }
                            .disabled(nextUnusedTarget == nil || members.count >= 6)
                        Spacer()
                        Text("Верхние маршруты получают более сильное предпочтение")
                            .font(.caption)
                            .foregroundStyle(.tertiary)
                    }

                    if let validationIssue {
                        Label(L10n.string(validationIssue), systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }
                }

                FormGroup("Контроль качества", symbol: "waveform.path.ecg", color: .blue) {
                    HStack(alignment: .bottom, spacing: 12) {
                        LabeledField("Максимальная задержка") {
                            HStack(spacing: 7) {
                                TextField("1200", text: $maxLatencyText)
                                    .textFieldStyle(.roundedBorder)
                                    .frame(width: 96)
                                Text("мс").foregroundStyle(.secondary)
                            }
                        }
                        LabeledField("Если все недоступны") {
                            Picker("Финальное действие", selection: $finalAction) {
                                ForEach(VPNFallbackFinalAction.allCases, id: \.self) { action in
                                    Label(action.routingTitle, systemImage: action.routingSymbol).tag(action)
                                }
                            }
                            .labelsHidden()
                        }
                    }

                    Label(
                        "Xray проверяет маршруты параллельно каждые 10 секунд и выбирает доступный вариант с учётом порядка и задержки. Это не жёсткая фиксация на первом маршруте: недоступные и слишком медленные варианты исключаются автоматически.",
                        systemImage: "info.circle"
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                    Divider()
                    Toggle("Fallback включён", isOn: $enabled)
                }
            }
        }
        .onAppear(perform: load)
    }

    private func fallbackMemberRow(_ index: Int) -> some View {
        HStack(spacing: 10) {
            Text("\(index + 1)")
                .font(.caption.monospacedDigit().weight(.bold))
                .foregroundStyle(index == 0 ? Color.white : Color.secondary)
                .frame(width: 24, height: 24)
                .background(index == 0 ? Color.accentColor : Color.secondary.opacity(0.12), in: Circle())

            VPNFallbackCandidatePicker(selection: Binding(
                get: { members[index].target },
                set: { members[index].target = $0 }
            ))
            .frame(maxWidth: .infinity)

            Button("Выше", systemImage: "chevron.up") { moveMember(index, by: -1) }
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
                .disabled(index == 0)
            Button("Ниже", systemImage: "chevron.down") { moveMember(index, by: 1) }
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
                .disabled(index == members.count - 1)
            Button("Удалить", systemImage: "minus.circle") { members.remove(at: index) }
                .labelStyle(.iconOnly)
                .buttonStyle(.borderless)
                .foregroundStyle(.red)
        }
        .padding(10)
        .background(Theme.elevatedSurface, in: .rect(cornerRadius: Theme.compactCorner))
    }

    private var candidateTargets: [VPNRouteTarget] {
        model.state.tunnels.map { .tunnel($0.id) }
            + model.state.vpnTunnelChains.map { .chain($0.id) }
    }

    private var nextUnusedTarget: VPNRouteTarget? {
        let used = Set(members.map(\.target))
        return candidateTargets.first { !used.contains($0) }
    }

    private func addMember() {
        guard let target = nextUnusedTarget else { return }
        members.append(VPNFallbackMember(target: target))
    }

    private func moveMember(_ index: Int, by offset: Int) {
        let destination = index + offset
        guard members.indices.contains(destination) else { return }
        members.swapAt(index, destination)
    }

    private func load() {
        guard !didLoad else { return }
        didLoad = true
        if let group {
            name = group.name
            members = group.members
            maxLatencyText = String(group.maxLatencyMs)
            finalAction = group.finalAction
            enabled = group.enabled
        } else {
            members = candidateTargets.prefix(2).map { VPNFallbackMember(target: $0) }
        }
    }

    private func save() {
        guard canSave, let maxLatency else { return }
        if var group {
            group.name = cleanName
            group.members = members
            group.maxLatencyMs = maxLatency
            group.finalAction = finalAction
            group.enabled = enabled
            model.updateVPNFallbackGroup(group)
        } else {
            model.addVPNFallbackGroup(VPNFallbackGroup(
                name: cleanName,
                members: members,
                maxLatencyMs: maxLatency,
                finalAction: finalAction,
                enabled: enabled
            ))
        }
    }
}
