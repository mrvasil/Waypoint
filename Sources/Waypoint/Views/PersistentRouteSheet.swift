import SwiftUI
import WaypointCore

struct PersistentRouteSheet: View {
    @Environment(AppModel.self) private var model
    let route: PersistentRoute?

    @State private var name = ""
    @State private var targets = ""
    @State private var tunnelID = ""
    @State private var appliesToSystemVPN = true
    @State private var appliesToLocalProxies = true
    @State private var enabled = true
    @State private var didLoad = false

    private var parsedTargets: PersistentRouteTargets {
        PersistentRouteTargets.parse(targets)
    }

    private var cleanName: String {
        name.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var canSave: Bool {
        !cleanName.isEmpty
            && !parsedTargets.isEmpty
            && parsedTargets.invalidLines.isEmpty
            && model.state.tunnel(id: tunnelID) != nil
            && (appliesToSystemVPN || appliesToLocalProxies)
    }

    var body: some View {
        SheetChrome(
            title: route == nil ? "Новый постоянный маршрут" : "Изменить маршрут",
            symbol: "pin.fill",
            subtitle: "Приоритетнее профилей VPN и локальных прокси",
            confirmTitle: route == nil ? "Добавить" : "Сохранить",
            confirmDisabled: !canSave,
            width: 620,
            onConfirm: save
        ) {
            VStack(spacing: 16) {
                FormGroup("Назначение", symbol: "list.bullet.rectangle", color: .blue) {
                    LabeledField("Название") {
                        TextField("Например «Рабочие сервисы»", text: $name)
                            .textFieldStyle(.roundedBorder)
                    }

                    LabeledField("IP, подсети и домены — по одному на строку") {
                        TextEditor(text: $targets)
                            .font(.body.monospaced())
                            .scrollContentBackground(.hidden)
                            .padding(8)
                            .frame(minHeight: 150)
                            .background(Theme.elevatedSurface, in: .rect(cornerRadius: Theme.compactCorner))
                            .overlay {
                                RoundedRectangle(cornerRadius: Theme.compactCorner, style: .continuous)
                                    .strokeBorder(Theme.separator.opacity(0.65), lineWidth: 0.5)
                            }
                    }

                    HStack(spacing: 8) {
                        Label("\(parsedTargets.count) целей", systemImage: "checkmark.circle")
                            .foregroundStyle(parsedTargets.isEmpty ? Color.secondary : Color.green)
                        Text("•")
                            .foregroundStyle(.tertiary)
                        Text("example.com включает все поддомены")
                            .foregroundStyle(.secondary)
                    }
                    .font(.caption)

                    if !parsedTargets.invalidLines.isEmpty {
                        Label(
                            invalidTargetsDescription,
                            systemImage: "exclamationmark.triangle.fill"
                        )
                        .font(.caption)
                        .foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                    }

                    Text("Поддерживаются IPv4, IPv6, CIDR, domain:, full:, regexp:, geosite: и geoip:. Строки с # считаются комментариями.")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                FormGroup("Маршрут", symbol: "point.3.connected.trianglepath.dotted", color: .indigo) {
                    LabeledField("Всегда через туннель") {
                        if model.state.tunnels.isEmpty {
                            Label("Сначала добавьте туннель", systemImage: "exclamationmark.triangle.fill")
                                .foregroundStyle(.orange)
                        } else {
                            Picker("Туннель", selection: $tunnelID) {
                                tunnelPickerOptions
                            }
                            .labelsHidden()
                            .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }

                    VStack(alignment: .leading, spacing: 10) {
                        Text("Применять к")
                            .font(.caption.weight(.medium))
                            .foregroundStyle(.secondary)
                        HStack(spacing: 14) {
                            Toggle("Системный VPN", isOn: $appliesToSystemVPN)
                            Toggle("Локальные прокси", isOn: $appliesToLocalProxies)
                        }
                    }

                    if !appliesToSystemVPN && !appliesToLocalProxies {
                        Label("Выберите VPN, прокси или оба варианта", systemImage: "exclamationmark.triangle.fill")
                            .font(.caption)
                            .foregroundStyle(.orange)
                    }

                    Divider()
                    Toggle("Маршрут включён", isOn: $enabled)
                }
            }
        }
        .onAppear(perform: load)
    }

    private var invalidTargetsDescription: String {
        let examples = parsedTargets.invalidLines.prefix(3).joined(separator: ", ")
        let suffix = parsedTargets.invalidLines.count > 3 ? " и ещё \(parsedTargets.invalidLines.count - 3)" : ""
        return "Не удалось распознать: \(examples)\(suffix)"
    }

    @ViewBuilder
    private var tunnelPickerOptions: some View {
        if !tunnelID.isEmpty, model.state.tunnel(id: tunnelID) == nil {
            Text("Недоступный туннель").tag(tunnelID)
        }

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

    private func load() {
        guard !didLoad else { return }
        didLoad = true
        if let route {
            name = route.name
            targets = route.targets
            tunnelID = route.tunnelId
            appliesToSystemVPN = route.appliesToSystemVPN
            appliesToLocalProxies = route.appliesToLocalProxies
            enabled = route.enabled
        } else {
            tunnelID = model.state.tunnels.first?.id ?? ""
        }
    }

    private func save() {
        guard canSave else { return }
        if var route {
            route.name = cleanName
            route.targets = targets
            route.tunnelId = tunnelID
            route.appliesToSystemVPN = appliesToSystemVPN
            route.appliesToLocalProxies = appliesToLocalProxies
            route.enabled = enabled
            model.updatePersistentRoute(route)
        } else {
            model.addPersistentRoute(PersistentRoute(
                name: cleanName,
                targets: targets,
                tunnelId: tunnelID,
                appliesToSystemVPN: appliesToSystemVPN,
                appliesToLocalProxies: appliesToLocalProxies,
                enabled: enabled
            ))
        }
    }
}
