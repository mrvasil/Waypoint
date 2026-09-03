import SwiftUI
import WaypointCore

struct SettingsSheet: View {
    @Environment(AppModel.self) private var model
    @AppStorage(AppLanguage.storageKey) private var appLanguageValue = AppLanguage.system.rawValue

    @State private var xrayPath = ""
    @State private var logLevel = "warning"
    @State private var bypassTunnels = true
    @State private var bypassInterface = ""
    @State private var status: NetworkInterface.BypassStatus?

    private let levels = ["none", "error", "warning", "info", "debug"]

    var body: some View {
        SheetChrome(
            title: "Настройки",
            symbol: "gearshape.fill",
            subtitle: "Движок, журнал и сетевой обход",
            confirmTitle: "Сохранить",
            width: 590,
            onConfirm: save
        ) {
            VStack(spacing: 16) {
                FormGroup("Интерфейс приложения", symbol: "globe", color: .purple) {
                    LabeledField("Язык интерфейса") {
                        Picker("Язык интерфейса", selection: $appLanguageValue) {
                            ForEach(AppLanguage.allCases) { language in
                                Text(language.displayName).tag(language.rawValue)
                            }
                        }
                        .labelsHidden()
                        .frame(width: 180, alignment: .leading)
                    }

                    Text("Изменения применяются сразу ко всем окнам и меню.")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }

                FormGroup("Движок Xray", symbol: "terminal.fill", color: .blue) {
                    LabeledField("Путь к исполняемому файлу") {
                        TextField("/opt/homebrew/bin/xray", text: $xrayPath)
                            .textFieldStyle(.roundedBorder)
                    }

                    Label(
                        L10n.string(detectedXray),
                        systemImage: model.xrayPath == nil ? "exclamationmark.circle" : "checkmark.circle.fill"
                    )
                        .font(.caption)
                        .foregroundStyle(model.xrayPath == nil ? .orange : .secondary)
                        .textSelection(.enabled)

                    LabeledField("Уровень журнала") {
                        Picker("Уровень журнала", selection: $logLevel) {
                            ForEach(levels, id: \.self) { level in
                                Text(level.localizedCapitalized).tag(level)
                            }
                        }
                        .labelsHidden()
                        .frame(width: 180, alignment: .leading)
                    }
                }

                FormGroup("Обход системных VPN", symbol: "arrow.triangle.turn.up.right.diamond.fill", color: .cyan) {
                    Toggle("Направлять Xray через физический интерфейс", isOn: $bypassTunnels)

                    Text(L10n.string(bypassDescription))
                        .font(.caption)
                        .foregroundStyle(bypassWarning ? .orange : .secondary)
                        .fixedSize(horizontal: false, vertical: true)

                    LabeledField("Интерфейс") {
                        TextField("Автоматически", text: $bypassInterface)
                            .textFieldStyle(.roundedBorder)
                            .disabled(!bypassTunnels)
                    }

                    Text("Оставьте поле пустым для автоматического выбора Wi‑Fi или Ethernet.")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                }
            }
        }
        .onAppear(perform: load)
    }

    private var detectedXray: String {
        guard let path = model.xrayPath else {
            return L10n.string("Xray не найден — установите через brew install xray")
        }

        let conciseVersion = model.xrayVersion?
            .split(separator: " ")
            .prefix(2)
            .joined(separator: " ")

        if let conciseVersion, !conciseVersion.isEmpty {
            return "\(conciseVersion) · \(path)"
        }
        return path
    }

    private var bypassWarning: Bool {
        bypassTunnels && effectiveInterface == nil
    }

    private var effectiveInterface: String? {
        if !bypassInterface.isEmpty { return bypassInterface }
        return status?.physical
    }

    private var bypassDescription: String {
        guard bypassTunnels else {
            return L10n.string("Обход выключен — трафик следует системным маршрутам.")
        }
        guard let interface = effectiveInterface else {
            return L10n.string("Физический интерфейс не найден — обход не применится.")
        }
        guard let status else {
            return L10n.format("Выбран интерфейс %@.", interface)
        }

        let tunnelNames = status.tunnels.map(\.name).joined(separator: ", ")
        if status.tunnelCapturedRoute {
            return L10n.format(
                "Выбран %@. Системный маршрут перехвачен туннелем, обход активен.",
                interface
            )
        }
        return tunnelNames.isEmpty
            ? L10n.format("Выбран %@. Активных системных туннелей сейчас нет.", interface)
            : L10n.format("Выбран %@. Обнаружены: %@.", interface, tunnelNames)
    }

    private func load() {
        let settings = model.state.settings
        xrayPath = settings.xrayPath
        logLevel = settings.logLevel
        bypassTunnels = settings.bypassTunnels
        bypassInterface = settings.bypassInterface
        status = NetworkInterface.bypassStatus()
    }

    private func save() {
        model.updateSettings(Settings(
            xrayPath: xrayPath.trimmingCharacters(in: .whitespaces),
            logLevel: logLevel,
            bypassTunnels: bypassTunnels,
            bypassInterface: bypassInterface.trimmingCharacters(in: .whitespaces)
        ))
    }
}
