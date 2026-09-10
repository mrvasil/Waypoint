import SwiftUI
import WaypointCore

struct SheetChrome<Content: View>: View {
    let title: String
    let symbol: String
    var subtitle: String?
    var confirmTitle: String = "Готово"
    var confirmDisabled: Bool = false
    var width: CGFloat = 560
    let onConfirm: () -> Void
    @ViewBuilder let content: Content

    @Environment(\.dismiss) private var dismiss

    init(
        title: String,
        symbol: String,
        subtitle: String? = nil,
        confirmTitle: String = "Готово",
        confirmDisabled: Bool = false,
        width: CGFloat = 560,
        onConfirm: @escaping () -> Void,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.symbol = symbol
        self.subtitle = subtitle
        self.confirmTitle = confirmTitle
        self.confirmDisabled = confirmDisabled
        self.width = width
        self.onConfirm = onConfirm
        self.content = content()
    }

    var body: some View {
        VStack(spacing: 0) {
            SheetTitle(title: title, subtitle: subtitle, symbol: symbol)
                .padding(.horizontal, 22)
                .padding(.vertical, 18)

            Divider()

            ScrollView {
                content
                    .padding(22)
                    .frame(maxWidth: .infinity, alignment: .topLeading)
            }

            Divider()

            HStack(spacing: 10) {
                Spacer()
                Button("Отмена") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button(L10n.string(confirmTitle)) {
                    onConfirm()
                    dismiss()
                }
                .buttonStyle(.borderedProminent)
                .disabled(confirmDisabled)
                .keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, 22)
            .padding(.vertical, 14)
        }
        .frame(width: width)
        .frame(minHeight: 360, maxHeight: 680)
    }
}

struct SheetTitle: View {
    let title: String
    let subtitle: String?
    let symbol: String

    init(title: String, subtitle: String? = nil, symbol: String) {
        self.title = title
        self.subtitle = subtitle
        self.symbol = symbol
    }

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: symbol)
                .font(.system(size: 18, weight: .semibold))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(.tint)
                .frame(width: 34, height: 34)
                .background(.tint.opacity(0.12), in: .rect(cornerRadius: 10))

            VStack(alignment: .leading, spacing: 2) {
                Text(L10n.string(title)).font(.headline)
                if let subtitle {
                    Text(L10n.string(subtitle))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer()
        }
    }
}

struct FormGroup<Content: View>: View {
    let title: String
    let symbol: String
    let color: Color
    @ViewBuilder let content: Content

    init(
        _ title: String,
        symbol: String,
        color: Color,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.symbol = symbol
        self.color = color
        self.content = content()
    }

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 9) {
                    SymbolTile(symbol: symbol, color: color, size: 28)
                    Text(L10n.string(title)).font(.headline)
                }
                Divider()
                content
            }
        }
    }
}

struct AddTunnelSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss

    private enum Mode: String, CaseIterable {
        case links = "Ссылки / WireGuard"
        case subscription = "Подписка (URL)"
    }

    @State private var mode: Mode = .links
    @State private var text = ""
    @State private var subscriptionName = ""
    @State private var subscriptionURL = ""
    @State private var preview: ParseResult?
    @State private var loading = false

    var body: some View {
        VStack(spacing: 0) {
            SheetTitle(
                title: "Добавить туннель",
                subtitle: "Ссылка, WireGuard-конфиг или подписка",
                symbol: "point.3.connected.trianglepath.dotted"
            )
            .padding(.horizontal, 22)
            .padding(.vertical, 18)

            Divider()

            VStack(alignment: .leading, spacing: 18) {
                Picker("Способ добавления", selection: $mode) {
                    ForEach(Mode.allCases, id: \.self) {
                        Text(L10n.string($0.rawValue)).tag($0)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()

                switch mode {
                case .links: linksEditor
                case .subscription: subscriptionEditor
                }

                if let preview { previewView(preview) }

                Spacer(minLength: 0)
            }
            .padding(22)

            Divider()

            HStack(spacing: 10) {
                Spacer()
                Button("Отмена") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Добавить") { add() }
                    .buttonStyle(.borderedProminent)
                    .disabled(!canAdd || loading)
                    .keyboardShortcut(.defaultAction)
            }
            .padding(.horizontal, 22)
            .padding(.vertical, 14)
        }
        .frame(width: 590, height: 520)
    }

    private var linksEditor: some View {
        VStack(alignment: .leading, spacing: 9) {
            Label("Данные подключения", systemImage: "link")
                .font(.headline)
            Text("Можно вставить несколько ссылок, полный WireGuard-конфиг или base64-блок.")
                .font(.caption)
                .foregroundStyle(.secondary)

            TextEditor(text: $text)
                .font(.caption.monospaced())
                .scrollContentBackground(.hidden)
                .padding(10)
                .frame(height: 170)
                .background(Theme.elevatedSurface, in: .rect(cornerRadius: Theme.compactCorner))
                .overlay {
                    RoundedRectangle(cornerRadius: Theme.compactCorner, style: .continuous)
                        .strokeBorder(Theme.separator.opacity(0.6), lineWidth: 0.5)
                }
                .onChange(of: text) { preview = nil }

            Button("Проверить содержимое", systemImage: "eye") {
                preview = Parsers.parseBulk(text)
            }
            .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
    }

    private var subscriptionEditor: some View {
        FormGroup("Подписка", symbol: "rectangle.stack.badge.plus", color: .blue) {
            Text("Узлы будут собраны в отдельную группу и автоматически обновляться каждые 15 минут.")
                .font(.caption)
                .foregroundStyle(.secondary)
            LabeledField("Название") {
                TextField("Например «Основная»", text: $subscriptionName)
                    .textFieldStyle(.roundedBorder)
            }
            LabeledField("URL") {
                TextField("https://example.com/sub", text: $subscriptionURL)
                    .textFieldStyle(.roundedBorder)
            }
            if loading {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Загрузка…").font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    private func previewView(_ result: ParseResult) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(
                L10n.format("Распознано: %lld", result.tunnels.count),
                systemImage: "checkmark.circle"
            )
                .font(.headline)

            GroupCard {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(result.tunnels) { tunnel in
                        Label {
                            Text(tunnel.name).lineLimit(1)
                        } icon: {
                            Text(tunnel.type.uppercased())
                                .font(.caption2.weight(.bold))
                                .foregroundStyle(.secondary)
                        }
                    }
                    ForEach(result.errors) { error in
                        Label(
                            L10n.format("%@ — %@", error.line, L10n.string(error.message)),
                            systemImage: "exclamationmark.triangle.fill"
                        )
                            .foregroundStyle(.orange)
                            .lineLimit(1)
                    }
                }
                .font(.caption)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private var canAdd: Bool {
        switch mode {
        case .links: !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        case .subscription:
            !subscriptionName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                && !subscriptionURL.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
    }

    private func add() {
        switch mode {
        case .links:
            let result = Parsers.parseBulk(text)
            guard !result.tunnels.isEmpty else {
                preview = result
                return
            }
            model.addTunnels(result.tunnels)
            dismiss()
        case .subscription:
            loading = true
            Task {
                let added = await model.addSubscription(
                    name: subscriptionName,
                    url: subscriptionURL
                )
                loading = false
                if added { dismiss() }
            }
        }
    }
}

struct ProxySheet: View {
    @Environment(AppModel.self) private var model
    let proxy: LocalProxy?

    @State private var name = ""
    @State private var kind: LocalProxy.Kind = .socks
    @State private var listen = "127.0.0.1"
    @State private var portText = ""
    @State private var target: VPNRouteTarget?
    @State private var routingMode: LocalProxy.RoutingMode = .tunnelAll
    @State private var useAuth = false
    @State private var user = ""
    @State private var pass = ""

    private var isEditing: Bool { proxy != nil }
    private var routeIssue: String? {
        guard routingMode != .directAll else { return nil }
        guard let target else { return "Маршрут прокси не выбран" }
        guard target.kind == .tunnel || target.kind == .chain || target.kind == .fallback else {
            return "Прокси поддерживает туннели, цепочки и fallback"
        }
        return model.state.vpnRouteTargetIssue(target)
    }

    var body: some View {
        SheetChrome(
            title: isEditing ? "Изменить прокси" : "Новый прокси",
            symbol: "arrow.triangle.branch",
            subtitle: "Локальный адрес для приложений",
            confirmTitle: isEditing ? "Сохранить" : "Создать",
            confirmDisabled: Int(portText) == nil || routeIssue != nil,
            onConfirm: save
        ) {
            VStack(spacing: 16) {
                FormGroup("Основное", symbol: "slider.horizontal.3", color: .indigo) {
                    LabeledField("Название") {
                        TextField("Например «Германия»", text: $name)
                            .textFieldStyle(.roundedBorder)
                    }
                    LabeledField("Тип") {
                        Picker("Тип", selection: $kind) {
                            ForEach(LocalProxy.Kind.allCases, id: \.self) {
                                Text(L10n.string($0.label)).tag($0)
                            }
                        }
                        .pickerStyle(.segmented)
                        .labelsHidden()
                    }
                }

                FormGroup("Маршрутизация", symbol: "arrow.triangle.turn.up.right.diamond", color: .blue) {
                    HStack(alignment: .bottom, spacing: 12) {
                        LabeledField("Адрес") {
                            Picker("Адрес", selection: $listen) {
                                Text("127.0.0.1 — только этот Mac").tag("127.0.0.1")
                                Text("0.0.0.0 — локальная сеть").tag("0.0.0.0")
                            }
                            .labelsHidden()
                        }
                        LabeledField("Порт") {
                            TextField("10808", text: $portText)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 92)
                        }
                    }
                    LabeledField("Профиль") {
                        Picker("Профиль маршрутизации", selection: $routingMode) {
                            ForEach(LocalProxy.RoutingMode.allCases, id: \.self) { mode in
                                Text(L10n.string(mode.label)).tag(mode)
                            }
                        }
                        .pickerStyle(.menu)
                        .labelsHidden()
                    }

                    if routingMode != .directAll {
                        LabeledField("Выходной маршрут") {
                            ProxyRouteTargetPicker(selection: $target)
                        }
                        if let routeIssue {
                            Label(L10n.string(routeIssue), systemImage: "exclamationmark.triangle.fill")
                                .font(.caption)
                                .foregroundStyle(.orange)
                        }
                    }

                    Label(
                        L10n.string(routingDescription),
                        systemImage: routingMode == .directRussia ? "globe.europe.africa.fill" : "arrow.triangle.branch"
                    )
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                FormGroup("Авторизация", symbol: "key.fill", color: .orange) {
                    Toggle("Требовать логин и пароль", isOn: $useAuth)
                    if useAuth {
                        HStack(spacing: 12) {
                            TextField("Логин", text: $user)
                                .textFieldStyle(.roundedBorder)
                            SecureField("Пароль", text: $pass)
                                .textFieldStyle(.roundedBorder)
                        }
                    }
                }
            }
        }
        .onAppear(perform: load)
        .onChange(of: routingMode) {
            if routingMode != .directAll, routeIssue != nil {
                target = model.state.firstAvailableLocalProxyTarget()
            }
        }
    }

    private func load() {
        if let proxy {
            name = proxy.name
            kind = proxy.kind
            listen = proxy.listen
            portText = String(proxy.port)
            target = proxy.target
            routingMode = proxy.routingMode
            if let auth = proxy.auth, !auth.user.isEmpty {
                useAuth = true
                user = auth.user
                pass = auth.pass
            }
        } else {
            portText = String(model.suggestedPort())
            target = model.state.firstAvailableLocalProxyTarget()
            routingMode = target == nil ? .directAll : .tunnelAll
        }
    }

    private func save() {
        guard let port = Int(portText) else { return }
        let auth = useAuth && !user.isEmpty ? ProxyAuth(user: user, pass: pass) : nil

        if var existing = proxy {
            existing.name = name
            existing.kind = kind
            existing.listen = listen
            existing.port = port
            existing.target = target
            existing.routingMode = routingMode
            existing.auth = auth
            model.updateProxy(existing)
        } else {
            model.addProxy(LocalProxy(
                name: name.isEmpty ? kind.label : name,
                kind: kind,
                listen: listen,
                port: port,
                target: target,
                routingMode: routingMode,
                auth: auth
            ))
        }
    }

    private var routingDescription: String {
        switch routingMode {
        case .tunnelAll:
            "Любой трафик этого локального прокси отправляется в выбранный маршрут."
        case .directRussia:
            "geoip:ru и geosite:category-ru идут напрямую, остальной трафик — в выбранный маршрут."
        case .directAll:
            "Любой трафик идёт напрямую; выбранный маршрут не используется."
        }
    }
}

struct LabeledField<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(L10n.string(title))
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

struct ConfigSheet: View {
    @Environment(\.dismiss) private var dismiss
    let text: String

    var body: some View {
        VStack(spacing: 0) {
            SheetTitle(title: "Конфигурация Xray", subtitle: "Итоговый JSON", symbol: "curlybraces")
                .padding(.horizontal, 22)
                .padding(.vertical, 18)
            Divider()
            ScrollView {
                Text(L10n.string(text))
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(16)
            }
            .background(Theme.elevatedSurface)
            Divider()
            HStack(spacing: 10) {
                Spacer()
                Button("Закрыть") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Копировать", systemImage: "doc.on.doc") { Pasteboard.copy(text) }
                    .buttonStyle(.borderedProminent)
            }
            .padding(.horizontal, 22)
            .padding(.vertical, 14)
        }
        .frame(width: 680, height: 600)
    }
}
