import SwiftUI
import WaypointCore

struct TunnelRow: View {
    @Environment(AppModel.self) private var model
    let tunnel: Tunnel

    private var testing: Bool { model.testingTunnelIds.contains(tunnel.id) }
    private var result: TunnelTestResult? { model.testResults[tunnel.id] }

    var body: some View {
        HStack(spacing: 14) {
            SystemVPNTunnelButton(
                tunnelName: tunnel.name,
                symbol: tunnelSymbol,
                color: tunnelColor,
                isSelected: model.state.systemVPNMainTunnelID() == tunnel.id
            ) {
                model.setSystemVPNMainRoute(.tunnel(tunnel.id))
            }

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 7) {
                    Text(tunnel.name)
                        .font(.body.weight(.medium))
                        .lineLimit(1)
                    Text(tunnel.type.uppercased())
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(.quaternary, in: Capsule())
                }

                Text(tunnel.port > 0 ? "\(tunnel.host):\(tunnel.port)" : tunnel.host)
                    .font(.caption.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            Spacer(minLength: 12)

            Button {
                model.testTunnel(tunnel)
            } label: {
                HStack(spacing: 5) {
                    if testing {
                        ProgressView()
                            .controlSize(.mini)
                    } else {
                        Image(systemName: "gauge.with.dots.needle.33percent")
                            .font(.caption2.weight(.semibold))
                    }
                    Text(latencyText)
                        .monospacedDigit()
                }
                .font(.caption.weight(.semibold))
                .foregroundStyle(latencyColor)
                .frame(minWidth: 68)
                .padding(.horizontal, 9)
                .padding(.vertical, 5)
                .background(latencyColor.opacity(0.1), in: Capsule())
                .overlay {
                    Capsule().strokeBorder(latencyColor.opacity(0.16), lineWidth: 0.5)
                }
            }
            .buttonStyle(.plain)
            .disabled(testing)
            .help(L10n.string(latencyHelp))
            .accessibilityLabel(L10n.format("Задержка через %@: %@", tunnel.name, latencyText))

            Menu {
                Button("Скопировать адрес", systemImage: "doc.on.doc") {
                    model.copyToClipboard("\(tunnel.host):\(tunnel.port)")
                }
                if tunnel.subscriptionId == nil {
                    Divider()
                    Button("Удалить", systemImage: "trash", role: .destructive) {
                        model.removeTunnel(tunnel.id)
                    }
                }
            } label: {
                Image(systemName: "ellipsis.circle")
                    .foregroundStyle(.secondary)
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .fixedSize()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 13)
        .contextMenu {
            Button("Измерить задержку через туннель") {
                model.testTunnel(tunnel)
            }
            Divider()
            Button("Скопировать адрес") {
                model.copyToClipboard("\(tunnel.host):\(tunnel.port)")
            }
            if tunnel.subscriptionId == nil {
                Button("Удалить", role: .destructive) { model.removeTunnel(tunnel.id) }
            }
        }
    }

    private var tunnelSymbol: String {
        switch tunnel.type.lowercased() {
        case "wireguard": "shield.lefthalf.filled"
        case "vless", "vmess": "point.3.connected.trianglepath.dotted"
        case "trojan": "bolt.shield.fill"
        case "shadowsocks", "ss": "lock.shield.fill"
        case "socks", "http": "network"
        default: "link"
        }
    }

    private var tunnelColor: Color {
        switch tunnel.type.lowercased() {
        case "wireguard": .blue
        case "vless", "vmess": .cyan
        case "trojan": .purple
        case "shadowsocks", "ss": .indigo
        case "socks", "http": .orange
        default: .gray
        }
    }

    private var latencyText: String {
        if testing { return "…" }
        guard let result else { return L10n.string("Пинг") }
        guard result.ok, let milliseconds = result.latencyMs else { return L10n.string("Нет связи") }
        return L10n.format("%lld мс", milliseconds)
    }

    private var latencyColor: Color {
        guard let result else { return .secondary }
        guard result.ok, let milliseconds = result.latencyMs else { return .orange }
        if milliseconds < 120 { return Theme.accentGreen }
        if milliseconds < 300 { return .orange }
        return .red
    }

    private var latencyHelp: String {
        if testing { return "Измеряется реальным HTTP-запросом через туннель" }
        guard let result else {
            return model.isRunning
                ? "Остановите VPN или прокси, чтобы измерить задержку без второго Xray"
                : "Измерить задержку реальным запросом через туннель"
        }
        if result.ok {
            let exit = [result.ip, result.loc].compactMap { $0 }.joined(separator: " · ")
            return exit.isEmpty
                ? "Реальный HTTP-запрос прошёл через туннель"
                : L10n.format("Выход через %@", exit)
        }
        return result.error.map { L10n.string($0) } ?? L10n.string("Туннель не ответил")
    }
}

private struct SystemVPNTunnelButton: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var isHovering = false

    let tunnelName: String
    let symbol: String
    let color: Color
    let isSelected: Bool
    let action: () -> Void

    var body: some View {
        Button {
            if !isSelected { action() }
        } label: {
            ZStack(alignment: .bottomTrailing) {
                SymbolTile(symbol: symbol, color: color, size: 38)
                    .padding(3)
                    .background(
                        Color.accentColor.opacity(backgroundOpacity),
                        in: .rect(cornerRadius: 11)
                    )
                    .overlay {
                        RoundedRectangle(cornerRadius: 11, style: .continuous)
                            .strokeBorder(outlineColor, lineWidth: isSelected ? 2 : 1)
                    }

                if isSelected {
                    Image(systemName: "checkmark")
                        .font(.system(size: 7, weight: .bold))
                        .symbolRenderingMode(.monochrome)
                        .foregroundStyle(.white)
                        .frame(width: 15, height: 15)
                        .background(Color.accentColor, in: Circle())
                        .overlay {
                            Circle().strokeBorder(Theme.surface, lineWidth: 2)
                        }
                        .offset(x: 2, y: 2)
                        .transition(.scale.combined(with: .opacity))
                }
            }
            .frame(width: 44, height: 44)
            .scaleEffect(isHovering && !isSelected ? 1.025 : 1)
            .contentShape(.rect(cornerRadius: 11))
        }
        .buttonStyle(.plain)
        .onHover { isHovering = $0 }
        .animation(reduceMotion ? nil : .snappy(duration: 0.22), value: isSelected)
        .animation(reduceMotion ? nil : .easeOut(duration: 0.14), value: isHovering)
        .help(
            isSelected
                ? "Используется системным VPN"
                : L10n.format("Использовать «%@» для системного VPN", tunnelName)
        )
        .accessibilityLabel(L10n.format("Туннель системного VPN: %@", tunnelName))
        .accessibilityValue(L10n.string(isSelected ? "Выбран" : "Не выбран"))
        .accessibilityHint(
            isSelected
                ? "Сейчас используется системным VPN"
                : "Нажмите, чтобы назначить этот туннель системному VPN"
        )
    }

    private var outlineColor: Color {
        if isSelected { return .accentColor }
        return isHovering ? Color.accentColor.opacity(0.35) : .clear
    }

    private var backgroundOpacity: Double {
        if isSelected { return 0.12 }
        return isHovering ? 0.05 : 0
    }
}

struct LogView: View {
    let entries: [LogEntry]

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 4) {
                    if entries.isEmpty {
                        ContentUnavailableView(
                            "Журнал пуст",
                            systemImage: "text.alignleft",
                            description: Text("События появятся после запуска или проверки конфигурации.")
                        )
                        .frame(maxWidth: .infinity, minHeight: 280)
                    }

                    ForEach(entries) { entry in
                        Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 12) {
                            GridRow {
                                Text(entry.timestamp)
                                    .foregroundStyle(.tertiary)
                                Text(entry.text)
                                    .textSelection(.enabled)
                                    .gridColumnAlignment(.leading)
                            }
                        }
                        .font(.caption.monospaced())
                        .id(entry.id)
                    }
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .background(Theme.elevatedSurface, in: .rect(cornerRadius: Theme.corner))
            .overlay {
                RoundedRectangle(cornerRadius: Theme.corner, style: .continuous)
                    .strokeBorder(Theme.separator.opacity(0.55), lineWidth: 0.5)
            }
            .onChange(of: entries.count) {
                if let last = entries.last {
                    withAnimation(.easeOut(duration: 0.15)) {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
            }
        }
    }
}
