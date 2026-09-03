import SwiftUI

struct ToolbarConnectionControls: ToolbarContent {
    @Environment(AppModel.self) private var model

    private var enabledProxyCount: Int {
        model.state.proxies.filter(\.enabled).count
    }

    @ToolbarContentBuilder
    var body: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            ToolbarConnectionButton(
                title: "Прокси",
                symbol: "point.3.connected.trianglepath.dotted",
                state: proxyState,
                actionTitle: model.localProxyRequested ? "Отключить локальный прокси" : "Включить локальный прокси",
                disabled: model.xrayPath == nil
                    || enabledProxyCount == 0
                    || (model.isSystemVPNActive && !model.isSystemVPNReady),
                action: model.toggleLocalProxy
            )

            ToolbarConnectionButton(
                title: "VPN",
                symbol: model.isSystemVPNActive ? "shield.fill" : "shield",
                state: vpnState,
                actionTitle: model.isSystemVPNActive ? "Отключить системный VPN" : "Включить системный VPN",
                disabled: model.xrayPath == nil
                    || (!model.isSystemVPNActive && model.state.systemVPNMainRouteIssue() != nil),
                action: model.toggleSystemVPN
            )
        }
    }

    private var proxyState: ToolbarConnectionButton.State {
        if model.isLocalProxyActive { return .active }
        return model.isLocalProxyConnecting ? .connecting : .inactive
    }

    private var vpnState: ToolbarConnectionButton.State {
        guard model.isSystemVPNActive else { return .inactive }
        return model.isSystemVPNReady ? .active : .connecting
    }
}

private struct ToolbarConnectionButton: View {
    enum State: Equatable {
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

        var accessibilityLabel: String {
            switch self {
            case .inactive: "выключен"
            case .connecting: "подключается"
            case .active: "включен"
            }
        }
    }

    let title: String
    let symbol: String
    let state: State
    let actionTitle: String
    let disabled: Bool
    let action: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(state.color)
                .frame(width: 18, height: 18)
                .symbolEffect(
                    .pulse,
                    options: .repeating,
                    isActive: state == .connecting && !reduceMotion
                )
        }
        .disabled(disabled)
        .help("\(actionTitle) · сейчас \(state.accessibilityLabel)")
        .accessibilityLabel("\(title), \(state.accessibilityLabel)")
        .accessibilityHint(actionTitle)
    }
}

struct DashboardConnectionControl: View {
    enum Kind: Equatable {
        case proxy
        case vpn
    }

    enum ControlState: Equatable {
        case inactive
        case connecting
        case active

        var label: String {
            switch self {
            case .inactive: "ВЫКЛЮЧЕН"
            case .connecting: "ПОДКЛЮЧЕНИЕ"
            case .active: "ВКЛЮЧЕН"
            }
        }

        var color: Color {
            switch self {
            case .inactive: .secondary
            case .connecting: .orange
            case .active: .green
            }
        }

        var isActive: Bool { self != .inactive }
    }

    let title: String
    let detail: String
    let actionTitle: String
    let symbol: String
    let kind: Kind
    let state: ControlState
    let disabled: Bool
    let action: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var isHovering = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 18) {
                controlSymbol

                VStack(alignment: .leading, spacing: 7) {
                    Text(title)
                        .font(.headline)
                        .foregroundStyle(.primary)
                        .lineLimit(1)

                    Text(state.label)
                        .font(.caption2.weight(.bold))
                        .foregroundStyle(state.color)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(state.color.opacity(0.10), in: Capsule())

                    Text(detail)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .frame(maxWidth: .infinity, alignment: .leading)

                    HStack(spacing: 6) {
                        Text(actionTitle)
                            .font(.callout.weight(.semibold))
                        Image(systemName: state.isActive ? "power" : "arrow.right")
                            .font(.caption.weight(.bold))
                            .offset(x: isHovering && !state.isActive ? 2 : 0)
                    }
                    .foregroundStyle(state.isActive ? state.color : Color.accentColor)
                }
            }
            .padding(20)
            .frame(maxWidth: .infinity, minHeight: 150, alignment: .leading)
            .contentShape(.rect(cornerRadius: 22))
            .background(cardBackground, in: .rect(cornerRadius: 22))
            .overlay {
                RoundedRectangle(cornerRadius: 22, style: .continuous)
                    .strokeBorder(cardBorder, lineWidth: state.isActive ? 1 : 0.5)
            }
            .shadow(
                color: state.isActive ? state.color.opacity(0.08) : .clear,
                radius: 12,
                y: 5
            )
        }
        .buttonStyle(DashboardControlButtonStyle(isHovering: isHovering, reduceMotion: reduceMotion))
        .disabled(disabled)
        .opacity(disabled ? 0.58 : 1)
        .onHover { isHovering = $0 }
        .animation(reduceMotion ? nil : .snappy(duration: 0.24), value: state)
        .animation(reduceMotion ? nil : .easeOut(duration: 0.16), value: isHovering)
        .accessibilityLabel("\(title), \(state.label.lowercased()), \(detail)")
        .accessibilityHint(actionTitle)
        .help("\(actionTitle) · \(title)")
    }

    private var controlSymbol: some View {
        ZStack {
            Circle()
                .fill(state.color.opacity(state.isActive ? 0.14 : 0.07))

            Circle()
                .strokeBorder(
                    state.color.opacity(state.isActive ? 0.34 : 0.16),
                    lineWidth: state.isActive ? 1.5 : 1
                )

            if state.isActive {
                Circle()
                    .strokeBorder(state.color.opacity(0.10), lineWidth: 7)
                    .scaleEffect(isHovering ? 1.10 : 1.04)
            }

            Image(systemName: symbol)
                .font(.system(size: 35, weight: .medium))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(state.isActive ? state.color : .secondary)
                .symbolEffect(.pulse, options: .repeating, isActive: state == .connecting && !reduceMotion)
                .contentTransition(.symbolEffect(.replace))

            if kind == .vpn {
                Image(systemName: state.isActive ? "shield.fill" : "shield")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(state.isActive ? state.color : .secondary)
                    .padding(4)
                    .background(Theme.surface, in: Circle())
                    .offset(x: 27, y: 25)
                    .contentTransition(.symbolEffect(.replace))
            }
        }
        .frame(width: 86, height: 86)
        .scaleEffect(state.isActive ? 1 : 0.96)
        .accessibilityHidden(true)
    }

    private var cardBackground: some ShapeStyle {
        if state.isActive {
            return AnyShapeStyle(state.color.opacity(isHovering ? 0.085 : 0.055))
        }
        return AnyShapeStyle(isHovering ? Color.accentColor.opacity(0.055) : Theme.surface)
    }

    private var cardBorder: Color {
        if state.isActive {
            return state.color.opacity(isHovering ? 0.36 : 0.24)
        }
        return isHovering ? Color.accentColor.opacity(0.28) : Theme.separator.opacity(0.45)
    }
}

private struct DashboardControlButtonStyle: ButtonStyle {
    let isHovering: Bool
    let reduceMotion: Bool

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? 0.975 : (isHovering ? 1.008 : 1))
            .animation(
                reduceMotion ? nil : .snappy(duration: 0.18),
                value: configuration.isPressed
            )
    }
}
