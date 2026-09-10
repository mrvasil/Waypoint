import Foundation

/// Стабильные назначения для быстрых кнопок Dashboard.
///
/// Имена пользовательских туннелей остаются данными, а специальные профили
/// разрешаются здесь в обычные `VPNRouteTarget`, поэтому генератор Xray и
/// профессиональная вкладка маршрутизации продолжают использовать один формат.
public enum VPNQuickRoutes {
    public static let whitelistFallbackID = "vf_waypoint_whitelist"
    public static let whitelistFallbackName = "Whitelist · Akenai LTE"

    public static func mrvasilTarget(in state: AppState) -> VPNRouteTarget? {
        state.vpnFallbackGroups
            .first {
                normalized($0.name) == "mrvasil vpn"
                    && state.vpnFallbackGroupIssue($0) == nil
            }
            .map { .fallback($0.id) }
    }

    public static func whitelistTunnelIDs(in state: AppState) -> [String] {
        let subscriptionIDs = Set(state.subscriptions.compactMap { subscription in
            normalized(subscription.name) == "akenai" ? subscription.id : nil
        })
        guard !subscriptionIDs.isEmpty else { return [] }

        return state.tunnels.compactMap { tunnel in
            guard tunnel.subscriptionId.map(subscriptionIDs.contains) == true,
                  normalized(tunnel.name).contains("[обход lte]") else { return nil }
            return tunnel.id
        }
    }

    /// Поддерживает управляемый fallback в соответствии с текущим содержимым
    /// подписки. При одном узле лишний balancer не создаётся; при полном
    /// исчезновении узлов выбранный профиль остаётся fail-closed.
    @discardableResult
    public static func synchronizeWhitelist(in state: inout AppState) -> VPNRouteTarget? {
        let tunnelIDs = whitelistTunnelIDs(in: state)
        let existingIndex = state.vpnFallbackGroups.firstIndex { $0.id == whitelistFallbackID }

        guard tunnelIDs.count >= 2 else {
            if let tunnelID = tunnelIDs.first {
                let target = VPNRouteTarget.tunnel(tunnelID)
                if state.systemVPN.target == .fallback(whitelistFallbackID) {
                    state.systemVPN.target = target
                }
                if let existingIndex {
                    state.vpnFallbackGroups.remove(at: existingIndex)
                }
                return target
            }

            // Не удаляем активный маршрут при временно пустой подписке: старая
            // runtime-конфигурация продолжит держать kill-switch и не станет Direct.
            if state.systemVPN.target != .fallback(whitelistFallbackID), let existingIndex {
                state.vpnFallbackGroups.remove(at: existingIndex)
            }
            return nil
        }

        let previous = existingIndex.map { state.vpnFallbackGroups[$0] }
        var previousMembers: [VPNRouteTarget: String] = [:]
        for member in previous?.members ?? [] where previousMembers[member.target] == nil {
            previousMembers[member.target] = member.id
        }
        let members = tunnelIDs.map { tunnelID in
            let target = VPNRouteTarget.tunnel(tunnelID)
            return VPNFallbackMember(id: previousMembers[target] ?? "fm_" + UUID().uuidString.prefix(8).lowercased(), target: target)
        }
        var group = previous ?? VPNFallbackGroup(
            id: whitelistFallbackID,
            name: whitelistFallbackName,
            members: members
        )
        group.name = whitelistFallbackName
        group.members = members
        group.enabled = true
        group.finalAction = .block
        if !(100...30_000).contains(group.maxLatencyMs) {
            group.maxLatencyMs = 1200
        }

        if let existingIndex {
            state.vpnFallbackGroups[existingIndex] = group
        } else {
            state.vpnFallbackGroups.append(group)
        }
        return .fallback(whitelistFallbackID)
    }

    private static func normalized(_ value: String) -> String {
        value.trimmingCharacters(in: .whitespacesAndNewlines)
            .folding(
                options: [.caseInsensitive, .diacriticInsensitive],
                locale: Locale(identifier: "en_US_POSIX")
            )
    }
}
