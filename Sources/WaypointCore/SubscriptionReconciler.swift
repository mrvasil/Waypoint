import Foundation

/// Обновляет узлы одной подписки, не затрагивая ручные туннели и другие
/// подписки. Совпадение определяется по параметрам подключения, а не по имени.
public enum SubscriptionReconciler {
    public struct Result: Equatable, Sendable {
        public var tunnelIDs: [String]
        public var removedTunnelIDs: [String]

        public init(tunnelIDs: [String], removedTunnelIDs: [String]) {
            self.tunnelIDs = tunnelIDs
            self.removedTunnelIDs = removedTunnelIDs
        }
    }

    @discardableResult
    public static func refresh(
        subscriptionID: String,
        incoming: [Tunnel],
        updatedAt: Date = Date(),
        state: inout AppState
    ) -> Result {
        let previous = state.tunnels.filter { $0.subscriptionId == subscriptionID }
        var reusableIDs: [String: [String]] = [:]
        for tunnel in previous {
            reusableIDs[fingerprint(of: tunnel), default: []].append(tunnel.id)
        }

        let refreshed = incoming.map { tunnel in
            var tunnel = tunnel
            let key = fingerprint(of: tunnel)
            if var ids = reusableIDs[key], !ids.isEmpty {
                tunnel.id = ids.removeFirst()
                reusableIDs[key] = ids
            }
            tunnel.subscriptionId = subscriptionID
            return tunnel
        }

        let retained = state.tunnels.filter { $0.subscriptionId != subscriptionID }
        state.tunnels = retained + refreshed
        if let index = state.subscriptions.firstIndex(where: { $0.id == subscriptionID }) {
            state.subscriptions[index].lastUpdatedAt = updatedAt
        }

        let liveIDs = Set(refreshed.map(\.id))
        let removedIDs = previous.map(\.id).filter { !liveIDs.contains($0) }
        let removedIDSet = Set(removedIDs)
        for index in state.proxies.indices where state.proxies[index].tunnelId.map(removedIDSet.contains) == true {
            state.proxies[index].tunnelId = nil
        }
        if state.systemVPN.target?.kind == .tunnel,
           state.systemVPN.target?.referenceId.map(removedIDSet.contains) == true {
            state.systemVPN.target = state.tunnels.first.map { .tunnel($0.id) }
        }
        return Result(tunnelIDs: refreshed.map(\.id), removedTunnelIDs: removedIDs)
    }

    /// Удаляет подписку вместе с принадлежащими ей узлами. Прокси, которые
    /// использовали эти узлы, безопасно переключаются на прямой маршрут.
    @discardableResult
    public static func remove(subscriptionID: String, state: inout AppState) -> [String] {
        let removedIDs = state.tunnels
            .filter { $0.subscriptionId == subscriptionID }
            .map(\.id)
        let removedIDSet = Set(removedIDs)

        state.subscriptions.removeAll { $0.id == subscriptionID }
        state.tunnels.removeAll { $0.subscriptionId == subscriptionID }
        for index in state.proxies.indices where state.proxies[index].tunnelId.map(removedIDSet.contains) == true {
            state.proxies[index].tunnelId = nil
        }
        if state.systemVPN.target?.kind == .tunnel,
           state.systemVPN.target?.referenceId.map(removedIDSet.contains) == true {
            state.systemVPN.target = state.tunnels.first.map { .tunnel($0.id) }
        }
        return removedIDs
    }

    private static func fingerprint(of tunnel: Tunnel) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let outbound = (try? encoder.encode(tunnel.outbound))?.base64EncodedString() ?? ""
        return "\(tunnel.type.lowercased())|\(tunnel.host.lowercased())|\(tunnel.port)|\(outbound)"
    }
}
