import Foundation
import WaypointCore

enum VPNQuickRouteChecks {
    private static func tunnel(_ id: String, _ name: String, subscriptionID: String?) -> Tunnel {
        Tunnel(
            id: id,
            name: name,
            type: "vless",
            host: "\(id).example.com",
            port: 443,
            subscriptionId: subscriptionID,
            outbound: .object(["protocol": .string("vless")])
        )
    }

    static func run(_ h: Harness) {
        h.suite("быстрые маршруты VPN")

        h.check("mrvasil и Akenai LTE разрешаются в стабильные цели") {
            let akenai = Subscription(id: "s-akenai", name: "Akenai", url: "https://example.com/a")
            let other = Subscription(id: "s-other", name: "Other", url: "https://example.com/b")
            var state = AppState(
                subscriptions: [akenai, other],
                tunnels: [
                    tunnel("lte-1", "🇪🇺 [Обход LTE] Европа 1", subscriptionID: akenai.id),
                    tunnel("lte-2", "🇷🇺 [обход lte] Россия 1", subscriptionID: akenai.id),
                    tunnel("regular", "Германия", subscriptionID: akenai.id),
                    tunnel("foreign", "[Обход LTE] Чужой", subscriptionID: other.id),
                ],
                vpnFallbackGroups: [VPNFallbackGroup(
                    id: "f-mrvasil",
                    name: "mrvasil vpn",
                    members: [
                        VPNFallbackMember(target: .tunnel("lte-1")),
                        VPNFallbackMember(target: .tunnel("lte-2")),
                    ]
                )]
            )

            try expectEqual(VPNQuickRoutes.mrvasilTarget(in: state), .fallback("f-mrvasil"), "mrvasil")
            let whitelist = VPNQuickRoutes.synchronizeWhitelist(in: &state)
            try expectEqual(whitelist, .fallback(VPNQuickRoutes.whitelistFallbackID), "whitelist target")

            let group = try state.vpnFallbackGroup(id: VPNQuickRoutes.whitelistFallbackID)
                .orThrow("managed fallback не создан")
            try expectEqual(
                group.members.map(\.target),
                [.tunnel("lte-1"), .tunnel("lte-2")],
                "только Akenai LTE"
            )
            try expectEqual(group.finalAction, .block, "при отказе всех каналов нельзя уходить Direct")
        }

        h.check("избранные туннели сохраняют порядок и не содержат удалённых узлов") {
            var state = AppState(tunnels: [
                tunnel("one", "Один", subscriptionID: nil),
                tunnel("two", "Два", subscriptionID: nil),
            ])

            state.setTunnelFavorite("two", isFavorite: true)
            state.setTunnelFavorite("one", isFavorite: true)
            state.setTunnelFavorite("two", isFavorite: true)
            state.setTunnelFavorite("missing", isFavorite: true)
            try expectEqual(state.favoriteTunnelIDs, ["two", "one"], "порядок избранного")
            try expectEqual(state.favoriteTunnels().map(\.id), ["two", "one"], "видимые карточки")

            state.tunnels.removeAll { $0.id == "two" }
            state.pruneFavoriteTunnelIDs()
            try expectEqual(state.favoriteTunnelIDs, ["one"], "удалённые избранные")

            let roundTrip = try JSONDecoder().decode(AppState.self, from: JSONEncoder().encode(state))
            try expectEqual(roundTrip.favoriteTunnelIDs, ["one"], "JSON round-trip")
        }
    }
}

private extension Optional {
    func orThrow(_ message: String) throws -> Wrapped {
        guard let self else { throw Failure(message) }
        return self
    }
}
