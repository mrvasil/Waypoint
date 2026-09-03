import Foundation
import TPHCore

enum SubscriptionChecks {
    private static func tunnel(
        id: String,
        name: String,
        host: String,
        subscriptionId: String? = nil
    ) -> Tunnel {
        Tunnel(
            id: id,
            name: name,
            type: "vless",
            host: host,
            port: 443,
            subscriptionId: subscriptionId,
            outbound: .object([
                "protocol": .string("vless"),
                "settings": .object([
                    "vnext": .array([
                        .object([
                            "address": .string(host),
                            "port": .int(443),
                            "users": .array([.object(["id": .string("user-id")])]),
                        ]),
                    ]),
                ]),
            ])
        )
    }

    static func run(_ h: Harness) {
        h.suite("подписки")

        h.check("обновление подписки сохраняет ID совпавшего узла") {
            let subscription = Subscription(id: "s_1", name: "Основная", url: "https://example.com/sub")
            let old = tunnel(id: "t_stable", name: "Старое имя", host: "node.example.com", subscriptionId: subscription.id)
            let manual = tunnel(id: "t_manual", name: "Ручной", host: "manual.example.com")
            var state = AppState(subscriptions: [subscription], tunnels: [manual, old])
            let updateDate = Date(timeIntervalSince1970: 1_777_777_777)

            let incoming = tunnel(id: "t_random", name: "Новое имя", host: "node.example.com")
            _ = SubscriptionReconciler.refresh(
                subscriptionID: subscription.id,
                incoming: [incoming],
                updatedAt: updateDate,
                state: &state
            )

            let refreshed = try state.tunnels.first { $0.subscriptionId == subscription.id }
                .orThrow("обновлённый узел не найден")
            try expectEqual(refreshed.id, "t_stable", "ID узла")
            try expectEqual(refreshed.name, "Новое имя", "данные узла должны обновиться")
            try expectEqual(state.tunnels.first { $0.id == "t_manual" }?.subscriptionId, nil, "ручной туннель")
            try expectEqual(state.subscriptions[0].lastUpdatedAt, updateDate, "время обновления")
        }

        h.check("исчезнувший из подписки узел отвязывается от прокси") {
            let subscription = Subscription(id: "s_1", name: "Основная", url: "https://example.com/sub")
            let kept = tunnel(id: "t_kept", name: "Остаётся", host: "one.example.com", subscriptionId: subscription.id)
            let removed = tunnel(id: "t_removed", name: "Удалён", host: "two.example.com", subscriptionId: subscription.id)
            var state = AppState(
                systemVPN: SystemVPNConfiguration(tunnelId: removed.id),
                subscriptions: [subscription],
                tunnels: [kept, removed],
                proxies: [LocalProxy(id: "p_1", name: "SOCKS", kind: .socks, port: 10808, tunnelId: removed.id)]
            )

            let result = SubscriptionReconciler.refresh(
                subscriptionID: subscription.id,
                incoming: [tunnel(id: "new", name: "Остаётся", host: "one.example.com")],
                state: &state
            )

            try expectEqual(result.removedTunnelIDs, ["t_removed"], "удалённые узлы")
            try expectEqual(state.proxies[0].tunnelId, nil, "маршрут прокси должен стать прямым")
            try expectEqual(state.systemVPN.target, .tunnel(kept.id), "основной маршрут VPN")
        }

        h.check("удаление подписки удаляет только её узлы") {
            let removedSubscription = Subscription(id: "s_remove", name: "Удалить", url: "https://example.com/remove")
            let keptSubscription = Subscription(id: "s_keep", name: "Оставить", url: "https://example.com/keep")
            let owned = tunnel(id: "t_owned", name: "Из подписки", host: "owned.example.com", subscriptionId: removedSubscription.id)
            let other = tunnel(id: "t_other", name: "Другая", host: "other.example.com", subscriptionId: keptSubscription.id)
            let manual = tunnel(id: "t_manual", name: "Ручной", host: "manual.example.com")
            var state = AppState(
                systemVPN: SystemVPNConfiguration(tunnelId: owned.id),
                subscriptions: [removedSubscription, keptSubscription],
                tunnels: [owned, other, manual],
                proxies: [LocalProxy(id: "p_1", name: "SOCKS", kind: .socks, port: 10808, tunnelId: owned.id)]
            )

            let removedIDs = SubscriptionReconciler.remove(subscriptionID: removedSubscription.id, state: &state)

            try expectEqual(removedIDs, ["t_owned"], "удалённые узлы")
            try expectEqual(state.subscriptions.map(\.id), ["s_keep"], "оставшиеся подписки")
            try expectEqual(Set(state.tunnels.map(\.id)), Set(["t_other", "t_manual"]), "оставшиеся туннели")
            try expectEqual(state.proxies[0].tunnelId, nil, "привязка прокси")
            try expectEqual(state.systemVPN.target, .tunnel(other.id), "основной маршрут VPN")
        }

        h.check("исчезнувший узел не заменяет выбранную цепочку или fallback") {
            let subscription = Subscription(id: "s_route", name: "Маршруты", url: "https://example.com/routes")
            let removed = tunnel(
                id: "t_route_removed",
                name: "Удалён",
                host: "removed.example.com",
                subscriptionId: subscription.id
            )
            let kept = tunnel(id: "t_route_kept", name: "Остаётся", host: "kept.example.com")
            let chain = VPNTunnelChain(
                id: "c_selected",
                name: "Выбранная цепочка",
                tunnelIds: [removed.id, kept.id]
            )
            let fallback = VPNFallbackGroup(
                id: "f_selected",
                name: "Выбранный fallback",
                members: [
                    VPNFallbackMember(target: .tunnel(removed.id)),
                    VPNFallbackMember(target: .tunnel(kept.id)),
                ]
            )
            var state = AppState(
                systemVPN: SystemVPNConfiguration(target: .chain(chain.id)),
                subscriptions: [subscription],
                tunnels: [removed, kept],
                vpnTunnelChains: [chain],
                vpnFallbackGroups: [fallback]
            )

            _ = SubscriptionReconciler.refresh(
                subscriptionID: subscription.id,
                incoming: [],
                state: &state
            )
            try expectEqual(state.systemVPN.target, .chain(chain.id), "цепочка не должна заменяться")
            try expect(state.systemVPNMainRouteIssue() != nil, "битая цепочка должна быть видима")

            state.systemVPN.target = .fallback(fallback.id)
            try expectEqual(state.systemVPN.target, .fallback(fallback.id), "fallback не должен заменяться")
            try expect(state.systemVPNMainRouteIssue() != nil, "битый fallback должен быть видим")
        }
    }
}

private extension Optional {
    func orThrow(_ message: String) throws -> Wrapped {
        guard let self else { throw Failure(message) }
        return self
    }
}
