import Foundation
import WaypointCore

enum FallbackRuntimeChecks {
    static func run(_ h: Harness) {
        h.suite("runtime-статус fallback")

        h.check("парсер читает только выбранный outbound") {
            let output = """
              - Selecting Override:
                1
              - Selects:
                1   vpn-fallback-f1-candidate-1-m2
            """
            try expectEqual(
                XrayBalancerInfoParser.selectedOutboundTag(from: output),
                "vpn-fallback-f1-candidate-1-m2",
                "selected outbound"
            )
        }

        h.check("пустой и повреждённый ответ API не создаёт статус") {
            let malformed = """
              - Selecting Override:
                1   vpn-fallback-f1-candidate-0-m1
              - Selects:
                unavailable
            """
            try expect(XrayBalancerInfoParser.selectedOutboundTag(from: "") == nil, "пустой ответ принят")
            try expect(
                XrayBalancerInfoParser.selectedOutboundTag(from: malformed) == nil,
                "override ошибочно принят за selected outbound"
            )
        }

        h.check("выбранный Xray tag сопоставляется с участником fallback") {
            let group = sampleGroup(id: "f-map")
            let selectedTag = XrayConfig.tunnelTag("t2")
            let status = VPNFallbackRuntimeStatus.parse(
                group: group,
                xrayOutput: "  - Selects:\n    1   \(selectedTag)\n"
            )
            try expectEqual(status?.selectedMemberID, "m-secondary", "member id")
            try expectEqual(status?.selectedOutboundTag, selectedTag, "outbound tag")
        }

        h.check("резервные Direct и Block сохраняются как terminal selection") {
            let group = sampleGroup(id: "f-terminal")
            for terminal in ["direct", "block"] {
                let status = VPNFallbackRuntimeStatus.parse(
                    group: group,
                    xrayOutput: "  - Selects:\n    1   \(terminal)\n"
                )
                try expect(status != nil, "нет статуса для \(terminal)")
                try expectEqual(status?.selectedMemberID, nil, "terminal не должен быть member")
                try expectEqual(status?.selectedOutboundTag, terminal, "terminal outbound")
            }
        }

        h.check("список наблюдения содержит только реально используемые fallback") {
            var state = ConfigChecks.sampleState()
            state.vpnFallbackGroups = [
                sampleGroup(id: "f-policy"),
                sampleGroup(id: "f-main"),
                sampleGroup(id: "f-unused"),
            ]
            state.vpnRoutingPolicies = [
                VPNRoutingPolicy(
                    id: "p-invalid",
                    name: "Пустая",
                    targets: "",
                    target: .fallback("f-unused")
                ),
                VPNRoutingPolicy(
                    id: "p-valid",
                    name: "Политика",
                    targets: "example.com",
                    target: .fallback("f-policy")
                ),
                VPNRoutingPolicy(
                    id: "p-duplicate",
                    name: "Та же группа",
                    targets: "example.net",
                    target: .fallback("f-policy")
                ),
            ]
            state.systemVPN = SystemVPNConfiguration(target: .fallback("f-main"))

            try expectEqual(
                state.usedVPNFallbackGroupIDs(),
                ["f-policy", "f-main"],
                "порядок групп"
            )
        }

        h.check("Xray API маршрутизации доступен локально для любого системного VPN") {
            var state = ConfigChecks.sampleState()
            state.proxies = []
            state.vpnFallbackGroups = [sampleGroup(id: "f-api")]
            state.systemVPN = SystemVPNConfiguration(target: .fallback("f-api"))

            let config = XrayConfig.build(
                state: state,
                systemVPNInterface: "utun92",
                systemVPNAPIPort: 24_681
            )
            let apiInbound = (config["inbounds"]?.arrayValue ?? []).first {
                $0["tag"]?.stringValue == XrayConfig.vpnAPIInboundTag
            }
            try expectEqual(apiInbound?["listen"]?.stringValue, "127.0.0.1", "API listen")
            try expectEqual(apiInbound?["port"]?.intValue, 24_681, "API port")
            try expectEqual(
                apiInbound?["settings"]?["address"]?.stringValue,
                "127.0.0.1",
                "dokodemo target"
            )
            try expectEqual(
                config["api"]?["services"]?.arrayValue,
                [.string("RoutingService"), .string("HandlerService")],
                "API services"
            )
            let apiRule = (config["routing"]?["rules"]?.arrayValue ?? []).first {
                $0["inboundTag"]?[0]?.stringValue == XrayConfig.vpnAPIInboundTag
            }
            try expectEqual(apiRule?["outboundTag"]?.stringValue, XrayConfig.vpnAPITag, "API rule")

            let withoutPort = XrayConfig.build(
                state: state,
                systemVPNInterface: "utun92"
            )
            try expect(withoutPort["api"] == nil, "API появился без выделенного порта")

            state.systemVPN = SystemVPNConfiguration(target: .tunnel("t1"))
            let unused = XrayConfig.build(
                state: state,
                systemVPNInterface: "utun92",
                systemVPNAPIPort: 24_681
            )
            try expect(unused["api"] != nil, "API отсутствует для route-only переключения")
            try expect(
                (unused["inbounds"]?.arrayValue ?? []).contains {
                    $0["tag"]?.stringValue == XrayConfig.vpnAPIInboundTag
                },
                "локальный API inbound отсутствует"
            )
        }


        h.check("metrics parser читает полное наблюдение observatory") {
            let payload = Data(#"""
            {
              "observatory": {
                "vpn-fallback-f-health-candidate-0-m-primary": {
                  "alive": true,
                  "delay": 83,
                  "outbound_tag": "vpn-fallback-f-health-candidate-0-m-primary",
                  "last_try_time": 100
                },
                "vpn-fallback-f-health-candidate-1-m-secondary": {
                  "delay": 99999999,
                  "outbound_tag": "vpn-fallback-f-health-candidate-1-m-secondary",
                  "last_try_time": 101
                }
              }
            }
            """#.utf8)
            let observations = VPNFallbackMetricsParser.parse(payload)
            try expectEqual(observations.count, 2, "observation count")
            try expectEqual(
                observations["vpn-fallback-f-health-candidate-0-m-primary"]?.delayMs,
                83,
                "delay"
            )
            try expectEqual(
                observations["vpn-fallback-f-health-candidate-1-m-secondary"]?.alive,
                false,
                "failed health"
            )
        }

        h.check("bootstrap сразу использует первый канал, лучший подтверждается двумя пробами") {
            let group = sampleGroup(id: "f-best")
            var selector = VPNFallbackStableSelector(group: group)
            let first = XrayConfig.tunnelTag("t1")
            let second = XrayConfig.tunnelTag("t2")
            try expectEqual(selector.selectedOutboundTag, first, "bootstrap")

            let round1 = [
                first: VPNFallbackObservation(alive: true, delayMs: 600, lastTryTime: 10),
                second: VPNFallbackObservation(alive: true, delayMs: 20, lastTryTime: 10),
            ]
            try expectEqual(selector.consume(round1), nil, "слишком раннее переключение")
            let round2 = [
                first: VPNFallbackObservation(alive: true, delayMs: 590, lastTryTime: 20),
                second: VPNFallbackObservation(alive: true, delayMs: 18, lastTryTime: 20),
            ]
            try expectEqual(selector.consume(round2), .outbound(second), "подтверждённый лучший канал")
            try expectEqual(selector.selectedOutboundTag, second, "active after switch")
        }

        h.check("один сбой активного канала не вызывает fallback-дребезг") {
            let group = sampleGroup(id: "f-sticky")
            var selector = VPNFallbackStableSelector(group: group)
            let first = XrayConfig.tunnelTag("t1")
            let second = XrayConfig.tunnelTag("t2")
            _ = selector.consume([
                first: VPNFallbackObservation(alive: true, delayMs: 40, lastTryTime: 10),
                second: VPNFallbackObservation(alive: true, delayMs: 80, lastTryTime: 10),
            ])
            try expectEqual(selector.consume([
                first: VPNFallbackObservation(alive: false, delayMs: 99_999_999, lastTryTime: 20),
                second: VPNFallbackObservation(alive: true, delayMs: 80, lastTryTime: 20),
            ]), nil, "переключение после одного сбоя")
            try expectEqual(selector.selectedOutboundTag, first, "active должен остаться sticky")
            try expectEqual(selector.consume([
                first: VPNFallbackObservation(alive: true, delayMs: 42, lastTryTime: 30),
                second: VPNFallbackObservation(alive: true, delayMs: 79, lastTryTime: 30),
            ]), nil, "восстановление не требует переключения")
            try expectEqual(selector.selectedOutboundTag, first, "active после восстановления")
        }

        h.check("подтверждённый отказ переключает на живой резерв") {
            let group = sampleGroup(id: "f-fail")
            var selector = VPNFallbackStableSelector(group: group)
            let first = XrayConfig.tunnelTag("t1")
            let second = XrayConfig.tunnelTag("t2")
            _ = selector.consume([
                first: VPNFallbackObservation(alive: true, delayMs: 40, lastTryTime: 10),
                second: VPNFallbackObservation(alive: true, delayMs: 80, lastTryTime: 10),
            ])
            _ = selector.consume([
                first: VPNFallbackObservation(alive: false, delayMs: 99_999_999, lastTryTime: 20),
                second: VPNFallbackObservation(alive: true, delayMs: 80, lastTryTime: 20),
            ])
            try expectEqual(selector.consume([
                first: VPNFallbackObservation(alive: false, delayMs: 99_999_999, lastTryTime: 30),
                second: VPNFallbackObservation(alive: true, delayMs: 75, lastTryTime: 30),
            ]), .outbound(second), "confirmed fallback")
        }

        h.check("неподтверждённый bootstrap failure быстро выбирает уже живой канал") {
            let group = sampleGroup(id: "f-start")
            var selector = VPNFallbackStableSelector(group: group)
            let first = XrayConfig.tunnelTag("t1")
            let second = XrayConfig.tunnelTag("t2")
            try expectEqual(selector.consume([
                first: VPNFallbackObservation(alive: false, delayMs: 99_999_999, lastTryTime: 10),
                second: VPNFallbackObservation(alive: true, delayMs: 75, lastTryTime: 10),
            ]), .outbound(second), "startup recovery")
        }
    }

    private static func sampleGroup(id: String) -> VPNFallbackGroup {
        VPNFallbackGroup(
            id: id,
            name: "Primary + reserve",
            members: [
                VPNFallbackMember(id: "m-primary", target: .tunnel("t1")),
                VPNFallbackMember(id: "m-secondary", target: .tunnel("t2")),
            ],
            finalAction: .block
        )
    }
}
