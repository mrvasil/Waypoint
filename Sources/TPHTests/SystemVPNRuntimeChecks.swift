import Foundation
import TPHCore

enum SystemVPNRuntimeChecks {
    static func run(_ h: Harness) {
        h.suite("транзакции системного VPN")

        h.check("изменение только routing применяется без перезапуска Xray") {
            let active: JSONValue = .object([
                "inbounds": .array([.object(["tag": .string("in-system-vpn")])]),
                "outbounds": .array([.object(["tag": .string("out-a")])]),
                "routing": .object(["rules": .array([.object(["outboundTag": .string("out-a")])])]),
            ])
            var candidate = active
            candidate["routing"] = .object([
                "rules": .array([.object(["outboundTag": .string("out-b")])]),
            ])

            switch SystemVPNConfigTransition.plan(from: active, to: candidate) {
            case .hot(let update):
                try expectEqual(update.addedOutbounds, [], "лишние outbounds")
                try expectEqual(update.routing, candidate["routing"], "routing кандидата")
            case .reload:
                throw Failure("route-only изменение потребовало перезапуск")
            }
        }

        h.check("новый outbound добавляется до горячей смены маршрута") {
            let outA: JSONValue = .object([
                "tag": .string("out-a"), "protocol": .string("freedom"),
            ])
            let outB: JSONValue = .object([
                "tag": .string("out-b"), "protocol": .string("freedom"),
            ])
            let active: JSONValue = .object([
                "inbounds": .array([.object(["tag": .string("in-system-vpn")])]),
                "outbounds": .array([outA]),
                "routing": .object(["rules": .array([.object(["outboundTag": .string("out-a")])])]),
            ])
            let candidate: JSONValue = .object([
                "inbounds": active["inbounds"]!,
                "outbounds": .array([outB]),
                "routing": .object(["rules": .array([.object(["outboundTag": .string("out-b")])])]),
            ])

            switch SystemVPNConfigTransition.plan(from: active, to: candidate) {
            case .hot(let update):
                try expectEqual(update.addedOutbounds, [outB], "добавляемый outbound")
            case .reload:
                throw Failure("аддитивная смена outbound потребовала перезапуск")
            }
        }

        h.check("изменённый outbound с тем же tag требует транзакционный reload") {
            let active: JSONValue = .object([
                "outbounds": .array([.object([
                    "tag": .string("out-a"), "protocol": .string("freedom"),
                ])]),
                "routing": .object(["rules": .array([])]),
            ])
            let candidate: JSONValue = .object([
                "outbounds": .array([.object([
                    "tag": .string("out-a"), "protocol": .string("blackhole"),
                ])]),
                "routing": .object(["rules": .array([])]),
            ])
            try expectEqual(
                SystemVPNConfigTransition.plan(from: active, to: candidate),
                .reload,
                "same-tag mutation"
            )
        }

        h.check("результат reload привязан к generation и состоянию recovery") {
            let result = SystemVPNReloadResult.parse("gen-123 recovered 4242\n")
            try expectEqual(result?.generation, "gen-123", "generation")
            try expectEqual(result?.outcome, .recovered, "outcome")
            try expectEqual(result?.processID, 4242, "pid")
            try expect(SystemVPNReloadResult.parse("bad generation accepted 1") == nil, "принят пробел в generation")
        }

        h.check("смена сети передаёт helper новый physical interface") {
            let request = try SystemVPNReloadRequest(
                generation: "network-123",
                bypassInterface: "en7",
                routeOnly: true
            )
            try expectEqual(request.encodedText, "network-123 en7 route\n", "network reload request")
            try expectThrows("небезопасное имя интерфейса") {
                _ = try SystemVPNReloadRequest(
                    generation: "network-123",
                    bypassInterface: "../../en0"
                )
            }
        }

        h.check("helper получает отдельные active candidate rollback и result файлы") {
            let files = SystemVPNFiles(workDir: URL(fileURLWithPath: "/tmp/tph-vpn"))
            try expectEqual(files.config.lastPathComponent, "xray-system-vpn.json", "active")
            try expectEqual(files.candidate.lastPathComponent, "xray-system-vpn.candidate.json", "candidate")
            try expectEqual(files.rollback.lastPathComponent, "xray-system-vpn.rollback.json", "rollback")
            try expectEqual(files.result.lastPathComponent, "system-vpn.result", "result")

            let arguments = SystemVPNRuntime.helperArguments(
                xrayPath: "/opt/homebrew/bin/xray",
                helperFiles: files,
                interfaceName: "utun90",
                workDir: URL(fileURLWithPath: "/tmp/tph-vpn"),
                bypassInterface: "en0",
                userID: 501,
                groupID: 20,
                appPID: 42
            )
            try expectEqual(arguments[arguments.firstIndex(of: "--candidate")! + 1], files.candidate.path, "candidate arg")
            try expectEqual(arguments[arguments.firstIndex(of: "--rollback")! + 1], files.rollback.path, "rollback arg")
            try expectEqual(arguments[arguments.firstIndex(of: "--result")! + 1], files.result.path, "result arg")
        }

        h.check("перед hot switch проверяются только новые tunnel destinations") {
            let active: JSONValue = .object(["rules": .array([
                .object(["outboundTag": .string("out-a")]),
            ])])
            let candidate: JSONValue = .object(["rules": .array([
                .object(["outboundTag": .string("out-b")]),
                .object(["outboundTag": .string("direct")]),
                .object(["outboundTag": .string("block")]),
            ])])
            try expectEqual(
                SystemVPNConfigTransition.healthCheckOutboundTags(
                    from: active,
                    to: candidate
                ),
                ["out-b"],
                "health targets"
            )
        }
    }
}
