import Foundation
import WaypointCore

enum NetworkChangeChecks {
    static func run(_ h: Harness) {
        h.suite("смена физической сети")

        h.check("ранний старый fingerprint не завершает окно восстановления") {
            var window = NetworkPathRecoveryWindow(
                confirmedFingerprint: "en0|192.168.1.10|192.168.1.1"
            )

            try expectEqual(
                window.observe("en0|192.168.1.10|192.168.1.1"),
                .keepWatching,
                "ранний snapshot"
            )
            try expectEqual(window.observe(nil), .keepWatching, "переходное отсутствие gateway")

            let hotspot = "en0|172.20.10.2|172.20.10.1"
            try expectEqual(window.observe(hotspot), .rebind(hotspot), "готовый hotspot")

            window.confirm(hotspot)
            try expectEqual(window.observe(hotspot), .keepWatching, "подтверждённый путь")
        }

        h.check("возврат Wi-Fi требует rebind даже с прежним fingerprint") {
            let wifi = "en0|192.168.1.10|192.168.1.1"
            var window = NetworkPathRecoveryWindow(confirmedFingerprint: wifi)

            try expectEqual(window.observe(nil), .keepWatching, "DHCP ещё не готов")
            try expectEqual(window.observe(wifi), .rebind(wifi), "сокеты старого сеанса")

            window.confirm(wifi)
            try expectEqual(window.observe(wifi), .keepWatching, "повторный rebind не нужен")
        }

        h.check("новый физический default route важнее старого service order") {
            try expectEqual(
                NetworkInterface.choosePhysical(
                    defaultRoute: "en8",
                    serviceOrder: ["en0", "en8"],
                    usable: Set(["en0", "en8"])
                ),
                "en8",
                "USB-модем"
            )
            try expectEqual(
                NetworkInterface.choosePhysical(
                    defaultRoute: "utun90",
                    serviceOrder: ["en0", "en8"],
                    usable: Set(["en0", "en8"])
                ),
                "en0",
                "туннельный default route"
            )
        }

        h.check("физический monitor не прячет смену Wi-Fi за активным utun") {
            var tracker = PhysicalNetworkSignalTracker()

            try expectEqual(
                tracker.observe(source: "wifi", isAvailable: true),
                false,
                "initial callback не должен перезапускать VPN"
            )
            try expectEqual(
                tracker.observe(source: "wifi", isAvailable: false),
                true,
                "потеря physical link должна инвалидировать transport"
            )
            try expectEqual(
                tracker.isAwaitingPathRecovery,
                true,
                "старый DHCP route нельзя принять за восстановленную сеть"
            )
            try expectEqual(
                tracker.observe(source: "wifi", isAvailable: true),
                false,
                "возврат link — та же смена, а не второй restart"
            )
            try expectEqual(
                tracker.isAwaitingPathRecovery,
                false,
                "готовый physical path должен разблокировать recovery"
            )
            try expectEqual(
                tracker.observe(
                    source: "wifi",
                    isAvailable: true,
                    suppressStableAvailableChange: true
                ),
                false,
                "подъём собственного utun не должен выглядеть сменой Wi-Fi"
            )
            try expectEqual(
                tracker.observe(source: "wifi", isAvailable: true),
                true,
                "satisfied→satisfied callback всё равно означает смену physical path"
            )
        }
    }
}
