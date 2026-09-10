import Foundation
import Darwin

/// Определение физического сетевого интерфейса для обхода системных туннелей.
///
/// macOS маршрутизирует по назначению, а не по процессу: когда поднимается VPN
/// (Happ, WireGuard, Tailscale, системный), он ставит default route через свой
/// utun, и весь новый трафик — включая исходящий трафик xray — уходит внутрь
/// этого туннеля. Привязка сокета к физическому интерфейсу (sockopt.interface,
/// под капотом IP_BOUND_IF) перебивает таблицу маршрутизации.
public enum NetworkInterface {

    public struct Info: Equatable, Sendable {
        public var name: String
        public var address: String
        public var isTunnel: Bool
    }

    public struct BypassStatus: Equatable, Sendable {
        public var physical: String?
        public var defaultRoute: String?
        public var tunnels: [Info]
        public var tunnelCapturedRoute: Bool

        public init(
            physical: String? = nil,
            defaultRoute: String? = nil,
            tunnels: [Info] = [],
            tunnelCapturedRoute: Bool = false
        ) {
            self.physical = physical
            self.defaultRoute = defaultRoute
            self.tunnels = tunnels
            self.tunnelCapturedRoute = tunnelCapturedRoute
        }
    }

    /// Интерфейсы-туннели, которые нужно исключать из выбора.
    public static func isTunnelName(_ name: String) -> Bool {
        let lower = name.lowercased()
        for prefix in ["utun", "ipsec", "ppp", "gpd", "tun", "tap", "wg"] where lower.hasPrefix(prefix) {
            // Отсекаем совпадение по началу слова: "wg0" — туннель, а
            // гипотетический "wgadmin0" им не является.
            let suffix = lower.dropFirst(prefix.count)
            if suffix.isEmpty || suffix.allSatisfy(\.isNumber) { return true }
        }
        return false
    }

    /// Все интерфейсы с рабочим IPv4-адресом.
    ///
    /// getifaddrs читается напрямую из ядра — без запуска процессов, поэтому
    /// вызов дешёвый и его можно делать на каждый старт движка.
    public static func listInterfaces() -> [Info] {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0, let first = head else { return [] }
        defer { freeifaddrs(head) }

        var found: [String: Info] = [:]
        var ptr: UnsafeMutablePointer<ifaddrs>? = first

        while let cur = ptr {
            defer { ptr = cur.pointee.ifa_next }

            let flags = Int32(cur.pointee.ifa_flags)
            guard flags & IFF_UP != 0, flags & IFF_LOOPBACK == 0 else { continue }
            guard let addr = cur.pointee.ifa_addr, addr.pointee.sa_family == UInt8(AF_INET) else { continue }

            let name = String(cString: cur.pointee.ifa_name)

            var hostBuf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let res = getnameinfo(
                addr, socklen_t(addr.pointee.sa_len),
                &hostBuf, socklen_t(hostBuf.count),
                nil, 0, NI_NUMERICHOST
            )
            guard res == 0 else { continue }
            let ip = String(
                decoding: hostBuf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
                as: UTF8.self
            )

            // link-local (169.254.x.x) означает отсутствие реального линка.
            guard !ip.isEmpty, !ip.hasPrefix("169.254.") else { continue }

            found[name] = Info(name: name, address: ip, isTunnel: isTunnelName(name))
        }

        return found.values.sorted { $0.name < $1.name }
    }

    /// Физические интерфейсы в порядке приоритета системы.
    ///
    /// Порядок берётся из Network Service Order системных настроек, а не из
    /// default route: при активном full-tunnel VPN в default route окажется как
    /// раз utun — тот самый туннель, от которого мы уходим.
    public static func listPhysical() -> [String] {
        let usable = Set(listInterfaces().filter { !$0.isTunnel }.map(\.name))
        guard !usable.isEmpty else { return [] }

        var ordered: [String] = []
        if let output = Shell.run("/usr/sbin/networksetup", ["-listnetworkserviceorder"], timeout: 4) {
            // Строки вида: "(Hardware Port: Wi-Fi, Device: en0)"
            for line in output.components(separatedBy: .newlines) {
                guard let deviceRange = line.range(of: "Device: ") else { continue }
                let tail = line[deviceRange.upperBound...]
                let device = String(tail.prefix { $0 != ")" }).trimmingCharacters(in: .whitespaces)
                if usable.contains(device), !ordered.contains(device) {
                    ordered.append(device)
                }
            }
        }

        // Всё, что система не перечислила, добавляем следом — en* вперёд.
        let rest = usable.subtracting(ordered).sorted { a, b in
            let ae = a.hasPrefix("en") ? 0 : 1
            let be = b.hasPrefix("en") ? 0 : 1
            return ae == be ? a < b : ae < be
        }
        return ordered + rest
    }

    /// Интерфейс для обхода туннелей, либо nil если подходящего нет.
    public static func detectPhysical() -> String? {
        let ordered = listPhysical()
        return choosePhysical(
            defaultRoute: defaultRouteInterface(),
            serviceOrder: ordered,
            usable: Set(ordered)
        )
    }

    /// Во время Wi-Fi → USB-модем старый интерфейс ещё может иметь IPv4 и
    /// оставаться первым в Network Service Order. Если системный default route
    /// уже указывает на другой физический интерфейс, он точнее отражает текущий
    /// рабочий путь. Туннельный default route намеренно игнорируется.
    public static func choosePhysical(
        defaultRoute: String?,
        serviceOrder: [String],
        usable: Set<String>
    ) -> String? {
        if let defaultRoute,
           !isTunnelName(defaultRoute),
           usable.contains(defaultRoute) {
            return defaultRoute
        }
        return serviceOrder.first(where: usable.contains)
    }

    /// Стабильный снимок физического пути. Имя en0 само по себе недостаточно:
    /// при переходе между Wi-Fi сетями меняются адрес и gateway, а интерфейс
    /// остаётся тем же. Root-helper должен пересобрать scoped route и в этом случае.
    public static func physicalPathFingerprint(interface preferredInterface: String? = nil) -> String? {
        let interface = preferredInterface?.isEmpty == false
            ? preferredInterface
            : detectPhysical()
        guard let interface,
              let address = listInterfaces().first(where: {
                  $0.name == interface && !$0.isTunnel
              })?.address else { return nil }
        guard let gateway = scopedGateway(interface: interface) else { return nil }
        return "\(interface)|\(address)|\(gateway)"
    }

    public static func scopedGateway(interface: String) -> String? {
        guard !interface.isEmpty,
              let out = Shell.run(
                "/sbin/route",
                ["-n", "get", "-ifscope", interface, "default"],
                timeout: 4
              ) else { return nil }
        for line in out.components(separatedBy: .newlines) {
            let value = line.trimmingCharacters(in: .whitespaces)
            if value.hasPrefix("gateway:") {
                return String(value.dropFirst("gateway:".count))
                    .trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    /// Интерфейс из default route — какой сейчас выбрала бы система.
    /// Нужен для диагностики: если он отличается от физического, значит туннель
    /// перехватил маршрут и обход действительно работает.
    public static func defaultRouteInterface() -> String? {
        guard let out = Shell.run("/sbin/route", ["-n", "get", "default"], timeout: 4) else { return nil }
        for line in out.components(separatedBy: .newlines) {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("interface:") {
                return String(t.dropFirst("interface:".count)).trimmingCharacters(in: .whitespaces)
            }
        }
        return nil
    }

    /// Активные туннели — для показа в интерфейсе.
    public static func activeTunnels() -> [Info] {
        listInterfaces().filter(\.isTunnel)
    }

    /// Сводка: какой интерфейс выбран и перехвачен ли маршрут туннелем.
    public static func bypassStatus() -> BypassStatus {
        let route = defaultRouteInterface()
        return BypassStatus(
            physical: detectPhysical(),
            defaultRoute: route,
            tunnels: activeTunnels(),
            tunnelCapturedRoute: route.map(isTunnelName) ?? false
        )
    }
}
