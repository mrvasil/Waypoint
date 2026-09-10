import Foundation
import Darwin

/// Внешний туннель (upstream): то, через что уходит трафик.
public struct Tunnel: Identifiable, Codable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var type: String
    public var host: String
    public var port: Int
    /// Подписка-владелец. `nil` означает туннель, добавленный вручную.
    public var subscriptionId: String?
    /// Outbound для xray без поля `tag` — тег проставляет генератор конфига.
    public var outbound: JSONValue

    public init(
        id: String = "t_" + UUID().uuidString.prefix(8).lowercased(),
        name: String,
        type: String,
        host: String,
        port: Int,
        subscriptionId: String? = nil,
        outbound: JSONValue
    ) {
        self.id = id
        self.name = name
        self.type = type
        self.host = host
        self.port = port
        self.subscriptionId = subscriptionId
        self.outbound = outbound
    }
}

/// Сохранённый источник подписки. Сами узлы остаются в `AppState.tunnels` и
/// ссылаются на владельца через `Tunnel.subscriptionId`.
public struct Subscription: Identifiable, Codable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var url: String
    public var lastUpdatedAt: Date?

    public init(
        id: String = "s_" + UUID().uuidString.prefix(8).lowercased(),
        name: String,
        url: String,
        lastUpdatedAt: Date? = nil
    ) {
        self.id = id
        self.name = name
        self.url = url
        self.lastUpdatedAt = lastUpdatedAt
    }
}

/// Логин/пароль для локального прокси.
public struct ProxyAuth: Codable, Equatable, Sendable {
    public var user: String
    public var pass: String

    public init(user: String = "", pass: String = "") {
        self.user = user
        self.pass = pass
    }

    public var isEmpty: Bool { user.isEmpty }
}

/// Локальный прокси (downstream): то, что вписывают в браузер или Telegram.
public struct LocalProxy: Identifiable, Codable, Equatable, Sendable {
    public enum Kind: String, Codable, CaseIterable, Sendable {
        case socks
        case http

        public var label: String {
            switch self {
            case .socks: return "SOCKS5"
            case .http: return "HTTP"
            }
        }

        public var scheme: String {
            switch self {
            case .socks: return "socks5"
            case .http: return "http"
            }
        }
    }

    /// Готовые профили маршрутизации локального прокси.
    public enum RoutingMode: String, Codable, CaseIterable, Sendable {
        /// Любой трафик идёт через выбранный выходной маршрут.
        case tunnelAll
        /// Российские IP и домены идут напрямую, остальное — через туннель.
        case directRussia
        /// Любой трафик идёт напрямую, выбранный туннель не используется.
        case directAll

        public var label: String {
            switch self {
            case .tunnelAll: return L10n.string("Всё через маршрут")
            case .directRussia: return L10n.string("Россия напрямую")
            case .directAll: return L10n.string("Всё напрямую")
            }
        }
    }

    public var id: String
    public var name: String
    public var kind: Kind
    public var listen: String
    public var port: Int
    /// Основной выход для профилей с маршрутом. Может быть обычным туннелем,
    /// цепочкой или fallback-группой. В режиме `directAll` значение сохраняется,
    /// но генератор его игнорирует.
    public var target: VPNRouteTarget?
    public var routingMode: RoutingMode
    public var auth: ProxyAuth?
    public var enabled: Bool

    public init(
        id: String = "p_" + UUID().uuidString.prefix(8).lowercased(),
        name: String,
        kind: Kind,
        listen: String = "127.0.0.1",
        port: Int,
        target: VPNRouteTarget? = nil,
        tunnelId: String? = nil,
        routingMode: RoutingMode = .tunnelAll,
        auth: ProxyAuth? = nil,
        enabled: Bool = true
    ) {
        self.id = id
        self.name = name
        self.kind = kind
        self.listen = listen
        self.port = port
        self.target = target ?? tunnelId.map(VPNRouteTarget.tunnel)
        self.routingMode = routingMode
        self.auth = auth
        self.enabled = enabled
    }

    public var address: String { "\(listen):\(port)" }
    public var url: String { "\(kind.scheme)://\(listen):\(port)" }

    /// Source-совместимость со старой моделью. Для цепочки и fallback это
    /// намеренно `nil`: вызывающий код не должен принимать их за один туннель.
    public var tunnelId: String? {
        get {
            guard target?.kind == .tunnel else { return nil }
            return target?.referenceId
        }
        set {
            target = newValue.map(VPNRouteTarget.tunnel)
        }
    }

    private enum CodingKeys: String, CodingKey {
        case id, name, kind, listen, port, target, tunnelId, routingMode, auth, enabled
    }

    /// Совместимость с состоянием старых версий, где профиль маршрутизации не
    /// сохранялся: с `tunnelId` весь трафик шёл в туннель, без него — напрямую.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(String.self, forKey: .id)
            ?? "p_" + UUID().uuidString.prefix(8).lowercased()
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        kind = try c.decodeIfPresent(Kind.self, forKey: .kind) ?? .socks
        listen = try c.decodeIfPresent(String.self, forKey: .listen) ?? "127.0.0.1"
        port = try c.decodeIfPresent(Int.self, forKey: .port) ?? 10808
        if let decodedTarget = try c.decodeIfPresent(VPNRouteTarget.self, forKey: .target) {
            target = decodedTarget
        } else {
            target = try c.decodeIfPresent(String.self, forKey: .tunnelId)
                .map(VPNRouteTarget.tunnel)
        }
        routingMode = try c.decodeIfPresent(RoutingMode.self, forKey: .routingMode)
            ?? (target == nil ? .directAll : .tunnelAll)
        auth = try c.decodeIfPresent(ProxyAuth.self, forKey: .auth)
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(name, forKey: .name)
        try c.encode(kind, forKey: .kind)
        try c.encode(listen, forKey: .listen)
        try c.encode(port, forKey: .port)
        try c.encodeIfPresent(target, forKey: .target)
        try c.encode(routingMode, forKey: .routingMode)
        try c.encodeIfPresent(auth, forKey: .auth)
        try c.encode(enabled, forKey: .enabled)
    }
}

/// Основной маршрут для системного TUN-интерфейса.
///
/// Это только сохраняемая конфигурация. Состояние подключения намеренно не
/// хранится: приложение не должно показывать VPN активным после аварийного
/// завершения или перезагрузки macOS.
public struct SystemVPNConfiguration: Codable, Equatable, Sendable {
    public var target: VPNRouteTarget?

    public init(target: VPNRouteTarget? = nil) {
        self.target = target
    }

    /// Source-совместимость для тестов и клиентов старой модели. При записи
    /// состояние всё равно использует только новое поле `target`.
    public init(tunnelId: String?) {
        target = tunnelId.map(VPNRouteTarget.tunnel)
    }

    private enum CodingKeys: String, CodingKey {
        case target
        case tunnelId
        case routingMode
    }

    /// Миграция state.json без потери выбранного пользователем туннеля:
    /// новое поле имеет приоритет, иначе старый `tunnelId` становится route target.
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if let target = try container.decodeIfPresent(VPNRouteTarget.self, forKey: .target) {
            self.target = target
        } else {
            target = try container.decodeIfPresent(String.self, forKey: .tunnelId)
                .map(VPNRouteTarget.tunnel)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(target, forKey: .target)
    }
}

/// Приоритетный маршрут, который не зависит от выбранного профиля VPN/прокси.
/// Цели хранятся текстом, чтобы список было удобно вставлять и редактировать.
public struct PersistentRoute: Identifiable, Codable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var targets: String
    public var tunnelId: String
    public var appliesToSystemVPN: Bool
    public var appliesToLocalProxies: Bool
    public var enabled: Bool

    public init(
        id: String = "r_" + UUID().uuidString.prefix(8).lowercased(),
        name: String,
        targets: String,
        tunnelId: String,
        appliesToSystemVPN: Bool = true,
        appliesToLocalProxies: Bool = true,
        enabled: Bool = true
    ) {
        self.id = id
        self.name = name
        self.targets = targets
        self.tunnelId = tunnelId
        self.appliesToSystemVPN = appliesToSystemVPN
        self.appliesToLocalProxies = appliesToLocalProxies
        self.enabled = enabled
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decodeIfPresent(String.self, forKey: .id)
            ?? "r_" + UUID().uuidString.prefix(8).lowercased()
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        targets = try c.decodeIfPresent(String.self, forKey: .targets) ?? ""
        tunnelId = try c.decodeIfPresent(String.self, forKey: .tunnelId) ?? ""
        appliesToSystemVPN = try c.decodeIfPresent(Bool.self, forKey: .appliesToSystemVPN) ?? true
        appliesToLocalProxies = try c.decodeIfPresent(Bool.self, forKey: .appliesToLocalProxies) ?? true
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
    }
}

/// Разобранные цели постоянного маршрута. Xray требует разнести `domain` и
/// `ip` по разным правилам: если положить их в одно, условия будут сочетаться.
public struct PersistentRouteTargets: Equatable, Sendable {
    public var domains: [String]
    public var ips: [String]
    public var invalidLines: [String]

    public init(domains: [String] = [], ips: [String] = [], invalidLines: [String] = []) {
        self.domains = domains
        self.ips = ips
        self.invalidLines = invalidLines
    }

    public var count: Int { domains.count + ips.count }
    public var isEmpty: Bool { count == 0 }

    /// Формат списка: одна цель на строку, пустые строки и строки с `#`
    /// игнорируются. Обычный домен превращается в `domain:`, поэтому совпадают
    /// и сам домен, и его поддомены. Для точного совпадения доступен `full:`.
    public static func parse(_ text: String) -> PersistentRouteTargets {
        var result = PersistentRouteTargets()
        var seenDomains = Set<String>()
        var seenIPs = Set<String>()

        for rawLine in text.components(separatedBy: .newlines) {
            var line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty, !line.hasPrefix("#") else { continue }

            if line.hasPrefix("*.") {
                line.removeFirst(2)
            }

            if let prefix = ["domain:", "full:"].first(where: line.hasPrefix) {
                let value = String(line.dropFirst(prefix.count))
                if validDomain(value) {
                    let normalized = value.hasSuffix(".") ? String(value.dropLast()) : value
                    appendUnique("\(prefix)\(normalized.lowercased())", to: &result.domains, seen: &seenDomains)
                } else {
                    result.invalidLines.append(rawLine)
                }
            } else if validAdvancedToken(line, prefix: "geosite:") {
                appendUnique(line, to: &result.domains, seen: &seenDomains)
            } else if line.hasPrefix("regexp:") {
                let pattern = String(line.dropFirst("regexp:".count))
                if !pattern.isEmpty, (try? NSRegularExpression(pattern: pattern)) != nil {
                    appendUnique(line, to: &result.domains, seen: &seenDomains)
                } else {
                    result.invalidLines.append(rawLine)
                }
            } else if validAdvancedToken(line, prefix: "geoip:") {
                appendUnique(line, to: &result.ips, seen: &seenIPs)
            } else if validIPOrCIDR(line) {
                appendUnique(line, to: &result.ips, seen: &seenIPs)
            } else if validDomain(line) {
                let normalized = line.hasSuffix(".") ? String(line.dropLast()) : line
                appendUnique("domain:\(normalized.lowercased())", to: &result.domains, seen: &seenDomains)
            } else {
                result.invalidLines.append(rawLine)
            }
        }

        return result
    }

    private static func appendUnique(
        _ value: String,
        to values: inout [String],
        seen: inout Set<String>
    ) {
        guard seen.insert(value).inserted else { return }
        values.append(value)
    }

    private static func validAdvancedToken(_ value: String, prefix: String) -> Bool {
        guard value.hasPrefix(prefix), value.count > prefix.count else { return false }
        return value.dropFirst(prefix.count).allSatisfy { !$0.isWhitespace }
    }

    private static func validIPOrCIDR(_ value: String) -> Bool {
        let parts = value.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 1 || parts.count == 2 else { return false }
        let address = String(parts[0])
        let family = ipFamily(address)
        guard family != nil else { return false }
        guard parts.count == 2, let prefix = Int(parts[1]) else {
            return parts.count == 1
        }
        return prefix >= 0 && prefix <= (family == AF_INET ? 32 : 128)
    }

    private static func ipFamily(_ value: String) -> Int32? {
        var ipv4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            return AF_INET
        }
        var ipv6 = in6_addr()
        if value.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            return AF_INET6
        }
        return nil
    }

    private static func validDomain(_ value: String) -> Bool {
        let domain = value.hasSuffix(".") ? String(value.dropLast()) : value
        guard !domain.isEmpty, domain.utf8.count <= 253, !domain.contains(":") else { return false }
        let labels = domain.split(separator: ".", omittingEmptySubsequences: false)
        guard !labels.isEmpty else { return false }

        var containsNonDigit = false
        for label in labels {
            guard !label.isEmpty, label.utf8.count <= 63,
                  label.first != "-", label.last != "-" else { return false }
            for scalar in label.unicodeScalars {
                let valid = CharacterSet.alphanumerics.contains(scalar)
                    || scalar == "-" || scalar == "_"
                guard valid else { return false }
                if !CharacterSet.decimalDigits.contains(scalar) {
                    containsNonDigit = true
                }
            }
        }
        // Не принимаем ошибочные IPv4 вроде 999.1.1.1 за домен.
        return containsNonDigit
    }
}

/// Настройки приложения.
public struct Settings: Codable, Equatable, Sendable {
    public var xrayPath: String
    public var logLevel: String
    /// Обход системных VPN и туннелей включён по умолчанию: приложение должно
    /// работать поверх активного Happ / WireGuard / Tailscale без настройки.
    public var bypassTunnels: Bool
    /// Ручное переопределение интерфейса; пусто — определяется автоматически.
    public var bypassInterface: String

    public init(
        xrayPath: String = "",
        logLevel: String = "warning",
        bypassTunnels: Bool = true,
        bypassInterface: String = ""
    ) {
        self.xrayPath = xrayPath
        self.logLevel = logLevel
        self.bypassTunnels = bypassTunnels
        self.bypassInterface = bypassInterface
    }

    /// Совместимость с state.json из Electron-версии: там могло не быть новых
    /// полей, а декодер по умолчанию считает отсутствующий ключ ошибкой.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        xrayPath = try c.decodeIfPresent(String.self, forKey: .xrayPath) ?? ""
        logLevel = try c.decodeIfPresent(String.self, forKey: .logLevel) ?? "warning"
        bypassTunnels = try c.decodeIfPresent(Bool.self, forKey: .bypassTunnels) ?? true
        bypassInterface = try c.decodeIfPresent(String.self, forKey: .bypassInterface) ?? ""
    }
}

/// Полное состояние приложения — то, что лежит в state.json.
public struct AppState: Codable, Equatable, Sendable {
    public var settings: Settings
    public var systemVPN: SystemVPNConfiguration
    public var subscriptions: [Subscription]
    public var tunnels: [Tunnel]
    /// Пользовательский порядок быстрых туннелей на Dashboard.
    public var favoriteTunnelIDs: [String]
    public var proxies: [LocalProxy]
    public var persistentRoutes: [PersistentRoute]
    public var vpnRoutingPolicies: [VPNRoutingPolicy]
    public var vpnTunnelChains: [VPNTunnelChain]
    public var vpnFallbackGroups: [VPNFallbackGroup]

    public init(
        settings: Settings = Settings(),
        systemVPN: SystemVPNConfiguration = SystemVPNConfiguration(),
        subscriptions: [Subscription] = [],
        tunnels: [Tunnel] = [],
        favoriteTunnelIDs: [String] = [],
        proxies: [LocalProxy] = [],
        persistentRoutes: [PersistentRoute] = [],
        vpnRoutingPolicies: [VPNRoutingPolicy] = [],
        vpnTunnelChains: [VPNTunnelChain] = [],
        vpnFallbackGroups: [VPNFallbackGroup] = []
    ) {
        self.settings = settings
        self.systemVPN = systemVPN
        self.subscriptions = subscriptions
        self.tunnels = tunnels
        self.favoriteTunnelIDs = favoriteTunnelIDs
        self.proxies = proxies
        self.persistentRoutes = persistentRoutes
        self.vpnRoutingPolicies = vpnRoutingPolicies
        self.vpnTunnelChains = vpnTunnelChains
        self.vpnFallbackGroups = vpnFallbackGroups
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        settings = try c.decodeIfPresent(Settings.self, forKey: .settings) ?? Settings()
        systemVPN = try c.decodeIfPresent(SystemVPNConfiguration.self, forKey: .systemVPN)
            ?? SystemVPNConfiguration()
        subscriptions = try c.decodeIfPresent([Subscription].self, forKey: .subscriptions) ?? []
        tunnels = try c.decodeIfPresent([Tunnel].self, forKey: .tunnels) ?? []
        favoriteTunnelIDs = try c.decodeIfPresent([String].self, forKey: .favoriteTunnelIDs) ?? []
        proxies = try c.decodeIfPresent([LocalProxy].self, forKey: .proxies) ?? []
        persistentRoutes = try c.decodeIfPresent([PersistentRoute].self, forKey: .persistentRoutes) ?? []
        vpnRoutingPolicies = try c.decodeIfPresent([VPNRoutingPolicy].self, forKey: .vpnRoutingPolicies) ?? []
        vpnTunnelChains = try c.decodeIfPresent([VPNTunnelChain].self, forKey: .vpnTunnelChains) ?? []
        vpnFallbackGroups = try c.decodeIfPresent([VPNFallbackGroup].self, forKey: .vpnFallbackGroups) ?? []
    }

    public func tunnel(id: String?) -> Tunnel? {
        guard let id else { return nil }
        return tunnels.first { $0.id == id }
    }

    public func isTunnelFavorite(_ id: String) -> Bool {
        favoriteTunnelIDs.contains(id)
    }

    public func favoriteTunnels() -> [Tunnel] {
        favoriteTunnelIDs.compactMap { tunnel(id: $0) }
    }

    public mutating func setTunnelFavorite(_ id: String, isFavorite: Bool) {
        guard tunnel(id: id) != nil else { return }
        if isFavorite {
            if !favoriteTunnelIDs.contains(id) { favoriteTunnelIDs.append(id) }
        } else {
            favoriteTunnelIDs.removeAll { $0 == id }
        }
    }

    public mutating func pruneFavoriteTunnelIDs() {
        let available = Set(tunnels.map(\.id))
        var seen = Set<String>()
        favoriteTunnelIDs = favoriteTunnelIDs.filter {
            available.contains($0) && seen.insert($0).inserted
        }
    }

    /// Глобальный переключатель локальных прокси относится только к текущему
    /// запуску и не должен менять сохранённые флаги отдельных портов.
    public func configuredForRuntime(localProxiesEnabled: Bool) -> AppState {
        guard !localProxiesEnabled else { return self }
        var runtime = self
        for index in runtime.proxies.indices {
            runtime.proxies[index].enabled = false
        }
        return runtime
    }
}

/// Результат разбора текста со ссылками.
public struct ParseResult: Sendable {
    public var tunnels: [Tunnel]
    public var errors: [ParseError]

    public init(tunnels: [Tunnel] = [], errors: [ParseError] = []) {
        self.tunnels = tunnels
        self.errors = errors
    }
}

public struct ParseError: Sendable, Identifiable {
    public let id = UUID()
    public var line: String
    public var message: String

    public init(line: String, message: String) {
        self.line = line
        self.message = message
    }
}

public struct TunnelTestResult: Sendable {
    public var ok: Bool
    public var ip: String?
    public var loc: String?
    public var latencyMs: Int?
    public var error: String?

    public init(ok: Bool, ip: String? = nil, loc: String? = nil, latencyMs: Int? = nil, error: String? = nil) {
        self.ok = ok
        self.ip = ip
        self.loc = loc
        self.latencyMs = latencyMs
        self.error = error
    }
}
