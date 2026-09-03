import Foundation

/// Назначение одного правила системного VPN.
///
/// Структура вместо enum с associated values оставляет state.json простым и
/// позволяет безопасно декодировать новые варианты в следующих версиях.
public struct VPNRouteTarget: Codable, Equatable, Hashable, Sendable {
    public enum Kind: String, Codable, CaseIterable, Sendable {
        case direct
        case block
        case tunnel
        case chain
        case fallback
    }

    public var kind: Kind
    public var referenceId: String?

    public init(kind: Kind, referenceId: String? = nil) {
        self.kind = kind
        self.referenceId = referenceId
    }

    public static let direct = VPNRouteTarget(kind: .direct)
    public static let block = VPNRouteTarget(kind: .block)
    public static func tunnel(_ id: String) -> VPNRouteTarget {
        VPNRouteTarget(kind: .tunnel, referenceId: id)
    }
    public static func chain(_ id: String) -> VPNRouteTarget {
        VPNRouteTarget(kind: .chain, referenceId: id)
    }
    public static func fallback(_ id: String) -> VPNRouteTarget {
        VPNRouteTarget(kind: .fallback, referenceId: id)
    }
}

/// Приоритетный список доменов, сетей, GeoSite и GeoIP для системного VPN.
/// Порядок элементов в `AppState.vpnRoutingPolicies` — порядок first-match.
public struct VPNRoutingPolicy: Identifiable, Codable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var targets: String
    public var target: VPNRouteTarget
    public var enabled: Bool

    public init(
        id: String = "vr_" + UUID().uuidString.prefix(8).lowercased(),
        name: String,
        targets: String,
        target: VPNRouteTarget,
        enabled: Bool = true
    ) {
        self.id = id
        self.name = name
        self.targets = targets
        self.target = target
        self.enabled = enabled
    }
}

/// Последовательность реальных узлов от Mac к выходному узлу.
/// Например `[wireguard, vless]` означает `Mac → WireGuard → VLESS → Интернет`.
public struct VPNTunnelChain: Identifiable, Codable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var tunnelIds: [String]
    public var enabled: Bool

    public init(
        id: String = "vc_" + UUID().uuidString.prefix(8).lowercased(),
        name: String,
        tunnelIds: [String],
        enabled: Bool = true
    ) {
        self.id = id
        self.name = name
        self.tunnelIds = tunnelIds
        self.enabled = enabled
    }
}

/// Один кандидат fallback-группы. Вложенные fallback запрещены, но кандидатом
/// может быть как один туннель, так и готовая многошаговая цепочка.
public struct VPNFallbackMember: Identifiable, Codable, Equatable, Sendable {
    public var id: String
    public var target: VPNRouteTarget

    public init(
        id: String = "fm_" + UUID().uuidString.prefix(8).lowercased(),
        target: VPNRouteTarget
    ) {
        self.id = id
        self.target = target
    }
}

public enum VPNFallbackFinalAction: String, Codable, CaseIterable, Sendable {
    case block
    case direct
}

/// Health-aware маршрут. Xray исключает недоступные и слишком медленные
/// варианты, а порядок `members` задаёт предпочтение среди подходящих.
public struct VPNFallbackGroup: Identifiable, Codable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var members: [VPNFallbackMember]
    public var maxLatencyMs: Int
    public var finalAction: VPNFallbackFinalAction
    public var enabled: Bool

    public init(
        id: String = "vf_" + UUID().uuidString.prefix(8).lowercased(),
        name: String,
        members: [VPNFallbackMember],
        maxLatencyMs: Int = 1200,
        finalAction: VPNFallbackFinalAction = .block,
        enabled: Bool = true
    ) {
        self.id = id
        self.name = name
        self.members = members
        self.maxLatencyMs = maxLatencyMs
        self.finalAction = finalAction
        self.enabled = enabled
    }
}

public extension AppState {
    func vpnTunnelChain(id: String?) -> VPNTunnelChain? {
        guard let id else { return nil }
        return vpnTunnelChains.first { $0.id == id }
    }

    func vpnFallbackGroup(id: String?) -> VPNFallbackGroup? {
        guard let id else { return nil }
        return vpnFallbackGroups.first { $0.id == id }
    }

    /// Основной маршрут допускает только реальные сетевые пути. Direct и
    /// Block доступны политикам, но не catch-all системного VPN.
    func systemVPNMainRouteIssue() -> String? {
        guard let target = systemVPN.target else { return "Основной маршрут не выбран" }
        guard target.kind == .tunnel || target.kind == .chain || target.kind == .fallback else {
            return "Основным маршрутом может быть туннель, цепочка или fallback"
        }
        return vpnRouteTargetIssue(target)
    }

    func systemVPNMainTunnelID() -> String? {
        guard systemVPN.target?.kind == .tunnel else { return nil }
        return systemVPN.target?.referenceId
    }

    /// Fallback попадает в runtime только если на него ссылается корректная
    /// включённая политика или основной маршрут. Порядок совпадает с генератором.
    func usedVPNFallbackGroupIDs() -> [String] {
        var result: [String] = []
        func append(_ id: String) {
            if !result.contains(id) { result.append(id) }
        }

        for policy in vpnRoutingPolicies where policy.enabled && policy.target.kind == .fallback {
            guard !PersistentRouteTargets.parse(policy.targets).isEmpty,
                  vpnRouteTargetIssue(policy.target) == nil,
                  let id = policy.target.referenceId else { continue }
            append(id)
        }
        if let target = systemVPN.target,
           target.kind == .fallback,
           systemVPNMainRouteIssue() == nil,
           let id = target.referenceId {
            append(id)
        }
        return result
    }

    /// `nil` означает корректное назначение; текст предназначен и для UI, и
    /// для безопасного отбрасывания битых ссылок генератором.
    func vpnRouteTargetIssue(_ target: VPNRouteTarget, allowFallback: Bool = true) -> String? {
        switch target.kind {
        case .direct, .block:
            return nil
        case .tunnel:
            guard tunnel(id: target.referenceId) != nil else { return "Туннель недоступен" }
            return nil
        case .chain:
            guard let chain = vpnTunnelChain(id: target.referenceId) else { return "Цепочка удалена" }
            return vpnTunnelChainIssue(chain)
        case .fallback:
            guard allowFallback else { return "Fallback нельзя вложить в fallback" }
            guard let group = vpnFallbackGroup(id: target.referenceId) else { return "Fallback удалён" }
            return vpnFallbackGroupIssue(group)
        }
    }

    func vpnTunnelChainIssue(_ chain: VPNTunnelChain) -> String? {
        guard chain.enabled else { return "Цепочка выключена" }
        guard chain.tunnelIds.count >= 2 else { return "Нужно минимум два туннеля" }
        guard Set(chain.tunnelIds).count == chain.tunnelIds.count else {
            return "Один туннель повторяется в цепочке"
        }
        guard chain.tunnelIds.allSatisfy({ tunnel(id: $0) != nil }) else {
            return "Один из туннелей недоступен"
        }
        return nil
    }

    func vpnFallbackGroupIssue(_ group: VPNFallbackGroup) -> String? {
        guard group.enabled else { return "Fallback выключен" }
        guard group.maxLatencyMs >= 100, group.maxLatencyMs <= 30_000 else {
            return "Порог задержки должен быть от 100 до 30000 мс"
        }
        guard group.members.count >= 2 else { return "Нужно минимум два варианта" }
        let targets = group.members.map(\.target)
        guard Set(targets).count == targets.count else { return "Один маршрут повторяется" }
        for member in group.members {
            guard member.target.kind == .tunnel || member.target.kind == .chain else {
                return "Fallback поддерживает туннели и цепочки"
            }
            if let issue = vpnRouteTargetIssue(member.target, allowFallback: false) {
                return issue
            }
        }
        return nil
    }
}
