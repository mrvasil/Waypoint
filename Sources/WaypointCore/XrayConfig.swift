import Foundation

/// Генерация конфигурации xray-core из состояния приложения.
///
/// Каждый локальный прокси → inbound, каждый использованный туннель → outbound.
/// Маршрутизация связывает их через inboundTag / outboundTag.
///
/// Обход системных туннелей (bypassInterface): когда параллельно поднят VPN
/// (Happ, WireGuard, Tailscale, системный), он ставит default route через свой
/// utun, и исходящие соединения xray уходят внутрь чужого туннеля.
/// sockopt.interface привязывает исходящий сокет к физическому интерфейсу
/// (IP_BOUND_IF), перебивая таблицу маршрутизации.
public enum XrayConfig {

    public static func tunnelTag(_ id: String) -> String { "out-\(id)" }
    public static func proxyTag(_ id: String) -> String { "in-\(id)" }
    public static func vpnChainTag(_ id: String) -> String { "vpn-chain-\(id)" }
    public static func vpnFallbackTag(_ id: String) -> String { "vpn-fallback-\(id)" }
    public static func vpnFallbackMemberOutboundTag(_ member: VPNFallbackMember) -> String? {
        switch member.target.kind {
        case .tunnel:
            return member.target.referenceId.map(tunnelTag)
        case .chain:
            return member.target.referenceId.map(vpnChainTag)
        default:
            return nil
        }
    }
    public static let systemVPNTag = "in-system-vpn"
    public static let vpnAPIInboundTag = "in-vpn-api"
    public static let vpnAPITag = "api"

    static let dnsTag = "dns-bypass"

    // MARK: - Обход

    /// Вешает привязку к физическому интерфейсу на outbound.
    /// Возвращает новое значение: outbound туннеля лежит в состоянии и менять
    /// его на месте нельзя.
    public static func withBypass(_ outbound: JSONValue, interface: String?) -> JSONValue {
        guard let interface, !interface.isEmpty else { return outbound }

        // Существующие sockopt (например из ссылки) сохраняем, добавляя привязку.
        let existingStream = outbound["streamSettings"] ?? .object([:])
        let existingSockopt = existingStream["sockopt"] ?? .object([:])
        let sockopt = existingSockopt.merging(.object(["interface": .string(interface)]))
        let stream = existingStream.merging(.object(["sockopt": sockopt]))

        return outbound.merging(.object(["streamSettings": stream]))
    }

    /// DNS-секция: резолв должен идти мимо системного резолвера, иначе имена
    /// серверов туннелей уходят в DNS активного VPN (у Tailscale это
    /// 100.100.100.100) — запрос либо утекает оператору туннеля, либо не отвечает.
    ///
    /// queryStrategy UseIPv4: большинство серверов туннелей имеют только
    /// A-запись. При UseIP xray ждёт ещё и AAAA и считает резолв неудачным,
    /// если её нет — туннель не поднимается вообще.
    static func buildDNS(interface: String?) -> JSONValue? {
        guard let interface, !interface.isEmpty else { return nil }
        return .object([
            "servers": .array([.string("1.1.1.1"), .string("8.8.8.8")]),
            "queryStrategy": .string("UseIPv4"),
            "disableCache": .bool(false),
            "tag": .string(dnsTag),
        ])
    }

    /// Правило: DNS-запросы самого xray идут напрямую, а не в туннель.
    ///
    /// Без него возникает круговая зависимость: чтобы поднять туннель, нужно
    /// отрезолвить имя его сервера, а резолв идёт через этот же туннель,
    /// который ещё не поднят. Правило должно быть первым — они применяются
    /// по порядку.
    static func dnsRule(interface: String?) -> JSONValue? {
        guard let interface, !interface.isEmpty else { return nil }
        return .object([
            "type": .string("field"),
            "inboundTag": .array([.string(dnsTag)]),
            "outboundTag": .string("direct"),
        ])
    }

    // MARK: - Inbound

    static func buildInbound(_ proxy: LocalProxy) -> JSONValue {
        var settings: [String: JSONValue] = [:]
        let hasAuth = !(proxy.auth?.user.isEmpty ?? true)

        switch proxy.kind {
        case .socks:
            settings["udp"] = .bool(true)
            if hasAuth, let auth = proxy.auth {
                settings["auth"] = .string("password")
                settings["accounts"] = .array([
                    .object(["user": .string(auth.user), "pass": .string(auth.pass)])
                ])
            } else {
                settings["auth"] = .string("noauth")
            }
        case .http:
            if hasAuth, let auth = proxy.auth {
                settings["accounts"] = .array([
                    .object(["user": .string(auth.user), "pass": .string(auth.pass)])
                ])
            }
            settings["allowTransparent"] = .bool(false)
        }

        return .object([
            "tag": .string(proxyTag(proxy.id)),
            "listen": .string(proxy.listen.isEmpty ? "127.0.0.1" : proxy.listen),
            "port": .int(proxy.port),
            "protocol": .string(proxy.kind == .http ? "http" : "socks"),
            "settings": .object(settings),
            "sniffing": .object([
                "enabled": .bool(true),
                "destOverride": .array([.string("http"), .string("tls"), .string("quic")]),
                "routeOnly": .bool(false),
            ]),
        ])
    }

    static func buildSystemVPNInbound(interfaceName: String) -> JSONValue {
        .object([
            "tag": .string(systemVPNTag),
            "protocol": .string("tun"),
            "settings": .object([
                "name": .string(interfaceName),
                "MTU": .int(1500),
            ]),
            "sniffing": .object([
                "enabled": .bool(true),
                "destOverride": .array([.string("http"), .string("tls"), .string("quic")]),
                "routeOnly": .bool(false),
            ]),
        ])
    }

    static func buildVPNAPIInbound(port: Int) -> JSONValue {
        .object([
            "tag": .string(vpnAPIInboundTag),
            "listen": .string("127.0.0.1"),
            "port": .int(port),
            "protocol": .string("dokodemo-door"),
            "settings": .object(["address": .string("127.0.0.1")]),
        ])
    }

    /// Добавляет first-match правила одного inbound и возвращает id реально
    /// используемого туннеля. Если туннель не выбран, fallback остаётся direct;
    /// Engine отдельно запрещает такой запуск для профилей с туннелем.
    @discardableResult
    static func appendRouteRules(
        inboundTag: String,
        routingMode: LocalProxy.RoutingMode,
        tunnel: Tunnel?,
        rules: inout [JSONValue]
    ) -> String? {
        let usesTunnel = routingMode != .directAll && tunnel != nil

        if routingMode == .directRussia, usesTunnel {
            // Xray применяет первое совпавшее правило. Исключения direct
            // обязаны идти до общего fallback в туннель.
            rules.append(.object([
                "type": .string("field"),
                "inboundTag": .array([.string(inboundTag)]),
                "domain": .array([.string("geosite:category-ru")]),
                "outboundTag": .string("direct"),
            ]))
            rules.append(.object([
                "type": .string("field"),
                "inboundTag": .array([.string(inboundTag)]),
                "ip": .array([.string("geoip:ru")]),
                "outboundTag": .string("direct"),
            ]))
        }

        if usesTunnel, let tunnel {
            rules.append(.object([
                "type": .string("field"),
                "inboundTag": .array([.string(inboundTag)]),
                "outboundTag": .string(tunnelTag(tunnel.id)),
            ]))
            return tunnel.id
        }

        rules.append(.object([
            "type": .string("field"),
            "inboundTag": .array([.string(inboundTag)]),
            "outboundTag": .string("direct"),
        ]))
        return nil
    }

    /// Добавляет пользовательские маршруты до обычных профилей. Возвращает
    /// `true`, если есть IP-условия и для доменных назначений нужен DNS resolve.
    @discardableResult
    static func appendPersistentRouteRules(
        state: AppState,
        proxies: [LocalProxy],
        hasSystemVPN: Bool,
        rules: inout [JSONValue],
        usedTunnelIds: inout [String]
    ) -> Bool {
        var requiresIPResolution = false

        for route in state.persistentRoutes where route.enabled {
            guard let tunnel = state.tunnel(id: route.tunnelId) else { continue }

            var inboundTags: [JSONValue] = []
            if route.appliesToSystemVPN, hasSystemVPN {
                inboundTags.append(.string(systemVPNTag))
            }
            if route.appliesToLocalProxies {
                inboundTags.append(contentsOf: proxies.map { .string(proxyTag($0.id)) })
            }
            guard !inboundTags.isEmpty else { continue }

            let targets = PersistentRouteTargets.parse(route.targets)
            guard !targets.isEmpty else { continue }

            if !targets.domains.isEmpty {
                rules.append(.object([
                    "type": .string("field"),
                    "inboundTag": .array(inboundTags),
                    "domain": .array(targets.domains.map(JSONValue.string)),
                    "outboundTag": .string(tunnelTag(tunnel.id)),
                ]))
            }
            if !targets.ips.isEmpty {
                requiresIPResolution = true
                rules.append(.object([
                    "type": .string("field"),
                    "inboundTag": .array(inboundTags),
                    "ip": .array(targets.ips.map(JSONValue.string)),
                    "outboundTag": .string(tunnelTag(tunnel.id)),
                ]))
            }
            if !usedTunnelIds.contains(tunnel.id) {
                usedTunnelIds.append(tunnel.id)
            }
        }

        return requiresIPResolution
    }

    private enum VPNRuleDestination {
        case outbound(String)
        case balancer(String)

        func apply(to rule: inout [String: JSONValue]) {
            switch self {
            case .outbound(let tag):
                rule["outboundTag"] = .string(tag)
            case .balancer(let tag):
                rule["balancerTag"] = .string(tag)
            }
        }
    }

    private static func appendUnique(_ value: String, to values: inout [String]) {
        if !values.contains(value) { values.append(value) }
    }

    private static func resolveVPNRouteTarget(
        _ target: VPNRouteTarget,
        state: AppState,
        usedTunnelIds: inout [String],
        usedChainIds: inout [String],
        usedFallbackIds: inout [String]
    ) -> VPNRuleDestination? {
        guard state.vpnRouteTargetIssue(target) == nil else { return nil }

        switch target.kind {
        case .direct:
            return .outbound("direct")
        case .block:
            return .outbound("block")
        case .tunnel:
            guard let id = target.referenceId else { return nil }
            appendUnique(id, to: &usedTunnelIds)
            return .outbound(tunnelTag(id))
        case .chain:
            guard let id = target.referenceId else { return nil }
            appendUnique(id, to: &usedChainIds)
            return .outbound(vpnChainTag(id))
        case .fallback:
            guard let id = target.referenceId else { return nil }
            appendUnique(id, to: &usedFallbackIds)
            return .balancer(vpnFallbackTag(id))
        }
    }

    /// Добавляет видимые в VPN-вкладке first-match политики. Каждая политика
    /// относится только к системному TUN и располагается выше legacy-правил.
    @discardableResult
    static func appendVPNRoutingPolicyRules(
        state: AppState,
        hasSystemVPN: Bool,
        rules: inout [JSONValue],
        usedTunnelIds: inout [String],
        usedChainIds: inout [String],
        usedFallbackIds: inout [String]
    ) -> Bool {
        guard hasSystemVPN else { return false }
        var requiresIPResolution = false

        for policy in state.vpnRoutingPolicies where policy.enabled {
            let targets = PersistentRouteTargets.parse(policy.targets)
            guard !targets.isEmpty,
                  let destination = resolveVPNRouteTarget(
                    policy.target,
                    state: state,
                    usedTunnelIds: &usedTunnelIds,
                    usedChainIds: &usedChainIds,
                    usedFallbackIds: &usedFallbackIds
                  ) else { continue }

            if !targets.domains.isEmpty {
                var rule: [String: JSONValue] = [
                    "type": .string("field"),
                    "inboundTag": .array([.string(systemVPNTag)]),
                    "domain": .array(targets.domains.map(JSONValue.string)),
                ]
                destination.apply(to: &rule)
                rules.append(.object(rule))
            }
            if !targets.ips.isEmpty {
                requiresIPResolution = true
                var rule: [String: JSONValue] = [
                    "type": .string("field"),
                    "inboundTag": .array([.string(systemVPNTag)]),
                    "ip": .array(targets.ips.map(JSONValue.string)),
                ]
                destination.apply(to: &rule)
                rules.append(.object(rule))
            }
        }

        return requiresIPResolution
    }

    private static func buildVPNChainOutbounds(
        state: AppState,
        chain: VPNTunnelChain,
        namespace: String,
        finalTag: String
    ) -> [JSONValue]? {
        guard state.vpnTunnelChainIssue(chain) == nil else { return nil }

        guard let firstTunnelID = chain.tunnelIds.first else { return nil }
        var result: [JSONValue] = []
        var previousTag = tunnelTag(firstTunnelID)
        for (index, tunnelID) in chain.tunnelIds.enumerated().dropFirst() {
            guard let tunnel = state.tunnel(id: tunnelID) else { return nil }
            let isLast = index == chain.tunnelIds.count - 1
            let tag = isLast ? finalTag : "\(namespace)-hop-\(index)"
            var outbound = WireGuardAddress.normalizedOutbound(tunnel.outbound)
                .merging(.object(["tag": .string(tag)]))

            outbound = outbound.merging(.object([
                "proxySettings": .object([
                    "tag": .string(previousTag),
                    "transportLayer": .bool(true),
                ]),
            ]))

            result.append(outbound)
            previousTag = tag
        }
        return result
    }

    private static func buildVPNFallback(
        state: AppState,
        group: VPNFallbackGroup
    ) -> JSONValue? {
        guard state.vpnFallbackGroupIssue(group) == nil else { return nil }

        var candidateTags: [String] = []
        var costs: [JSONValue] = []

        for (index, member) in group.members.enumerated() {
            guard let candidateTag = vpnFallbackMemberOutboundTag(member) else { return nil }
            candidateTags.append(candidateTag)

            // WeightManager применяет sqrt(cost) к RTT deviation. Степень 16
            // даёт выраженное предпочтение более раннему живому кандидату, а
            // maxRTT всё равно исключает зависший или слишком медленный маршрут.
            let priorityCost = pow(16.0, Double(index))
            costs.append(.object([
                "regexp": .bool(false),
                "match": .string(candidateTag),
                "value": .double(priorityCost),
            ]))
        }

        guard let bootstrapTag = candidateTags.first else { return nil }
        let balancer: JSONValue = .object([
            "tag": .string(vpnFallbackTag(group.id)),
            // Reuse canonical route outbounds. Duplicating a WireGuard peer
            // with the same private key creates two UDP sessions that keep
            // moving the server-side endpoint and looks like reconnect loops.
            "selector": .array(candidateTags.map(JSONValue.string)),
            // leastLoad returns no selection until the first observatory result.
            // Keep traffic on configured priority 1 during that short window;
            // Engine applies the explicit terminal action only after warm-up.
            "fallbackTag": .string(bootstrapTag),
            "strategy": .object([
                "type": .string("leastLoad"),
                "settings": .object([
                    "expected": .int(1),
                    "maxRTT": .string("\(group.maxLatencyMs)ms"),
                    "tolerance": .double(0.5),
                    "costs": .array(costs),
                ]),
            ]),
        ])
        return balancer
    }

    // MARK: - Полный конфиг

    public static func build(
        state: AppState,
        logLevel: String = "warning",
        bypassInterface: String? = nil,
        systemVPNInterface: String? = nil,
        systemVPNAPIPort: Int? = nil,
        systemVPNMetricsPort: Int? = nil
    ) -> JSONValue {
        let bypass = (bypassInterface?.isEmpty ?? true) ? nil : bypassInterface
        let proxies = state.proxies.filter(\.enabled)

        var inbounds: [JSONValue] = []
        var rules: [JSONValue] = []
        var usedTunnelIds: [String] = []
        var usedChainIds: [String] = []
        var usedFallbackIds: [String] = []

        // DNS-правило первым, до правил прокси.
        if let rule = dnsRule(interface: bypass) {
            rules.append(rule)
        }

        // Новые видимые политики идут раньше legacy-маршрутов и обычного
        // профиля. Их порядок в state — пользовательский first-match приоритет.
        let vpnPoliciesNeedIPResolution = appendVPNRoutingPolicyRules(
            state: state,
            hasSystemVPN: systemVPNInterface?.isEmpty == false,
            rules: &rules,
            usedTunnelIds: &usedTunnelIds,
            usedChainIds: &usedChainIds,
            usedFallbackIds: &usedFallbackIds
        )

        // Постоянные маршруты идут раньше локальной сети, RU-исключений и
        // fallback: пользователь явно потребовал их применять независимо от
        // обычного профиля VPN/прокси.
        let persistentRoutesNeedIPResolution = appendPersistentRouteRules(
            state: state,
            proxies: proxies.filter { $0.port > 0 },
            hasSystemVPN: systemVPNInterface?.isEmpty == false,
            rules: &rules,
            usedTunnelIds: &usedTunnelIds
        )

        if let systemVPNInterface, !systemVPNInterface.isEmpty {
            inbounds.append(buildSystemVPNInbound(interfaceName: systemVPNInterface))

            // Домашняя сеть и локальный DNS должны оставаться достижимыми. Это
            // правило не выпускает интернет напрямую: geoip:private содержит
            // только loopback, link-local и частные диапазоны.
            rules.append(.object([
                "type": .string("field"),
                "inboundTag": .array([.string(systemVPNTag)]),
                "ip": .array([.string("geoip:private")]),
                "outboundTag": .string("direct"),
            ]))

            // Последнее правило — выбранный основной маршрут. Невалидное
            // назначение намеренно не превращается в Direct: Engine запретит
            // запуск, а конфиг останется fail-closed.
            if state.systemVPNMainRouteIssue() == nil,
               let target = state.systemVPN.target,
               let destination = resolveVPNRouteTarget(
                    target,
                    state: state,
                    usedTunnelIds: &usedTunnelIds,
                    usedChainIds: &usedChainIds,
                    usedFallbackIds: &usedFallbackIds
               ) {
                var rule: [String: JSONValue] = [
                    "type": .string("field"),
                    "inboundTag": .array([.string(systemVPNTag)]),
                ]
                destination.apply(to: &rule)
                rules.append(.object(rule))
            }
        }

        for proxy in proxies where proxy.port > 0 {
            inbounds.append(buildInbound(proxy))

            let tunnel = state.tunnel(id: proxy.tunnelId)
            if let id = appendRouteRules(
                inboundTag: proxyTag(proxy.id),
                routingMode: proxy.routingMode,
                tunnel: tunnel,
                rules: &rules
            ), !usedTunnelIds.contains(id) {
                usedTunnelIds.append(id)
            }
        }

        // Fallbacks reuse the same canonical tunnel/chain handlers as direct
        // policies. Materialize their dependencies once before building any
        // outbound so identical WireGuard keys never create duplicate peers.
        for id in usedFallbackIds {
            guard let group = state.vpnFallbackGroup(id: id) else { continue }
            for member in group.members {
                switch member.target.kind {
                case .tunnel:
                    if let id = member.target.referenceId {
                        appendUnique(id, to: &usedTunnelIds)
                    }
                case .chain:
                    if let id = member.target.referenceId {
                        appendUnique(id, to: &usedChainIds)
                    }
                default:
                    break
                }
            }
        }
        for id in usedChainIds {
            if let firstTunnelID = state.vpnTunnelChain(id: id)?.tunnelIds.first {
                appendUnique(firstTunnelID, to: &usedTunnelIds)
            }
        }

        var outbounds: [JSONValue] = []
        for id in usedTunnelIds {
            guard let tunnel = state.tunnel(id: id) else { continue }
            let tagged = WireGuardAddress.normalizedOutbound(tunnel.outbound)
                .merging(.object(["tag": .string(tunnelTag(id))]))
            outbounds.append(withBypass(tagged, interface: bypass))
        }

        for id in usedChainIds {
            guard let chain = state.vpnTunnelChain(id: id),
                  let chainOutbounds = buildVPNChainOutbounds(
                    state: state,
                    chain: chain,
                    // Xray balancer selectors are prefix matches. Keep
                    // internal hops outside the public chain-tag namespace,
                    // otherwise selecting `vpn-chain-<id>` also selects its
                    // `-hop-*` implementation details.
                    namespace: "vpn-chain-hop-\(id)",
                    finalTag: vpnChainTag(id)
                  ) else { continue }
            outbounds.append(contentsOf: chainOutbounds)
        }

        var balancers: [JSONValue] = []
        var observatorySelectors: [JSONValue] = []
        for id in usedFallbackIds {
            guard let group = state.vpnFallbackGroup(id: id),
                  let generated = buildVPNFallback(
                    state: state,
                    group: group
                  ) else { continue }
            balancers.append(generated)
            for member in group.members {
                guard let tag = vpnFallbackMemberOutboundTag(member),
                      !observatorySelectors.contains(.string(tag)) else { continue }
                observatorySelectors.append(.string(tag))
            }
        }

        outbounds.append(withBypass(
            .object(["tag": .string("direct"), "protocol": .string("freedom"), "settings": .object([:])]),
            interface: bypass
        ))
        // blackhole никуда не ходит — привязка ему не нужна.
        outbounds.append(.object([
            "tag": .string("block"), "protocol": .string("blackhole"), "settings": .object([:]),
        ]))

        let hasVPNAPI = systemVPNInterface?.isEmpty == false
            && systemVPNAPIPort.map { (1...65_535).contains($0) } == true
        if hasVPNAPI, let systemVPNAPIPort {
            inbounds.append(buildVPNAPIInbound(port: systemVPNAPIPort))
            rules.append(.object([
                "type": .string("field"),
                "inboundTag": .array([.string(vpnAPIInboundTag)]),
                "outboundTag": .string(vpnAPITag),
            ]))
        }

        var routing: [String: JSONValue] = [
            "domainStrategy": .string(
                vpnPoliciesNeedIPResolution
                || persistentRoutesNeedIPResolution
                || proxies.contains {
                    $0.routingMode == .directRussia && state.tunnel(id: $0.tunnelId) != nil
                } ? "IPIfNonMatch" : "AsIs"
            ),
            "rules": .array(rules),
        ]
        if !balancers.isEmpty {
            routing["balancers"] = .array(balancers)
        }

        var config: [String: JSONValue] = [
            "log": .object(["loglevel": .string(logLevel)]),
            "inbounds": .array(inbounds),
            "outbounds": .array(outbounds),
            "routing": .object(routing),
        ]
        if hasVPNAPI {
            config["api"] = .object([
                "tag": .string(vpnAPITag),
                "services": .array([
                    .string("RoutingService"),
                    .string("HandlerService"),
                ]),
            ])
        }
        let hasVPNMetrics = systemVPNInterface?.isEmpty == false
            && systemVPNMetricsPort.map { (1...65_535).contains($0) } == true
        if hasVPNMetrics, let systemVPNMetricsPort {
            // Observatory health is consumed by Engine to apply sticky,
            // confirmed fallback transitions. Loopback keeps it local-only.
            config["metrics"] = .object([
                "listen": .string("127.0.0.1:\(systemVPNMetricsPort)"),
            ])
        }
        if let dns = buildDNS(interface: bypass) {
            config["dns"] = dns
        }
        if !observatorySelectors.isEmpty {
            config["observatory"] = .object([
                "subjectSelector": .array(observatorySelectors),
                "probeUrl": .string("https://www.gstatic.com/generate_204"),
                // Probe starts immediately; a short steady interval bounds the
                // dead-primary window without putting health checks in the data path.
                "probeInterval": .string("3s"),
                "enableConcurrency": .bool(true),
            ])
        }
        return .object(config)
    }

    /// Мини-конфиг для проверки одного туннеля: http-inbound → outbound туннеля.
    public static func buildTest(
        tunnel: Tunnel,
        port: Int,
        bypassInterface: String? = nil
    ) -> JSONValue {
        let bypass = (bypassInterface?.isEmpty ?? true) ? nil : bypassInterface

        var rules: [JSONValue] = []
        if let rule = dnsRule(interface: bypass) {
            rules.append(rule)
        }
        rules.append(.object([
            "type": .string("field"),
            "inboundTag": .array([.string("test-in")]),
            "outboundTag": .string("test-out"),
        ]))

        let testOut = WireGuardAddress.normalizedOutbound(tunnel.outbound)
            .merging(.object(["tag": .string("test-out")]))

        var config: [String: JSONValue] = [
            "log": .object(["loglevel": .string("warning")]),
            "inbounds": .array([
                .object([
                    "tag": .string("test-in"),
                    "listen": .string("127.0.0.1"),
                    "port": .int(port),
                    "protocol": .string("http"),
                    "settings": .object([:]),
                ])
            ]),
            "outbounds": .array([
                withBypass(testOut, interface: bypass),
                withBypass(
                    .object(["tag": .string("direct"), "protocol": .string("freedom"), "settings": .object([:])]),
                    interface: bypass
                ),
            ]),
            "routing": .object(["rules": .array(rules)]),
        ]
        if let dns = buildDNS(interface: bypass) {
            config["dns"] = dns
        }
        return .object(config)
    }

    /// Один временный Xray для пакетного измерения задержки: каждому туннелю
    /// соответствует свой локальный HTTP-inbound и outbound. Так десятки узлов
    /// проверяются без запуска отдельного процесса на каждую строку.
    public static func buildLatencyTests(
        tunnels: [Tunnel],
        ports: [String: Int],
        bypassInterface: String? = nil
    ) -> JSONValue {
        let bypass = (bypassInterface?.isEmpty ?? true) ? nil : bypassInterface
        let selected = tunnels.filter { ports[$0.id] != nil }
        var inbounds: [JSONValue] = []
        var outbounds: [JSONValue] = []
        var rules: [JSONValue] = []

        if let rule = dnsRule(interface: bypass) {
            rules.append(rule)
        }

        for tunnel in selected {
            guard let port = ports[tunnel.id] else { continue }
            let inboundTag = "latency-in-\(tunnel.id)"
            let outboundTag = "latency-out-\(tunnel.id)"
            inbounds.append(.object([
                "tag": .string(inboundTag),
                "listen": .string("127.0.0.1"),
                "port": .int(port),
                "protocol": .string("http"),
                "settings": .object([:]),
            ]))
            outbounds.append(withBypass(
                WireGuardAddress.normalizedOutbound(tunnel.outbound)
                    .merging(.object(["tag": .string(outboundTag)])),
                interface: bypass
            ))
            rules.append(.object([
                "type": .string("field"),
                "inboundTag": .array([.string(inboundTag)]),
                "outboundTag": .string(outboundTag),
            ]))
        }

        outbounds.append(withBypass(
            .object([
                "tag": .string("direct"),
                "protocol": .string("freedom"),
                "settings": .object([:]),
            ]),
            interface: bypass
        ))

        var config: [String: JSONValue] = [
            "log": .object(["loglevel": .string("warning")]),
            "inbounds": .array(inbounds),
            "outbounds": .array(outbounds),
            "routing": .object([
                "domainStrategy": .string("AsIs"),
                "rules": .array(rules),
            ]),
        ]
        if let dns = buildDNS(interface: bypass) {
            config["dns"] = dns
        }
        return .object(config)
    }

    /// Сериализация конфига в JSON для передачи xray.
    public static func encode(_ config: JSONValue, pretty: Bool = true) throws -> Data {
        let encoder = JSONEncoder()
        if pretty {
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        }
        return try encoder.encode(config)
    }
}
