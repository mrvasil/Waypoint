import Foundation
import WaypointCore

enum ConfigChecks {
    static func sampleState() -> AppState {
        let vless = Tunnel(
            id: "t1", name: "vless", type: "vless", host: "a.example.com", port: 443,
            outbound: .object([
                "protocol": .string("vless"),
                "settings": .object(["vnext": .array([])]),
                "streamSettings": .object(["network": .string("ws"), "security": .string("tls")]),
            ])
        )
        let wg = Tunnel(
            id: "t2", name: "wg", type: "wireguard", host: "wg.example.com", port: 51820,
            outbound: .object([
                "protocol": .string("wireguard"),
                "settings": .object(["secretKey": .string("k"), "peers": .array([])]),
            ])
        )
        return AppState(
            settings: Settings(),
            tunnels: [vless, wg],
            proxies: [
                LocalProxy(id: "p1", name: "s", kind: .socks, port: 10808, tunnelId: "t1"),
                LocalProxy(id: "p2", name: "h", kind: .http, port: 10809, tunnelId: "t2"),
            ]
        )
    }

    static func run(_ h: Harness) {
        h.suite("генерация конфига xray")

        h.check("привязка попадает во все outbound-туннели") {
            let c = XrayConfig.build(state: sampleState(), bypassInterface: "en0")
            let outs = (c["outbounds"]?.arrayValue ?? []).filter {
                ($0["tag"]?.stringValue ?? "").hasPrefix("out-")
            }
            try expectEqual(outs.count, 2, "outbound-туннелей")
            for o in outs {
                try expectEqual(
                    o["streamSettings"]?["sockopt"]?["interface"]?.stringValue, "en0",
                    "привязка \(o["tag"]?.stringValue ?? "?")"
                )
            }
        }

        h.check("direct привязан, block — нет") {
            let c = XrayConfig.build(state: sampleState(), bypassInterface: "en0")
            let outs = c["outbounds"]?.arrayValue ?? []
            let direct = outs.first { $0["tag"]?.stringValue == "direct" }
            let block = outs.first { $0["tag"]?.stringValue == "block" }
            try expectEqual(direct?["streamSettings"]?["sockopt"]?["interface"]?.stringValue, "en0", "direct")
            try expect(block?["streamSettings"] == nil, "blackhole не должен получать sockopt")
        }

        h.check("существующие streamSettings сохраняются") {
            let c = XrayConfig.build(state: sampleState(), bypassInterface: "en0")
            let vless = (c["outbounds"]?.arrayValue ?? []).first { $0["tag"]?.stringValue == "out-t1" }
            try expectEqual(vless?["streamSettings"]?["network"]?.stringValue, "ws", "network")
            try expectEqual(vless?["streamSettings"]?["security"]?.stringValue, "tls", "security")
        }

        h.check("состояние не мутируется") {
            let state = sampleState()
            let before = state.tunnels[0].outbound
            _ = XrayConfig.build(state: state, bypassInterface: "en0")
            try expect(state.tunnels[0].outbound == before, "outbound туннеля изменился")
        }

        h.check("старый WireGuard CIDR нормализуется при генерации") {
            var state = sampleState()
            state.tunnels[1].outbound["settings"]?["address"] = .array([
                .string("10.8.0.2/24"),
                .string("fdcc:ad94:bacf:61a4::2/64"),
            ])
            let config = XrayConfig.build(state: state, bypassInterface: "en0")
            let wireguard = (config["outbounds"]?.arrayValue ?? []).first {
                $0["tag"]?.stringValue == "out-t2"
            }
            let addresses = wireguard?["settings"]?["address"]?.arrayValue?
                .compactMap(\.stringValue)
            try expectEqual(
                addresses,
                ["10.8.0.2/32", "fdcc:ad94:bacf:61a4::2/128"],
                "Xray-compatible persisted addresses"
            )
        }

        h.check("WireGuard получает постоянный keepalive без перезаписи явного значения") {
            var state = sampleState()
            state.tunnels[1].outbound["settings"]?["peers"] = .array([
                .object(["endpoint": .string("wg-a.example.com:51820")]),
                .object([
                    "endpoint": .string("wg-b.example.com:51820"),
                    "keepAlive": .int(0),
                ]),
                .object([
                    "endpoint": .string("wg-c.example.com:51820"),
                    "keepAlive": .int(17),
                ]),
            ])
            let config = XrayConfig.build(state: state, bypassInterface: "en0")
            let wireguard = (config["outbounds"]?.arrayValue ?? []).first {
                $0["tag"]?.stringValue == "out-t2"
            }
            let keepAlives = wireguard?["settings"]?["peers"]?.arrayValue?
                .compactMap { $0["keepAlive"]?.intValue }
            try expectEqual(keepAlives, [25, 25, 17], "persistent keepalive")
        }

        h.check("без обхода sockopt не появляется") {
            let c = XrayConfig.build(state: sampleState(), bypassInterface: nil)
            for o in c["outbounds"]?.arrayValue ?? [] {
                try expect(o["streamSettings"]?["sockopt"] == nil, "лишняя привязка у \(o["tag"]?.stringValue ?? "?")")
            }
            try expect(c["dns"] == nil, "без обхода DNS-секции быть не должно")
        }

        // Регресс: при UseIP xray ждёт и A, и AAAA. У большинства серверов
        // туннелей AAAA нет — резолв считается неудачным и туннель не встаёт.
        h.check("queryStrategy не требует AAAA-записи") {
            let c = XrayConfig.build(state: sampleState(), bypassInterface: "en0")
            try expectEqual(c["dns"]?["queryStrategy"]?.stringValue, "UseIPv4", "queryStrategy")
        }

        // Регресс: без правила DNS уходит в туннель, и получается круговая
        // зависимость — резолв имени сервера идёт через ещё не поднятый туннель.
        h.check("DNS идёт мимо туннеля и правило первое") {
            let c = XrayConfig.build(state: sampleState(), bypassInterface: "en0")
            let rules = c["routing"]?["rules"]?.arrayValue ?? []
            guard let first = rules.first else { throw Failure("нет правил маршрутизации") }
            try expectEqual(first["inboundTag"]?[0]?.stringValue, "dns-bypass", "первое правило")
            try expectEqual(first["outboundTag"]?.stringValue, "direct", "DNS должен идти напрямую")
            try expectEqual(c["dns"]?["tag"]?.stringValue, "dns-bypass", "тег DNS совпадает с правилом")
        }

        h.check("в тестовом конфиге DNS тоже мимо туннеля") {
            let t = sampleState().tunnels[0]
            let c = XrayConfig.buildTest(tunnel: t, port: 10999, bypassInterface: "en0")
            let rules = c["routing"]?["rules"]?.arrayValue ?? []
            let dnsRule = rules.first { $0["inboundTag"]?[0]?.stringValue == "dns-bypass" }
            try expect(dnsRule != nil, "нет DNS-правила")
            try expectEqual(dnsRule?["outboundTag"]?.stringValue, "direct", "DNS напрямую")
            let out = (c["outbounds"]?.arrayValue ?? []).first { $0["tag"]?.stringValue == "test-out" }
            try expectEqual(out?["streamSettings"]?["sockopt"]?["interface"]?.stringValue, "en0", "привязка теста")
        }

        h.check("пакетный latency-тест связывает отдельный порт с каждым туннелем") {
            let state = sampleState()
            let c = XrayConfig.buildLatencyTests(
                tunnels: state.tunnels,
                ports: ["t1": 20_101, "t2": 20_102],
                bypassInterface: "en0"
            )
            let inbounds = c["inbounds"]?.arrayValue ?? []
            let outbounds = c["outbounds"]?.arrayValue ?? []
            let rules = c["routing"]?["rules"]?.arrayValue ?? []

            try expectEqual(inbounds.count, 2, "latency inbound")
            try expectEqual(
                Set(inbounds.compactMap { $0["port"]?.intValue }),
                Set([20_101, 20_102]),
                "latency ports"
            )
            for tunnel in state.tunnels {
                let outboundTag = "latency-out-\(tunnel.id)"
                let outbound = outbounds.first { $0["tag"]?.stringValue == outboundTag }
                let route = rules.first { $0["outboundTag"]?.stringValue == outboundTag }
                try expect(outbound != nil, "нет outbound \(tunnel.id)")
                try expectEqual(
                    outbound?["streamSettings"]?["sockopt"]?["interface"]?.stringValue,
                    "en0",
                    "bypass \(tunnel.id)"
                )
                try expectEqual(
                    route?["inboundTag"]?[0]?.stringValue,
                    "latency-in-\(tunnel.id)",
                    "route \(tunnel.id)"
                )
            }
        }

        h.check("inbound: socks с авторизацией и без") {
            var state = sampleState()
            state.proxies[0].auth = ProxyAuth(user: "u", pass: "p")
            let c = XrayConfig.build(state: state)
            let ins = c["inbounds"]?.arrayValue ?? []
            let socks = ins.first { $0["tag"]?.stringValue == "in-p1" }
            try expectEqual(socks?["settings"]?["auth"]?.stringValue, "password", "auth")
            try expectEqual(socks?["settings"]?["accounts"]?[0]?["user"]?.stringValue, "u", "логин")
            try expectEqual(socks?["settings"]?["udp"]?.boolValue, true, "udp для socks")

            let plain = XrayConfig.build(state: sampleState())
            let socksPlain = (plain["inbounds"]?.arrayValue ?? []).first { $0["tag"]?.stringValue == "in-p1" }
            try expectEqual(socksPlain?["settings"]?["auth"]?.stringValue, "noauth", "без логина")
        }

        h.check("выключенный прокси не попадает в конфиг") {
            var state = sampleState()
            state.proxies[1].enabled = false
            let c = XrayConfig.build(state: state)
            try expectEqual(c["inbounds"]?.arrayValue?.count, 1, "inbound'ов")
        }

        h.check("прокси без туннеля идёт напрямую") {
            var state = sampleState()
            state.proxies[0].tunnelId = nil
            let c = XrayConfig.build(state: state)
            let rules = c["routing"]?["rules"]?.arrayValue ?? []
            let rule = rules.first { $0["inboundTag"]?[0]?.stringValue == "in-p1" }
            try expectEqual(rule?["outboundTag"]?.stringValue, "direct", "должен идти напрямую")
        }

        h.check("профиль Россия напрямую ставит geo-правила перед туннелем") {
            var state = sampleState()
            state.proxies[0].routingMode = .directRussia

            let c = XrayConfig.build(state: state)
            let rules = (c["routing"]?["rules"]?.arrayValue ?? []).filter {
                $0["inboundTag"]?.arrayValue?.contains(.string("in-p1")) == true
            }

            try expectEqual(rules.count, 3, "правил для прокси")
            try expectEqual(rules[0]["domain"]?[0]?.stringValue, "geosite:category-ru", "доменное правило")
            try expectEqual(rules[0]["outboundTag"]?.stringValue, "direct", "RU-домены напрямую")
            try expectEqual(rules[1]["ip"]?[0]?.stringValue, "geoip:ru", "IP-правило")
            try expectEqual(rules[1]["outboundTag"]?.stringValue, "direct", "RU-IP напрямую")
            try expectEqual(rules[2]["outboundTag"]?.stringValue, "out-t1", "остальное через туннель")
            try expectEqual(c["routing"]?["domainStrategy"]?.stringValue, "IPIfNonMatch", "стратегия geoip")
        }

        h.check("профиль Всё напрямую не добавляет выбранный туннель") {
            var state = sampleState()
            state.proxies[0].routingMode = .directAll

            let c = XrayConfig.build(state: state)
            let rules = (c["routing"]?["rules"]?.arrayValue ?? []).filter {
                $0["inboundTag"]?.arrayValue?.contains(.string("in-p1")) == true
            }
            let outboundTags = (c["outbounds"]?.arrayValue ?? []).compactMap {
                $0["tag"]?.stringValue
            }

            try expectEqual(rules.count, 1, "правил для прокси")
            try expectEqual(rules[0]["outboundTag"]?.stringValue, "direct", "маршрут")
            try expect(!outboundTags.contains("out-t1"), "неиспользуемый туннель не должен попадать в конфиг")
        }

        h.check("системный VPN создаёт TUN и отправляет остальное в основной туннель") {
            var state = sampleState()
            state.systemVPN = SystemVPNConfiguration(tunnelId: "t1")

            let c = XrayConfig.build(
                state: state,
                bypassInterface: "en0",
                systemVPNInterface: "utun99"
            )
            let inbound = (c["inbounds"]?.arrayValue ?? []).first {
                $0["tag"]?.stringValue == XrayConfig.systemVPNTag
            }
            try expectEqual(inbound?["protocol"]?.stringValue, "tun", "protocol")
            try expectEqual(inbound?["settings"]?["name"]?.stringValue, "utun99", "utun")
            try expectEqual(inbound?["settings"]?["MTU"]?.intValue, 1500, "MTU")
            try expectEqual(inbound?["sniffing"]?["enabled"]?.boolValue, true, "sniffing")

            let rules = (c["routing"]?["rules"]?.arrayValue ?? []).filter {
                $0["inboundTag"]?.arrayValue?.contains(.string(XrayConfig.systemVPNTag)) == true
            }
            try expectEqual(rules.count, 2, "правил системного VPN")
            try expectEqual(rules[0]["ip"]?[0]?.stringValue, "geoip:private", "локальная сеть")
            try expectEqual(rules[0]["outboundTag"]?.stringValue, "direct", "локальная сеть напрямую")
            try expectEqual(rules[1]["outboundTag"]?.stringValue, "out-t1", "остальное в туннель")
            try expectEqual(c["routing"]?["domainStrategy"]?.stringValue, "AsIs", "domainStrategy")
        }

        h.check("системный VPN работает без локальных прокси") {
            var state = sampleState()
            state.proxies = []
            state.systemVPN = SystemVPNConfiguration(tunnelId: "t2")

            let c = XrayConfig.build(
                state: state,
                bypassInterface: "en0",
                systemVPNInterface: "utun98"
            )
            try expectEqual(c["inbounds"]?.arrayValue?.count, 1, "только TUN inbound")
            let tags = (c["outbounds"]?.arrayValue ?? []).compactMap { $0["tag"]?.stringValue }
            try expect(tags.contains("out-t2"), "выбранный системный туннель не добавлен")
        }

        h.check("локальный прокси можно включать одновременно с VPN") {
            var state = sampleState()
            state.systemVPN = SystemVPNConfiguration(tunnelId: "t2")

            let both = XrayConfig.build(
                state: state.configuredForRuntime(localProxiesEnabled: true),
                systemVPNInterface: "utun96"
            )
            let bothTags = (both["inbounds"]?.arrayValue ?? []).compactMap { $0["tag"]?.stringValue }
            try expect(bothTags.contains(XrayConfig.systemVPNTag), "нет TUN inbound")
            try expect(bothTags.contains("in-p1"), "нет локального proxy inbound")

            let vpnOnly = XrayConfig.build(
                state: state.configuredForRuntime(localProxiesEnabled: false),
                systemVPNInterface: "utun96"
            )
            let vpnOnlyTags = (vpnOnly["inbounds"]?.arrayValue ?? []).compactMap { $0["tag"]?.stringValue }
            try expectEqual(vpnOnlyTags, [XrayConfig.systemVPNTag], "глобальный переключатель прокси")
            try expectEqual(state.proxies[0].enabled, true, "runtime-переключатель не меняет сохранённое состояние")
        }

        h.check("системный VPN всегда использует выбранный основной туннель") {
            var state = sampleState()
            state.proxies = []
            state.systemVPN = SystemVPNConfiguration(tunnelId: "t1")

            let c = XrayConfig.build(
                state: state,
                bypassInterface: "en0",
                systemVPNInterface: "utun97"
            )
            let tags = (c["outbounds"]?.arrayValue ?? []).compactMap { $0["tag"]?.stringValue }
            try expect(tags.contains("out-t1"), "основной туннель отсутствует")
        }

        h.check("постоянный маршрут имеет приоритет над основным VPN и профилями прокси") {
            var state = sampleState()
            state.systemVPN = SystemVPNConfiguration(tunnelId: "t1")
            state.proxies[0].routingMode = .directAll
            state.persistentRoutes = [PersistentRoute(
                id: "r1",
                name: "Pinned",
                targets: "example.com\n1.1.1.0/24",
                tunnelId: "t2"
            )]

            let c = XrayConfig.build(
                state: state,
                bypassInterface: "en0",
                systemVPNInterface: "utun95"
            )
            let rules = c["routing"]?["rules"]?.arrayValue ?? []
            let pinnedDomain = rules.firstIndex {
                $0["domain"]?[0]?.stringValue == "domain:example.com"
                    && $0["outboundTag"]?.stringValue == "out-t2"
            }
            let privateDirect = rules.firstIndex {
                $0["ip"]?[0]?.stringValue == "geoip:private"
            }
            let proxyDirect = rules.firstIndex {
                $0["inboundTag"]?.arrayValue == [.string("in-p1")]
                    && $0["domain"] == nil
                    && $0["ip"] == nil
            }
            try expect(pinnedDomain != nil, "нет закреплённого домена")
            try expect(privateDirect != nil, "нет правила локальной сети")
            try expect(proxyDirect != nil, "нет обычного fallback прокси")
            try expect(pinnedDomain! < privateDirect!, "постоянный маршрут должен быть раньше private-direct")
            try expect(pinnedDomain! < proxyDirect!, "постоянный маршрут должен быть раньше профиля прокси")
            try expectEqual(c["routing"]?["domainStrategy"]?.stringValue, "IPIfNonMatch", "IP-маршрут требует resolve")
        }

        h.check("область постоянного маршрута разделяет VPN и локальные прокси") {
            var state = sampleState()
            state.systemVPN = SystemVPNConfiguration(tunnelId: "t1")
            state.persistentRoutes = [
                PersistentRoute(
                    id: "vpn-only", name: "VPN", targets: "vpn.example",
                    tunnelId: "t2", appliesToSystemVPN: true, appliesToLocalProxies: false
                ),
                PersistentRoute(
                    id: "proxy-only", name: "Proxy", targets: "proxy.example",
                    tunnelId: "t2", appliesToSystemVPN: false, appliesToLocalProxies: true
                ),
            ]

            let c = XrayConfig.build(state: state, systemVPNInterface: "utun94")
            let rules = c["routing"]?["rules"]?.arrayValue ?? []
            let vpnRule = rules.first { $0["domain"]?[0]?.stringValue == "domain:vpn.example" }
            let proxyRule = rules.first { $0["domain"]?[0]?.stringValue == "domain:proxy.example" }
            try expectEqual(
                vpnRule?["inboundTag"]?.arrayValue,
                [.string(XrayConfig.systemVPNTag)],
                "VPN-only область"
            )
            try expectEqual(
                proxyRule?["inboundTag"]?.arrayValue,
                [.string("in-p1"), .string("in-p2")],
                "proxy-only область"
            )
        }

        h.check("постоянный маршрут добавляет свой outbound рядом с основным VPN") {
            var state = sampleState()
            for index in state.proxies.indices {
                state.proxies[index].routingMode = .directAll
            }
            state.systemVPN = SystemVPNConfiguration(tunnelId: "t1")
            state.persistentRoutes = [PersistentRoute(
                id: "r-direct", name: "Override", targets: "203.0.113.7",
                tunnelId: "t2"
            )]

            let c = XrayConfig.build(state: state, systemVPNInterface: "utun93")
            let tags = (c["outbounds"]?.arrayValue ?? []).compactMap { $0["tag"]?.stringValue }
            try expect(tags.contains("out-t2"), "закреплённый туннель отсутствует")
            try expect(tags.contains("out-t1"), "основной туннель VPN отсутствует")
        }

        h.check("выключенные и потерявшие туннель постоянные маршруты безопасно пропускаются") {
            var state = sampleState()
            state.proxies = [state.proxies[0]]
            state.proxies[0].routingMode = .directAll
            state.persistentRoutes = [
                PersistentRoute(
                    id: "off", name: "Off", targets: "off.example",
                    tunnelId: "t2", enabled: false
                ),
                PersistentRoute(
                    id: "missing", name: "Missing", targets: "missing.example",
                    tunnelId: "does-not-exist"
                ),
            ]

            let c = XrayConfig.build(state: state)
            let rules = c["routing"]?["rules"]?.arrayValue ?? []
            try expect(rules.allSatisfy { $0["domain"] == nil }, "неактивное правило попало в конфиг")
            let tags = (c["outbounds"]?.arrayValue ?? []).compactMap { $0["tag"]?.stringValue }
            try expect(!tags.contains("out-t2"), "туннель выключенного правила не должен использоваться")
        }

        h.check("список постоянного маршрута разбирает домены, IP и ошибки") {
            let parsed = PersistentRouteTargets.parse("""
            # comment
            example.com
            *.example.com
            full:login.example.com
            192.0.2.1
            2001:db8::/32
            geoip:private
            999.1.1.1
            bad domain
            """)
            try expectEqual(
                parsed.domains,
                ["domain:example.com", "full:login.example.com"],
                "доменные цели и дедупликация"
            )
            try expectEqual(
                parsed.ips,
                ["192.0.2.1", "2001:db8::/32", "geoip:private"],
                "IP-цели"
            )
            try expectEqual(parsed.invalidLines.count, 2, "невалидные строки")
        }

        h.check("VPN-политики применяются по порядку до основного туннеля") {
            var state = sampleState()
            state.proxies = []
            state.systemVPN = SystemVPNConfiguration(tunnelId: "t1")
            state.vpnRoutingPolicies = [
                VPNRoutingPolicy(
                    id: "vr-direct",
                    name: "Direct services",
                    targets: "geosite:category-ru\nexample.com",
                    target: .direct
                ),
                VPNRoutingPolicy(
                    id: "vr-block",
                    name: "Blocked networks",
                    targets: "geoip:private\n203.0.113.0/24",
                    target: .block
                ),
            ]

            let c = XrayConfig.build(state: state, systemVPNInterface: "utun92")
            let rules = c["routing"]?["rules"]?.arrayValue ?? []
            let directIndex = rules.firstIndex {
                $0["domain"]?[0]?.stringValue == "geosite:category-ru"
                    && $0["outboundTag"]?.stringValue == "direct"
            }
            let blockIndex = rules.firstIndex {
                $0["ip"]?[0]?.stringValue == "geoip:private"
                    && $0["outboundTag"]?.stringValue == "block"
            }
            let builtInPrivateIndex = rules.lastIndex {
                $0["ip"]?[0]?.stringValue == "geoip:private"
                    && $0["outboundTag"]?.stringValue == "direct"
            }
            let defaultIndex = rules.firstIndex {
                $0["inboundTag"]?.arrayValue == [.string(XrayConfig.systemVPNTag)]
                    && $0["domain"] == nil
                    && $0["ip"] == nil
            }
            try expect(directIndex != nil && blockIndex != nil, "нет пользовательских правил")
            try expect(builtInPrivateIndex != nil && defaultIndex != nil, "нет базовых правил")
            try expect(directIndex! < blockIndex!, "порядок политик изменился")
            try expect(blockIndex! < builtInPrivateIndex!, "политика должна быть выше private-direct")
            try expect(builtInPrivateIndex! < defaultIndex!, "private-direct должен быть выше fallback")
            try expectEqual(c["routing"]?["domainStrategy"]?.stringValue, "IPIfNonMatch", "GeoIP требует resolve")
        }

        h.check("цепочка VPN сохраняет транспорт и связывает hop-ы") {
            var state = sampleState()
            state.proxies = []
            state.systemVPN = SystemVPNConfiguration(tunnelId: "t1")
            state.vpnTunnelChains = [
                VPNTunnelChain(id: "c1", name: "WG → VLESS", tunnelIds: ["t2", "t1"])
            ]
            state.vpnRoutingPolicies = [
                VPNRoutingPolicy(id: "vr-chain", name: "Chain", targets: "chain.example", target: .chain("c1"))
            ]

            let c = XrayConfig.build(
                state: state,
                bypassInterface: "en0",
                systemVPNInterface: "utun91"
            )
            let outbounds = c["outbounds"]?.arrayValue ?? []
            let first = outbounds.first { $0["tag"]?.stringValue == XrayConfig.tunnelTag("t2") }
            let exit = outbounds.first { $0["tag"]?.stringValue == XrayConfig.vpnChainTag("c1") }
            try expectEqual(first?["protocol"]?.stringValue, "wireguard", "первый hop")
            try expectEqual(first?["streamSettings"]?["sockopt"]?["interface"]?.stringValue, "en0", "bypass первого hop")
            try expectEqual(exit?["protocol"]?.stringValue, "vless", "выходной hop")
            try expectEqual(exit?["streamSettings"]?["network"]?.stringValue, "ws", "транспорт выхода")
            try expectEqual(exit?["proxySettings"]?["tag"]?.stringValue, XrayConfig.tunnelTag("t2"), "связь hop-ов")
            try expectEqual(exit?["proxySettings"]?["transportLayer"]?.boolValue, true, "transportLayer")
            let route = (c["routing"]?["rules"]?.arrayValue ?? []).first {
                $0["domain"]?[0]?.stringValue == "domain:chain.example"
            }
            try expectEqual(route?["outboundTag"]?.stringValue, XrayConfig.vpnChainTag("c1"), "назначение цепочки")
        }

        h.check("основной маршрут VPN может быть цепочкой") {
            var state = sampleState()
            state.proxies = []
            state.vpnTunnelChains = [
                VPNTunnelChain(id: "c-main", name: "WG → VLESS", tunnelIds: ["t2", "t1"])
            ]
            state.systemVPN = SystemVPNConfiguration(target: .chain("c-main"))

            let config = XrayConfig.build(
                state: state,
                bypassInterface: "en0",
                systemVPNInterface: "utun88"
            )
            let catchAll = (config["routing"]?["rules"]?.arrayValue ?? []).first {
                $0["inboundTag"]?.arrayValue == [.string(XrayConfig.systemVPNTag)]
                    && $0["domain"] == nil
                    && $0["ip"] == nil
            }
            try expectEqual(
                catchAll?["outboundTag"]?.stringValue,
                XrayConfig.vpnChainTag("c-main"),
                "catch-all цепочки"
            )
            let tags = (config["outbounds"]?.arrayValue ?? []).compactMap { $0["tag"]?.stringValue }
            try expect(tags.contains(XrayConfig.tunnelTag("t2")), "первый hop основного маршрута отсутствует")
            try expect(tags.contains(XrayConfig.vpnChainTag("c-main")), "выход цепочки отсутствует")
        }

        h.check("fallback создаёт приоритетные кандидаты и observatory") {
            var state = sampleState()
            state.proxies = []
            state.tunnels.append(Tunnel(
                id: "t3", name: "second vless", type: "vless", host: "b.example.com", port: 443,
                outbound: state.tunnels[0].outbound
            ))
            state.systemVPN = SystemVPNConfiguration(tunnelId: "t1")
            state.vpnTunnelChains = [
                VPNTunnelChain(id: "c1", name: "WG → VLESS → VLESS", tunnelIds: ["t2", "t1", "t3"])
            ]
            state.vpnFallbackGroups = [
                VPNFallbackGroup(
                    id: "f1",
                    name: "Primary + reserve",
                    members: [
                        VPNFallbackMember(id: "m1", target: .tunnel("t1")),
                        VPNFallbackMember(id: "m2", target: .chain("c1")),
                    ],
                    maxLatencyMs: 850,
                    finalAction: .block
                )
            ]
            state.vpnRoutingPolicies = [
                VPNRoutingPolicy(id: "vr-fallback", name: "Fallback", targets: "fallback.example", target: .fallback("f1"))
            ]

            let c = XrayConfig.build(
                state: state,
                bypassInterface: "en0",
                systemVPNInterface: "utun90"
            )
            let rule = (c["routing"]?["rules"]?.arrayValue ?? []).first {
                $0["domain"]?[0]?.stringValue == "domain:fallback.example"
            }
            try expectEqual(rule?["balancerTag"]?.stringValue, XrayConfig.vpnFallbackTag("f1"), "balancer rule")

            let balancer = c["routing"]?["balancers"]?[0]
            try expectEqual(balancer?["tag"]?.stringValue, XrayConfig.vpnFallbackTag("f1"), "balancer tag")
            try expectEqual(
                balancer?["fallbackTag"]?.stringValue,
                XrayConfig.tunnelTag("t1"),
                "мгновенный bootstrap через первый приоритет"
            )
            try expectEqual(
                balancer?["selector"]?.arrayValue,
                [.string(XrayConfig.tunnelTag("t1")), .string(XrayConfig.vpnChainTag("c1"))],
                "canonical fallback routes"
            )
            try expectEqual(balancer?["strategy"]?["type"]?.stringValue, "leastLoad", "strategy")
            try expectEqual(balancer?["strategy"]?["settings"]?["expected"]?.intValue, 1, "expected")
            try expectEqual(balancer?["strategy"]?["settings"]?["maxRTT"]?.stringValue, "850ms", "maxRTT")
            try expectEqual(balancer?["strategy"]?["settings"]?["costs"]?.arrayValue?.count, 2, "priority costs")
            try expectEqual(
                c["observatory"]?["subjectSelector"]?[0]?.stringValue,
                XrayConfig.tunnelTag("t1"),
                "observatory selector"
            )
            try expectEqual(c["observatory"]?["probeInterval"]?.stringValue, "3s", "probe interval")

            let outboundTags = (c["outbounds"]?.arrayValue ?? []).compactMap { $0["tag"]?.stringValue }
            try expectEqual(outboundTags.filter { $0 == XrayConfig.tunnelTag("t1") }.count, 1, "shared tunnel")
            try expectEqual(outboundTags.filter { $0 == XrayConfig.vpnChainTag("c1") }.count, 1, "shared chain")
            let internalChainTags = outboundTags.filter { $0.hasPrefix("vpn-chain-hop-c1-") }
            try expectEqual(internalChainTags.count, 1, "internal chain hop")
            try expect(
                internalChainTags.allSatisfy { !$0.hasPrefix(XrayConfig.vpnChainTag("c1")) },
                "balancer selector цепочки не должен захватывать её внутренние hop-ы"
            )
            let wireGuardOutbounds = (c["outbounds"]?.arrayValue ?? []).filter {
                $0["protocol"]?.stringValue == "wireguard"
            }
            try expectEqual(wireGuardOutbounds.count, 1, "WireGuard peer не должен дублироваться")
        }

        h.check("health telemetry системного VPN слушает только loopback") {
            var state = sampleState()
            state.proxies = []
            state.vpnFallbackGroups = [
                VPNFallbackGroup(
                    id: "f-metrics",
                    name: "Metrics",
                    members: [
                        VPNFallbackMember(id: "m1", target: .tunnel("t1")),
                        VPNFallbackMember(id: "m2", target: .tunnel("t2")),
                    ]
                )
            ]
            state.systemVPN = SystemVPNConfiguration(target: .fallback("f-metrics"))

            let config = XrayConfig.build(
                state: state,
                systemVPNInterface: "utun91",
                systemVPNAPIPort: 24_681,
                systemVPNMetricsPort: 24_682
            )
            try expectEqual(
                config["metrics"]?["listen"]?.stringValue,
                "127.0.0.1:24682",
                "metrics listen"
            )

            let withoutMetrics = XrayConfig.build(
                state: state,
                systemVPNInterface: "utun91",
                systemVPNAPIPort: 24_681
            )
            try expect(withoutMetrics["metrics"] == nil, "metrics появился без порта")
        }

        h.check("основной маршрут VPN может быть fallback-группой") {
            var state = sampleState()
            state.proxies = []
            state.vpnFallbackGroups = [
                VPNFallbackGroup(
                    id: "f-main",
                    name: "Основной + резерв",
                    members: [
                        VPNFallbackMember(id: "m-main", target: .tunnel("t1")),
                        VPNFallbackMember(id: "m-reserve", target: .tunnel("t2")),
                    ]
                )
            ]
            state.systemVPN = SystemVPNConfiguration(target: .fallback("f-main"))

            let config = XrayConfig.build(
                state: state,
                bypassInterface: "en0",
                systemVPNInterface: "utun87"
            )
            let catchAll = (config["routing"]?["rules"]?.arrayValue ?? []).first {
                $0["inboundTag"]?.arrayValue == [.string(XrayConfig.systemVPNTag)]
                    && $0["domain"] == nil
                    && $0["ip"] == nil
            }
            try expectEqual(
                catchAll?["balancerTag"]?.stringValue,
                XrayConfig.vpnFallbackTag("f-main"),
                "catch-all fallback"
            )
            try expectEqual(
                config["routing"]?["balancers"]?[0]?["tag"]?.stringValue,
                XrayConfig.vpnFallbackTag("f-main"),
                "balancer основного маршрута"
            )
            try expectEqual(
                config["observatory"]?["subjectSelector"]?[0]?.stringValue,
                XrayConfig.tunnelTag("t1"),
                "health-check основного fallback"
            )
        }

        h.check("невалидный основной маршрут VPN не становится Direct") {
            var state = sampleState()
            state.proxies = []
            state.vpnTunnelChains = [
                VPNTunnelChain(id: "disabled", name: "Выключена", tunnelIds: ["t1", "t2"], enabled: false)
            ]
            state.systemVPN = SystemVPNConfiguration(target: .chain("disabled"))

            let config = XrayConfig.build(state: state, systemVPNInterface: "utun86")
            let catchAll = (config["routing"]?["rules"]?.arrayValue ?? []).first {
                $0["inboundTag"]?.arrayValue == [.string(XrayConfig.systemVPNTag)]
                    && $0["domain"] == nil
                    && $0["ip"] == nil
            }
            try expectEqual(catchAll, nil, "битый маршрут не должен получить catch-all")
            try expectEqual(state.systemVPNMainRouteIssue(), "Цепочка выключена", "причина блокировки запуска")

            state.systemVPN = SystemVPNConfiguration(target: .direct)
            let directConfig = XrayConfig.build(state: state, systemVPNInterface: "utun86")
            let directCatchAll = (directConfig["routing"]?["rules"]?.arrayValue ?? []).first {
                $0["inboundTag"]?.arrayValue == [.string(XrayConfig.systemVPNTag)]
                    && $0["domain"] == nil
                    && $0["ip"] == nil
            }
            try expectEqual(directCatchAll, nil, "Direct нельзя использовать как основной маршрут")
        }

        h.check("битые VPN-топологии не создают случайный direct") {
            var state = sampleState()
            state.proxies = []
            state.systemVPN = SystemVPNConfiguration(tunnelId: "t1")
            state.vpnTunnelChains = [
                VPNTunnelChain(id: "broken", name: "Broken", tunnelIds: ["t1", "missing"])
            ]
            state.vpnRoutingPolicies = [
                VPNRoutingPolicy(id: "vr-broken", name: "Broken", targets: "broken.example", target: .chain("broken"))
            ]

            let c = XrayConfig.build(state: state, systemVPNInterface: "utun89")
            let rules = c["routing"]?["rules"]?.arrayValue ?? []
            try expect(
                !rules.contains { $0["domain"]?[0]?.stringValue == "domain:broken.example" },
                "битое правило попало в конфиг"
            )
            let tags = (c["outbounds"]?.arrayValue ?? []).compactMap { $0["tag"]?.stringValue }
            try expect(!tags.contains(XrayConfig.vpnChainTag("broken")), "битая цепочка попала в outbound")
        }

        h.check("VPN launcher передаёт каждый аргумент без shell") {
            let files = SystemVPNFiles(workDir: URL(fileURLWithPath: "/tmp/vpn dir"))
            let arguments = SystemVPNRuntime.launcherArguments(
                helperPath: "/Applications/Waypoint.app/Contents/Helpers/WaypointVPNHelper",
                arguments: ["--config", "/tmp/user's config.json"],
                files: files
            )
            try expectEqual(arguments[0], "--helper", "ключ helper")
            try expectEqual(arguments[1], "/Applications/Waypoint.app/Contents/Helpers/WaypointVPNHelper", "helper path")
            try expectEqual(arguments[2], "--log", "ключ log")
            try expectEqual(arguments[3], "/tmp/vpn dir/system-vpn.log", "log path")
            try expectEqual(arguments[6], "--", "конец launcher-аргументов")
            try expectEqual(arguments[8], "/tmp/user's config.json", "аргумент с апострофом")
        }

        h.check("ошибки авторизации VPN получают понятный текст") {
            let wrongPassword = SystemVPNRuntime.authorizationError(
                from: "execution error: Неверное имя или пароль. (-60005)"
            )
            let cancelled = SystemVPNRuntime.authorizationError(
                from: "WAYPOINT_AUTH_ERROR status=(-60006) stage=execute"
            )
            try expect(wrongPassword?.contains("установку VPN-сервиса") == true, "не распознан отказ авторизации")
            try expect(cancelled?.contains("отменена") == true, "не распознана отмена")
            try expect(SystemVPNRuntime.authorizationError(from: "unrelated") == nil, "ложное совпадение")
        }

        h.suite("состояние")

        h.check("Store атомарно возвращает last-confirmed состояние") {
            let directory = FileManager.default.temporaryDirectory
                .appendingPathComponent("waypoint-store-rollback-\(UUID().uuidString)", isDirectory: true)
            defer { try? FileManager.default.removeItem(at: directory) }
            let store = Store(workDir: directory)
            let confirmed = store.snapshot()
            store.mutate { $0.settings.logLevel = "debug" }
            store.replace(with: confirmed)
            try expectEqual(Store(workDir: directory).snapshot(), confirmed, "persisted rollback")
        }

        h.check("Waypoint переносит legacy state один раз и не копирует runtime-файлы") {
            let root = FileManager.default.temporaryDirectory
                .appendingPathComponent("waypoint-store-migration-\(UUID().uuidString)", isDirectory: true)
            let legacy = root.appendingPathComponent("legacy", isDirectory: true)
            let destination = root.appendingPathComponent("Waypoint", isDirectory: true)
            defer { try? FileManager.default.removeItem(at: root) }
            try FileManager.default.createDirectory(at: legacy, withIntermediateDirectories: true)

            var oldState = sampleState()
            oldState.settings.logLevel = "debug"
            let data = try JSONEncoder().encode(oldState)
            try data.write(to: legacy.appendingPathComponent("state.json"), options: .atomic)
            try Data("stale".utf8).write(to: legacy.appendingPathComponent("system-vpn.ready"))

            try expect(
                Store.migrateLegacyStateIfNeeded(from: legacy, to: destination),
                "первый перенос не выполнен"
            )
            try expectEqual(Store(workDir: destination).snapshot(), oldState, "перенесённое состояние")
            try expect(
                !FileManager.default.fileExists(
                    atPath: destination.appendingPathComponent("system-vpn.ready").path
                ),
                "runtime-маркер не должен переноситься"
            )

            var replacement = oldState
            replacement.settings.logLevel = "warning"
            try JSONEncoder().encode(replacement).write(
                to: legacy.appendingPathComponent("state.json"), options: .atomic
            )
            try expect(
                !Store.migrateLegacyStateIfNeeded(from: legacy, to: destination),
                "существующее состояние нельзя перезаписывать"
            )
            try expectEqual(Store(workDir: destination).snapshot(), oldState, "повторный перенос")
        }

        h.check("Settings читается без новых полей (старый state.json)") {
            let json = #"{"xrayPath":"","logLevel":"warning"}"#
            let s = try JSONDecoder().decode(Settings.self, from: Data(json.utf8))
            try expectEqual(s.bypassTunnels, true, "обход по умолчанию включён")
            try expectEqual(s.bypassInterface, "", "интерфейс по умолчанию пуст")
        }

        h.check("AppState читается из формата Electron-версии") {
            let json = """
            {"settings":{"xrayPath":"","logLevel":"warning"},
             "tunnels":[{"id":"t_1","name":"WG","type":"wireguard","host":"h","port":1,
                         "outbound":{"protocol":"wireguard","settings":{"mtu":1420}}}],
             "proxies":[{"id":"p_1","name":"s","kind":"socks","listen":"127.0.0.1",
                         "port":10808,"tunnelId":"t_1","enabled":true}]}
            """
            let st = try JSONDecoder().decode(AppState.self, from: Data(json.utf8))
            try expectEqual(st.tunnels.count, 1, "туннелей")
            try expectEqual(st.proxies.count, 1, "прокси")
            try expectEqual(st.subscriptions.count, 0, "старое состояние не должно создавать подписки")
            try expectEqual(st.systemVPN, SystemVPNConfiguration(), "старое состояние получает VPN-настройки")
            try expectEqual(st.persistentRoutes.count, 0, "старое состояние не должно создавать маршруты")
            try expectEqual(st.vpnRoutingPolicies.count, 0, "старое состояние не должно создавать VPN-политики")
            try expectEqual(st.vpnTunnelChains.count, 0, "старое состояние не должно создавать цепочки")
            try expectEqual(st.vpnFallbackGroups.count, 0, "старое состояние не должно создавать fallback")
            try expectEqual(st.tunnels[0].subscriptionId, nil, "старый туннель остаётся ручным")
            try expectEqual(st.tunnels[0].outbound["settings"]?["mtu"]?.intValue, 1420, "mtu из outbound")
            try expectEqual(st.proxies[0].kind, .socks, "тип прокси")
            try expectEqual(st.proxies[0].routingMode, .tunnelAll, "старый прокси сохраняет прежний маршрут")
        }

        h.check("старый прокси без туннеля мигрирует во Всё напрямую") {
            let json = """
            {"id":"p_direct","name":"direct","kind":"http","listen":"127.0.0.1",
             "port":10809,"enabled":true}
            """
            let proxy = try JSONDecoder().decode(LocalProxy.self, from: Data(json.utf8))
            try expectEqual(proxy.routingMode, .directAll, "профиль прямого прокси")
        }

        h.check("старый режим системного VPN игнорируется при чтении") {
            let json = #"{"tunnelId":"t1","routingMode":"directRussia"}"#
            let configuration = try JSONDecoder().decode(
                SystemVPNConfiguration.self,
                from: Data(json.utf8)
            )
            try expectEqual(configuration, SystemVPNConfiguration(target: .tunnel("t1")), "основной маршрут")

            let encoded = try JSONEncoder().encode(configuration)
            let object = try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
            try expect(object?["routingMode"] == nil, "устаревший режим снова записался в state")
            try expect(object?["tunnelId"] == nil, "устаревший tunnelId снова записался в state")
            let target = object?["target"] as? [String: Any]
            try expectEqual(target?["kind"] as? String, "tunnel", "тип мигрированного маршрута")
            try expectEqual(target?["referenceId"] as? String, "t1", "ссылка мигрированного маршрута")
        }

        h.check("новый основной маршрут проходит JSON round-trip без legacy-полей") {
            let original = SystemVPNConfiguration(target: .fallback("fallback-main"))
            let encoded = try JSONEncoder().encode(original)
            let decoded = try JSONDecoder().decode(SystemVPNConfiguration.self, from: encoded)
            try expectEqual(decoded, original, "round-trip основного маршрута")

            let object = try JSONSerialization.jsonObject(with: encoded) as? [String: Any]
            try expect(object?["target"] != nil, "новое поле target отсутствует")
            try expect(object?["tunnelId"] == nil, "state содержит legacy tunnelId")
            try expect(object?["routingMode"] == nil, "state содержит legacy routingMode")
        }

        h.suite("сетевые интерфейсы")

        h.check("туннельные имена распознаются") {
            for n in ["utun0", "utun29", "ipsec0", "ppp0", "wg0", "tun5"] {
                try expect(NetworkInterface.isTunnelName(n), "\(n) должен считаться туннелем")
            }
            for n in ["en0", "en1", "bridge0", "lo0"] {
                try expect(!NetworkInterface.isTunnelName(n), "\(n) не должен считаться туннелем")
            }
        }

        h.check("физический интерфейс определяется и не является туннелем") {
            let list = NetworkInterface.listPhysical()
            if list.isEmpty {
                print("    (нет активных интерфейсов — пропуск)")
                return
            }
            for n in list {
                try expect(!NetworkInterface.isTunnelName(n), "туннель \(n) попал в список физических")
            }
        }

        h.check("bypassStatus заполнен") {
            let st = NetworkInterface.bypassStatus()
            try expect(st.physical != nil || NetworkInterface.listPhysical().isEmpty, "нет физического интерфейса")
            _ = st.tunnels
            _ = st.tunnelCapturedRoute
        }

    }
}
