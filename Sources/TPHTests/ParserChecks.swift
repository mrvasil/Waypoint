import Foundation
import TPHCore

enum ParserChecks {
    static func run(_ h: Harness) {
        h.suite("парсеры")

        h.check("vless + reality + ws") {
            let link = "vless://11111111-2222-3333-4444-555555555555@example.com:443?type=ws&security=reality&pbk=PUBKEY&sid=ab12&path=%2Fws&host=cdn.example.com&flow=xtls-rprx-vision#My%20Node"
            let t = try Parsers.parseVless(link)
            try expectEqual(t.type, "vless", "тип")
            try expectEqual(t.host, "example.com", "хост")
            try expectEqual(t.port, 443, "порт")
            try expectEqual(t.name, "My Node", "имя")

            let user = t.outbound["settings"]?["vnext"]?[0]?["users"]?[0]
            try expectEqual(user?["id"]?.stringValue, "11111111-2222-3333-4444-555555555555", "uuid")
            try expectEqual(user?["flow"]?.stringValue, "xtls-rprx-vision", "flow")

            let ss = t.outbound["streamSettings"]
            try expectEqual(ss?["network"]?.stringValue, "ws", "транспорт")
            try expectEqual(ss?["security"]?.stringValue, "reality", "security")
            try expectEqual(ss?["realitySettings"]?["publicKey"]?.stringValue, "PUBKEY", "pbk")
            try expectEqual(ss?["realitySettings"]?["shortId"]?.stringValue, "ab12", "sid")
            try expectEqual(ss?["wsSettings"]?["path"]?.stringValue, "/ws", "ws path")
            try expectEqual(ss?["wsSettings"]?["headers"]?["Host"]?.stringValue, "cdn.example.com", "Host header")
        }

        h.check("vless + tcp + tls") {
            let t = try Parsers.parseVless("vless://uuid-here@1.2.3.4:8443?security=tls&sni=a.example.com&alpn=h2,http%2F1.1&fp=chrome")
            let ss = t.outbound["streamSettings"]
            try expectEqual(ss?["network"]?.stringValue, "tcp", "транспорт")
            try expectEqual(ss?["security"]?.stringValue, "tls", "security")
            try expectEqual(ss?["tlsSettings"]?["serverName"]?.stringValue, "a.example.com", "sni")
            try expectEqual(ss?["tlsSettings"]?["fingerprint"]?.stringValue, "chrome", "fp")
            try expectEqual(ss?["tlsSettings"]?["alpn"]?.arrayValue?.count, 2, "alpn")
            try expectEqual(t.name, "1.2.3.4:8443", "имя по умолчанию")
        }

        h.check("vmess base64 json") {
            let cfg = #"{"v":"2","ps":"Test VMess","add":"vm.example.com","port":"443","id":"aaaa-bbbb","aid":"0","scy":"auto","net":"ws","type":"none","host":"vm.example.com","path":"/path","tls":"tls","sni":"vm.example.com"}"#
            let t = try Parsers.parseVmess("vmess://" + Data(cfg.utf8).base64EncodedString())
            try expectEqual(t.name, "Test VMess", "имя")
            try expectEqual(t.host, "vm.example.com", "хост")
            try expectEqual(t.port, 443, "порт")

            let user = t.outbound["settings"]?["vnext"]?[0]?["users"]?[0]
            try expectEqual(user?["id"]?.stringValue, "aaaa-bbbb", "id")
            try expectEqual(user?["alterId"]?.intValue, 0, "alterId")

            let ss = t.outbound["streamSettings"]
            try expectEqual(ss?["network"]?.stringValue, "ws", "транспорт")
            try expectEqual(ss?["security"]?.stringValue, "tls", "security")
            try expectEqual(ss?["wsSettings"]?["path"]?.stringValue, "/path", "path")
        }

        h.check("trojan получает tls по умолчанию") {
            let t = try Parsers.parseTrojan("trojan://password123@tj.example.com:443#Trojan")
            try expectEqual(t.outbound["settings"]?["servers"]?[0]?["password"]?.stringValue, "password123", "пароль")
            try expectEqual(t.outbound["streamSettings"]?["security"]?.stringValue, "tls", "security по умолчанию")
        }

        h.check("shadowsocks: userinfo в base64") {
            let userinfo = Data("aes-256-gcm:mypassword".utf8).base64EncodedString()
            let t = try Parsers.parseShadowsocks("ss://\(userinfo)@ss.example.com:8388#SS%20Node")
            try expectEqual(t.name, "SS Node", "имя")
            try expectEqual(t.host, "ss.example.com", "хост")
            try expectEqual(t.port, 8388, "порт")
            let srv = t.outbound["settings"]?["servers"]?[0]
            try expectEqual(srv?["method"]?.stringValue, "aes-256-gcm", "метод")
            try expectEqual(srv?["password"]?.stringValue, "mypassword", "пароль")
        }

        h.check("shadowsocks: вся ссылка в base64") {
            let all = Data("chacha20-ietf-poly1305:pass@1.2.3.4:9999".utf8).base64EncodedString()
            let t = try Parsers.parseShadowsocks("ss://\(all)")
            try expectEqual(t.host, "1.2.3.4", "хост")
            try expectEqual(t.port, 9999, "порт")
            let srv = t.outbound["settings"]?["servers"]?[0]
            try expectEqual(srv?["method"]?.stringValue, "chacha20-ietf-poly1305", "метод")
        }

        h.check("socks и http как туннели") {
            let s = try Parsers.parseSocksHttp("socks5://user:pw@10.0.0.5:1080")
            try expectEqual(s.type, "socks", "тип")
            let u = s.outbound["settings"]?["servers"]?[0]?["users"]?[0]
            try expectEqual(u?["user"]?.stringValue, "user", "логин")
            try expectEqual(u?["pass"]?.stringValue, "pw", "пароль")

            let hp = try Parsers.parseSocksHttp("http://proxy.example.com:3128")
            try expectEqual(hp.type, "http", "тип")
            try expectEqual(hp.port, 3128, "порт")
            try expect(hp.outbound["settings"]?["servers"]?[0]?["users"] == nil, "без логина не должно быть users")
        }

        h.check("WireGuard из wg-quick") {
            let cfg = """
            [Interface]
            PrivateKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
            Address = 10.8.0.2/32, fdcc:ad94:bacf:61a4::cafe:2/128
            MTU = 1420

            [Peer]
            PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
            PresharedKey = AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=
            AllowedIPs = 0.0.0.0/0, ::/0
            Endpoint = vpn.example.com:51820
            """
            let t = try Parsers.parseWireguard(cfg)
            try expectEqual(t.host, "vpn.example.com", "хост endpoint")
            try expectEqual(t.port, 51820, "порт endpoint")

            let s = t.outbound["settings"]
            try expectEqual(s?["secretKey"]?.stringValue, "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", "secretKey")
            try expectEqual(s?["mtu"]?.intValue, 1420, "mtu")
            try expectEqual(s?["address"]?.arrayValue?.count, 2, "адреса")

            let peer = s?["peers"]?[0]
            try expectEqual(peer?["publicKey"]?.stringValue, "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=", "publicKey")
            try expectEqual(peer?["preSharedKey"]?.stringValue, "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=", "psk")
            try expectEqual(peer?["allowedIPs"]?.arrayValue?.count, 2, "allowedIPs")
        }

        h.check("WireGuard приводит адрес интерфейса к host prefix для Xray") {
            let cfg = """
            [Interface]
            PrivateKey = key==
            Address = 10.8.0.2/24, fdcc:ad94:bacf:61a4::2/64
            [Peer]
            PublicKey = pub==
            Endpoint = wg.example.com:51820
            """
            let tunnel = try Parsers.parseWireguard(cfg)
            let addresses = tunnel.outbound["settings"]?["address"]?.arrayValue?
                .compactMap(\.stringValue)
            try expectEqual(
                addresses,
                ["10.8.0.2/32", "fdcc:ad94:bacf:61a4::2/128"],
                "Xray-compatible addresses"
            )
        }

        h.check("WireGuard: endpoint IPv6 в скобках") {
            let cfg = """
            [Interface]
            PrivateKey = key==
            Address = 10.0.0.2/32
            [Peer]
            PublicKey = pub==
            Endpoint = [2001:db8::1]:51820
            """
            let t = try Parsers.parseWireguard(cfg)
            try expectEqual(t.host, "2001:db8::1", "IPv6 хост")
            try expectEqual(t.port, 51820, "порт")
        }

        h.check("WireGuard без PrivateKey — ошибка") {
            try expectThrows("нет PrivateKey") {
                _ = try Parsers.parseWireguard("[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = x")
            }
        }

        h.check("bulk: несколько ссылок построчно") {
            let text = """
            vless://uuid@a.example.com:443?security=tls#A
            trojan://pw@b.example.com:443#B
            не-ссылка-вообще
            """
            let r = Parsers.parseBulk(text)
            try expectEqual(r.tunnels.count, 2, "туннелей")
            try expectEqual(r.errors.count, 1, "ошибок")
            try expectEqual(r.tunnels[0].name, "A", "первый")
            try expectEqual(r.tunnels[1].name, "B", "второй")
        }

        h.check("bulk: base64-блок подписки") {
            let list = """
            vless://uuid@a.example.com:443?security=tls#Node1
            trojan://pw@b.example.com:443#Node2
            """
            let r = Parsers.parseBulk(Data(list.utf8).base64EncodedString())
            try expectEqual(r.tunnels.count, 2, "туннелей")
            try expectEqual(r.errors.count, 0, "ошибок")
        }

        h.check("bulk: целый конфиг WireGuard") {
            let r = Parsers.parseBulk("""
            [Interface]
            PrivateKey = abc=
            Address = 10.0.0.2/32
            [Peer]
            PublicKey = def=
            Endpoint = wg.example.com:51820
            """)
            try expectEqual(r.tunnels.count, 1, "туннелей")
            try expectEqual(r.tunnels[0].type, "wireguard", "тип")
        }

        h.check("base64 в urlsafe-варианте") {
            let original = "test?data+with/chars"
            let urlsafe = Data(original.utf8).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
            try expectEqual(Parsers.b64decode(urlsafe), original, "декодирование")
        }
    }
}
