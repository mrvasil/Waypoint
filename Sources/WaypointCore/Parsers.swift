import Foundation

/// Разбор внешних туннелей в xray-outbound'ы.
///
/// Поддержка: vless://, vmess:// (base64 JSON формата v2rayN), trojan://,
/// ss:// (оба формата), WireGuard (текст wg-quick), socks:// / http://,
/// и подписки — base64-список ссылок или обычный список.
public enum Parsers {

    public struct ParseFailure: LocalizedError {
        public let message: String
        public init(_ message: String) { self.message = message }
        public var errorDescription: String? { L10n.string(message) }
    }

    // MARK: - Хелперы

    /// base64 в обоих вариантах — urlsafe и обычный, с восстановлением паддинга.
    public static func b64decode(_ str: String) -> String? {
        var s = str.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        s = s.components(separatedBy: .whitespacesAndNewlines).joined()
        while s.count % 4 != 0 { s += "=" }
        guard let data = Data(base64Encoded: s) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    static func looksLikeBase64(_ str: String) -> Bool {
        let s = str.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty, !s.contains("://") else { return false }
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_-")
            .union(.whitespacesAndNewlines)
        return s.unicodeScalars.allSatisfy { allowed.contains($0) }
    }

    static func splitList(_ v: String?) -> [String]? {
        guard let v, !v.isEmpty else { return nil }
        let parts = v.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespaces)
        }.filter { !$0.isEmpty }
        return parts.isEmpty ? nil : parts
    }

    static func decodeName(_ hash: String) -> String {
        guard !hash.isEmpty else { return "" }
        return hash.removingPercentEncoding ?? hash
    }

    /// Query-параметры ссылки. URLComponents не декодирует "+" как пробел, что
    /// здесь и нужно: base64-значения (pbk, sid) содержат "+" как значащий символ.
    struct Query {
        private var items: [String: String] = [:]

        init(_ url: URL) {
            guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
                  let queryItems = comps.queryItems else { return }
            for item in queryItems where item.value != nil {
                items[item.name] = item.value
            }
        }

        init(_ dict: [String: String]) { items = dict }

        func get(_ key: String) -> String? {
            guard let v = items[key], !v.isEmpty else { return nil }
            return v
        }

        mutating func set(_ key: String, _ value: String) { items[key] = value }
    }

    // MARK: - streamSettings

    /// Общий строитель транспорта для vless / vmess / trojan.
    static func buildStreamSettings(_ q: Query, hostFallback: String) -> JSONValue {
        let rawNetwork = (q.get("type") ?? q.get("net") ?? "tcp").lowercased()
        var network = rawNetwork == "h2" ? "http" : rawNetwork
        let security = (q.get("security") ?? "none").lowercased()

        var ss: [String: JSONValue] = [:]

        // --- security ---
        let sni = q.get("sni") ?? q.get("peer") ?? q.get("host") ?? hostFallback
        let alpn = splitList(q.get("alpn"))
        let fp = q.get("fp")

        switch security {
        case "tls", "xtls":
            ss["security"] = .string("tls")
            let insecure = q.get("allowInsecure") == "1" || q.get("insecure") == "1"
            ss["tlsSettings"] = JSONValue.pruned([
                "serverName": sni.isEmpty ? nil : .string(sni),
                "alpn": alpn.map { .array($0.map { .string($0) }) },
                "fingerprint": fp.map { .string($0) },
                "allowInsecure": insecure ? .bool(true) : nil,
            ])
        case "reality":
            ss["security"] = .string("reality")
            ss["realitySettings"] = JSONValue.pruned([
                "serverName": sni.isEmpty ? nil : .string(sni),
                "fingerprint": .string(fp ?? "chrome"),
                "publicKey": q.get("pbk").map { .string($0) },
                "shortId": q.get("sid").map { .string($0) },
                "spiderX": q.get("spx").map { .string($0) },
            ])
        default:
            ss["security"] = .string("none")
        }

        // --- transport ---
        let path = q.get("path")
        let hostHeader = q.get("host")

        switch network {
        case "ws":
            ss["wsSettings"] = JSONValue.pruned([
                "path": .string(path ?? "/"),
                "host": hostHeader.map { .string($0) },
                "headers": hostHeader.map { .object(["Host": .string($0)]) },
            ])
        case "httpupgrade":
            ss["httpupgradeSettings"] = JSONValue.pruned([
                "path": .string(path ?? "/"),
                "host": hostHeader.map { .string($0) },
            ])
        case "xhttp", "splithttp":
            network = "xhttp"
            ss["xhttpSettings"] = JSONValue.pruned([
                "path": .string(path ?? "/"),
                "host": hostHeader.map { .string($0) },
                "mode": q.get("mode").map { .string($0) },
            ])
        case "grpc":
            let multi = (q.get("mode") ?? "") == "multi"
            ss["grpcSettings"] = JSONValue.pruned([
                "serviceName": .string(q.get("serviceName") ?? path ?? ""),
                "multiMode": multi ? .bool(true) : nil,
            ])
        case "http":
            ss["httpSettings"] = JSONValue.pruned([
                "path": .string(path ?? "/"),
                "host": hostHeader.map { .array([.string($0)]) },
            ])
        case "kcp":
            ss["kcpSettings"] = JSONValue.pruned([
                "header": .object(["type": .string(q.get("headerType") ?? "none")]),
                "seed": q.get("seed").map { .string($0) },
            ])
        case "quic":
            ss["quicSettings"] = JSONValue.pruned([
                "security": .string(q.get("quicSecurity") ?? "none"),
                "key": .string(q.get("key") ?? ""),
                "header": .object(["type": .string(q.get("headerType") ?? "none")]),
            ])
        default:
            network = "tcp"
            if q.get("headerType") == "http" {
                let request = JSONValue.pruned([
                    "path": .array([.string(path ?? "/")]),
                    "headers": hostHeader.map { .object(["Host": .array([.string($0)])]) },
                ])
                ss["tcpSettings"] = .object([
                    "header": .object(["type": .string("http"), "request": request])
                ])
            }
        }

        ss["network"] = .string(network)
        return .object(ss)
    }

    // MARK: - Протоколы

    public static func parseVless(_ link: String) throws -> Tunnel {
        guard let u = URL(string: link), let host = u.host, !host.isEmpty else {
            throw ParseFailure("vless: не удалось разобрать адрес")
        }
        let uuid = (u.user ?? "").removingPercentEncoding ?? ""
        guard !uuid.isEmpty else { throw ParseFailure("vless: не указан UUID") }
        let port = u.port ?? 443
        let q = Query(u)
        let name = decodeName(u.fragment ?? "").isEmpty ? "\(host):\(port)" : decodeName(u.fragment ?? "")

        let user = JSONValue.pruned([
            "id": .string(uuid),
            "encryption": .string(q.get("encryption") ?? "none"),
            "flow": q.get("flow").map { .string($0) },
        ])

        let outbound: JSONValue = .object([
            "protocol": .string("vless"),
            "settings": .object([
                "vnext": .array([
                    .object([
                        "address": .string(host),
                        "port": .int(port),
                        "users": .array([user]),
                    ])
                ])
            ]),
            "streamSettings": buildStreamSettings(q, hostFallback: host),
        ])

        return Tunnel(name: name, type: "vless", host: host, port: port, outbound: outbound)
    }

    public static func parseTrojan(_ link: String) throws -> Tunnel {
        guard let u = URL(string: link), let host = u.host, !host.isEmpty else {
            throw ParseFailure("trojan: не удалось разобрать адрес")
        }
        let password = (u.user ?? "").removingPercentEncoding ?? ""
        let port = u.port ?? 443
        var q = Query(u)
        // Для trojan security = tls по умолчанию.
        if q.get("security") == nil { q.set("security", "tls") }
        let name = decodeName(u.fragment ?? "").isEmpty ? "\(host):\(port)" : decodeName(u.fragment ?? "")

        let outbound: JSONValue = .object([
            "protocol": .string("trojan"),
            "settings": .object([
                "servers": .array([
                    .object([
                        "address": .string(host),
                        "port": .int(port),
                        "password": .string(password),
                    ])
                ])
            ]),
            "streamSettings": buildStreamSettings(q, hostFallback: host),
        ])

        return Tunnel(name: name, type: "trojan", host: host, port: port, outbound: outbound)
    }

    public static func parseVmess(_ link: String) throws -> Tunnel {
        let raw = String(link.dropFirst("vmess://".count))
        guard let json = b64decode(raw),
              let data = json.data(using: .utf8),
              let cfg = try? JSONDecoder().decode(JSONValue.self, from: data),
              let obj = cfg.objectValue else {
            throw ParseFailure("Не удалось разобрать vmess")
        }

        let host = obj["add"]?.stringValue ?? ""
        let port = obj["port"]?.intValue ?? 443
        guard !host.isEmpty else { throw ParseFailure("vmess: не указан адрес") }
        let name = obj["ps"]?.stringValue ?? "\(host):\(port)"

        // Псевдо-query для общего строителя транспорта.
        var params: [String: String] = [:]
        let net = obj["net"]?.stringValue ?? "tcp"
        params["type"] = net
        let tls = obj["tls"]
        let tlsOn = tls?.stringValue == "tls" || tls?.boolValue == true
        params["security"] = tlsOn ? "tls" : "none"
        if let v = obj["sni"]?.stringValue { params["sni"] = v }
        if let v = obj["host"]?.stringValue { params["host"] = v }
        if let v = obj["path"]?.stringValue { params["path"] = v }
        if let v = obj["type"]?.stringValue, net == "tcp" { params["headerType"] = v }
        if let v = obj["type"]?.stringValue, net == "grpc" { params["mode"] = v }
        if let v = obj["path"]?.stringValue, net == "grpc" { params["serviceName"] = v }
        if let v = obj["alpn"]?.stringValue { params["alpn"] = v }
        if let v = obj["fp"]?.stringValue { params["fp"] = v }

        let outbound: JSONValue = .object([
            "protocol": .string("vmess"),
            "settings": .object([
                "vnext": .array([
                    .object([
                        "address": .string(host),
                        "port": .int(port),
                        "users": .array([
                            .object([
                                "id": .string(obj["id"]?.stringValue ?? ""),
                                "alterId": .int(obj["aid"]?.intValue ?? 0),
                                "security": .string(obj["scy"]?.stringValue ?? "auto"),
                            ])
                        ]),
                    ])
                ])
            ]),
            "streamSettings": buildStreamSettings(Query(params), hostFallback: host),
        ])

        return Tunnel(name: name, type: "vmess", host: host, port: port, outbound: outbound)
    }

    public static func parseShadowsocks(_ link: String) throws -> Tunnel {
        // Форматы:
        //   ss://base64(method:password)@host:port#name
        //   ss://base64(method:password@host:port)#name
        var rest = String(link.dropFirst("ss://".count))
        var name = ""
        if let hashIdx = rest.firstIndex(of: "#") {
            name = decodeName(String(rest[rest.index(after: hashIdx)...]))
            rest = String(rest[..<hashIdx])
        }
        // plugin-параметры не поддерживаем — отбрасываем query.
        if let qIdx = rest.firstIndex(of: "?") {
            rest = String(rest[..<qIdx])
        }

        let method: String, password: String, host: String, port: Int

        func splitServer(_ server: String) throws -> (String, Int) {
            guard let lc = server.lastIndex(of: ":") else {
                throw ParseFailure("ss: не удалось разобрать адрес сервера")
            }
            let h = String(server[..<lc])
            guard let p = Int(server[server.index(after: lc)...]) else {
                throw ParseFailure("ss: некорректный порт")
            }
            return (h, p)
        }

        func splitUserinfo(_ userinfo: String) throws -> (String, String) {
            guard let ci = userinfo.firstIndex(of: ":") else {
                throw ParseFailure("ss: не удалось разобрать метод шифрования")
            }
            return (String(userinfo[..<ci]), String(userinfo[userinfo.index(after: ci)...]))
        }

        if let at = rest.lastIndex(of: "@") {
            let userinfoRaw = String(rest[..<at])
            let server = String(rest[rest.index(after: at)...])
            // userinfo может быть base64 или уже method:pass
            let userinfo = userinfoRaw.contains(":") ? userinfoRaw : (b64decode(userinfoRaw) ?? "")
            (method, password) = try splitUserinfo(userinfo)
            (host, port) = try splitServer(server)
        } else {
            guard let decoded = b64decode(rest) else {
                throw ParseFailure("ss: не удалось раскодировать ссылку")
            }
            guard let at = decoded.lastIndex(of: "@") else {
                throw ParseFailure("ss: не найден разделитель адреса")
            }
            (method, password) = try splitUserinfo(String(decoded[..<at]))
            (host, port) = try splitServer(String(decoded[decoded.index(after: at)...]))
        }

        let outbound: JSONValue = .object([
            "protocol": .string("shadowsocks"),
            "settings": .object([
                "servers": .array([
                    .object([
                        "address": .string(host),
                        "port": .int(port),
                        "method": .string(method),
                        "password": .string(password),
                    ])
                ])
            ]),
        ])

        return Tunnel(
            name: name.isEmpty ? "\(host):\(port)" : name,
            type: "shadowsocks", host: host, port: port, outbound: outbound
        )
    }

    public static func parseSocksHttp(_ link: String) throws -> Tunnel {
        guard let u = URL(string: link), let host = u.host, !host.isEmpty else {
            throw ParseFailure("Не удалось разобрать адрес прокси")
        }
        let proto = (u.scheme ?? "").lowercased()
        let isSocks = proto.hasPrefix("socks")
        let port = u.port ?? (isSocks ? 1080 : 8080)
        let fragment = decodeName(u.fragment ?? "")
        let name = fragment.isEmpty ? "\(proto)://\(host):\(port)" : fragment

        let user = u.user?.removingPercentEncoding
        let pass = u.password?.removingPercentEncoding

        let users: JSONValue? = (user?.isEmpty == false)
            ? .array([.object(["user": .string(user!), "pass": .string(pass ?? "")])])
            : nil

        let server = JSONValue.pruned([
            "address": .string(host),
            "port": .int(port),
            "users": users,
        ])

        let outbound: JSONValue = .object([
            "protocol": .string(isSocks ? "socks" : "http"),
            "settings": .object(["servers": .array([server])]),
        ])

        return Tunnel(
            name: name, type: isSocks ? "socks" : "http",
            host: host, port: port, outbound: outbound
        )
    }

    /// WireGuard из текста конфига wg-quick.
    public static func parseWireguard(_ text: String) throws -> Tunnel {
        var iface: [String: String] = [:]
        var peers: [[String: String]] = []
        var section: String?

        for rawLine in text.components(separatedBy: .newlines) {
            // Комментарии обрезаем, но только настоящие: "#" внутри значения
            // (например в пароле) не встречается в формате wg-quick.
            var line = rawLine
            if let hashIdx = line.firstIndex(of: "#") {
                line = String(line[..<hashIdx])
            }
            line = line.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { continue }

            let lower = line.lowercased()
            if lower == "[interface]" { section = "interface"; continue }
            if lower == "[peer]" { section = "peer"; peers.append([:]); continue }

            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let value = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)

            if section == "interface" {
                iface[key] = value
            } else if section == "peer", !peers.isEmpty {
                peers[peers.count - 1][key] = value
            }
        }

        guard let privateKey = iface["privatekey"], !privateKey.isEmpty else {
            throw ParseFailure("WireGuard: не найден PrivateKey в [Interface]")
        }
        guard !peers.isEmpty else {
            throw ParseFailure("WireGuard: не найдена секция [Peer]")
        }

        let address = (splitList(iface["address"]) ?? ["10.0.0.2/32"])
            .map(WireGuardAddress.normalized)

        let peersOut: [JSONValue] = peers.map { p in
            let allowed = splitList(p["allowedips"]) ?? ["0.0.0.0/0", "::/0"]
            return JSONValue.pruned([
                "publicKey": p["publickey"].map { .string($0) },
                "preSharedKey": p["presharedkey"].map { .string($0) },
                "endpoint": p["endpoint"].map { .string($0) },
                "allowedIPs": .array(allowed.map { .string($0) }),
                "keepAlive": p["persistentkeepalive"].flatMap { Int($0) }.map { .int($0) },
            ])
        }

        let firstEndpoint = peers[0]["endpoint"] ?? ""
        // Endpoint может быть IPv6 в скобках — [::1]:51820.
        let epHost: String
        let epPort: Int
        if firstEndpoint.hasPrefix("["), let close = firstEndpoint.firstIndex(of: "]") {
            epHost = String(firstEndpoint[firstEndpoint.index(after: firstEndpoint.startIndex)..<close])
            let after = firstEndpoint[firstEndpoint.index(after: close)...]
            epPort = Int(after.dropFirst()) ?? 0
        } else if let lc = firstEndpoint.lastIndex(of: ":") {
            epHost = String(firstEndpoint[..<lc])
            epPort = Int(firstEndpoint[firstEndpoint.index(after: lc)...]) ?? 0
        } else {
            epHost = firstEndpoint
            epPort = 0
        }

        let settings = JSONValue.pruned([
            "secretKey": .string(privateKey),
            "address": .array(address.map { .string($0) }),
            "peers": .array(peersOut),
            "mtu": .int(iface["mtu"].flatMap { Int($0) } ?? 1420),
        ])

        let outbound: JSONValue = .object([
            "protocol": .string("wireguard"),
            "settings": settings,
        ])

        let name = iface["name"] ?? "WireGuard \(epHost)".trimmingCharacters(in: .whitespaces)
        return Tunnel(name: name, type: "wireguard", host: epHost, port: epPort, outbound: outbound)
    }

    // MARK: - Диспетчер

    /// Разбирает одну ссылку. Бросает исключение при неудаче.
    public static func parseLink(_ link: String) throws -> Tunnel {
        let l = link.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !l.isEmpty else { throw ParseFailure("Пустая ссылка") }
        let lower = l.lowercased()

        if lower.hasPrefix("vless://") { return try parseVless(l) }
        if lower.hasPrefix("vmess://") { return try parseVmess(l) }
        if lower.hasPrefix("trojan://") { return try parseTrojan(l) }
        if lower.hasPrefix("ss://") { return try parseShadowsocks(l) }
        if lower.hasPrefix("socks://") || lower.hasPrefix("socks5://") { return try parseSocksHttp(l) }
        if lower.hasPrefix("http://") || lower.hasPrefix("https://") { return try parseSocksHttp(l) }
        if lower.contains("[interface]") || lower.contains("privatekey") { return try parseWireguard(l) }

        throw ParseFailure("Неизвестный формат ссылки/конфига")
    }

    /// Разбирает произвольный текст: одна ссылка, список ссылок по строкам,
    /// base64-блок подписки или конфиг WireGuard.
    public static func parseBulk(_ text: String) -> ParseResult {
        let input = text.trimmingCharacters(in: .whitespacesAndNewlines)
        var result = ParseResult()
        guard !input.isEmpty else { return result }

        // Целый конфиг WireGuard?
        if input.lowercased().contains("[interface]") {
            do {
                result.tunnels.append(try parseWireguard(input))
            } catch {
                result.errors.append(ParseError(line: "[WireGuard]", message: error.localizedDescription))
            }
            return result
        }

        // Возможно, это base64-блок подписки.
        var body = input
        let schemes = ["vless:", "vmess:", "trojan:", "ss:", "socks:", "http:", "https:"]
        let startsWithScheme = schemes.contains { input.lowercased().hasPrefix($0) }
        if looksLikeBase64(input), !startsWithScheme, let decoded = b64decode(input) {
            if schemes.contains(where: { decoded.lowercased().contains($0 + "//") }) {
                body = decoded
            }
        }

        let lines = body.components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("//") && !$0.hasPrefix("#") }

        for line in lines {
            do {
                result.tunnels.append(try parseLink(line))
            } catch {
                result.errors.append(
                    ParseError(line: String(line.prefix(60)), message: error.localizedDescription)
                )
            }
        }
        return result
    }

    /// Разбор уже скачанного тела подписки.
    public static func parseSubscriptionBody(_ body: String) -> ParseResult {
        parseBulk(body)
    }
}
