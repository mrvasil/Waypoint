import Foundation
import Darwin

enum WireGuardAddress {
    static let defaultPersistentKeepAlive = 25

    /// Repairs the malformed trailing zone marker produced by some imported
    /// WireGuard configs (`host:port%`). Xray accepts the config during
    /// preflight but later panics when that peer handles its first packet.
    /// A `%` inside a bracketed IPv6 address remains untouched.
    static func normalizedEndpoint(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let candidate = trimmed.replacingOccurrences(
            of: "%+$",
            with: "",
            options: .regularExpression
        )
        guard candidate != trimmed, isValidEndpoint(candidate) else { return trimmed }
        return candidate
    }

    private static func isValidEndpoint(_ value: String) -> Bool {
        let host: Substring
        let portText: Substring
        if value.hasPrefix("["), let close = value.firstIndex(of: "]") {
            host = value[value.index(after: value.startIndex)..<close]
            let suffix = value[value.index(after: close)...]
            guard suffix.first == ":" else { return false }
            portText = suffix.dropFirst()
        } else {
            guard let colon = value.lastIndex(of: ":") else { return false }
            host = value[..<colon]
            portText = value[value.index(after: colon)...]
        }
        guard !host.isEmpty,
              !portText.isEmpty,
              portText.allSatisfy(\.isNumber),
              let port = Int(portText) else { return false }
        return (1...65_535).contains(port)
    }

    /// Xray's userspace WireGuard device accepts interface host addresses only.
    /// wg-quick commonly stores the containing subnet, so preserve the IP while
    /// converting its prefix to /32 or /128. Invalid values remain unchanged and
    /// are rejected later by Xray preflight with the original diagnostic.
    static func normalized(_ value: String) -> String {
        let address = value.split(separator: "/", maxSplits: 1).first.map(String.init) ?? value
        var ipv4 = in_addr()
        if address.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            return "\(address)/32"
        }
        var ipv6 = in6_addr()
        if address.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            return "\(address)/128"
        }
        return value
    }

    static func normalizedOutbound(_ outbound: JSONValue) -> JSONValue {
        guard outbound["protocol"]?.stringValue == "wireguard",
              var settings = outbound["settings"] else { return outbound }
        if let addresses = settings["address"]?.arrayValue {
            settings["address"] = .array(addresses.map { value in
                guard let address = value.stringValue else { return value }
                return .string(normalized(address))
            })
        }
        if let peers = settings["peers"]?.arrayValue {
            settings["peers"] = .array(peers.map { peer in
                guard peer.objectValue != nil else { return peer }
                var patch: [String: JSONValue] = [:]
                if let endpoint = peer["endpoint"]?.stringValue {
                    let normalized = normalizedEndpoint(endpoint)
                    if normalized != endpoint {
                        patch["endpoint"] = .string(normalized)
                    }
                }
                if (peer["keepAlive"]?.intValue ?? 0) <= 0 {
                    patch["keepAlive"] = .int(defaultPersistentKeepAlive)
                }
                guard !patch.isEmpty else { return peer }
                return peer.merging(.object(patch))
            })
        }
        return outbound.merging(.object(["settings": settings]))
    }
}
