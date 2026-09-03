import Foundation
import Darwin

enum WireGuardAddress {
    static let defaultPersistentKeepAlive = 25

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
                guard peer.objectValue != nil,
                      (peer["keepAlive"]?.intValue ?? 0) <= 0 else { return peer }
                return peer.merging(.object([
                    "keepAlive": .int(defaultPersistentKeepAlive),
                ]))
            })
        }
        return outbound.merging(.object(["settings": settings]))
    }
}
