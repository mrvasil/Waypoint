import Foundation

public struct SystemVPNHotUpdate: Sendable, Equatable {
    public var addedOutbounds: [JSONValue]
    public var routing: JSONValue

    public init(addedOutbounds: [JSONValue], routing: JSONValue) {
        self.addedOutbounds = addedOutbounds
        self.routing = routing
    }
}

public enum SystemVPNConfigTransitionPlan: Sendable, Equatable {
    case hot(SystemVPNHotUpdate)
    case reload
}

public enum SystemVPNConfigTransition {
    public static func healthCheckOutboundTags(
        from activeRouting: JSONValue,
        to candidateRouting: JSONValue
    ) -> [String] {
        let activeRules = activeRouting["rules"]?.arrayValue ?? []
        let candidateRules = candidateRouting["rules"]?.arrayValue ?? []
        var seen = Set<String>()
        var result: [String] = []
        for rule in candidateRules where !activeRules.contains(rule) {
            guard let tag = rule["outboundTag"]?.stringValue,
                  tag != "direct", tag != "block", tag != XrayConfig.vpnAPITag,
                  seen.insert(tag).inserted else { continue }
            result.append(tag)
        }
        return result
    }

    public static func plan(
        from active: JSONValue,
        to candidate: JSONValue
    ) -> SystemVPNConfigTransitionPlan {
        guard var activeObject = active.objectValue,
              var candidateObject = candidate.objectValue,
              let routing = candidateObject["routing"],
              let activeOutbounds = activeObject["outbounds"]?.arrayValue,
              let candidateOutbounds = candidateObject["outbounds"]?.arrayValue,
              let activeByTag = outboundsByTag(activeOutbounds),
              let candidateByTag = outboundsByTag(candidateOutbounds) else { return .reload }

        activeObject.removeValue(forKey: "routing")
        candidateObject.removeValue(forKey: "routing")
        activeObject.removeValue(forKey: "outbounds")
        candidateObject.removeValue(forKey: "outbounds")
        guard activeObject == candidateObject else { return .reload }

        for (tag, candidateOutbound) in candidateByTag {
            if let activeOutbound = activeByTag[tag], activeOutbound != candidateOutbound {
                return .reload
            }
        }
        let added = candidateOutbounds.filter { outbound in
            guard let tag = outbound["tag"]?.stringValue else { return false }
            return activeByTag[tag] == nil
        }
        return .hot(SystemVPNHotUpdate(addedOutbounds: added, routing: routing))
    }

    private static func outboundsByTag(_ outbounds: [JSONValue]) -> [String: JSONValue]? {
        var result: [String: JSONValue] = [:]
        for outbound in outbounds {
            guard let tag = outbound["tag"]?.stringValue,
                  !tag.isEmpty,
                  result[tag] == nil else { return nil }
            result[tag] = outbound
        }
        return result
    }
}
