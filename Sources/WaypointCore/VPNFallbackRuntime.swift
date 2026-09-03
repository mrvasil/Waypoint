import Foundation

public struct VPNFallbackObservation: Sendable, Equatable {
    public var alive: Bool
    public var delayMs: Int
    public var lastTryTime: Int64

    public init(alive: Bool, delayMs: Int, lastTryTime: Int64) {
        self.alive = alive
        self.delayMs = delayMs
        self.lastTryTime = lastTryTime
    }
}

/// `/debug/vars` Xray metrics contains one bounded record per observed
/// outbound. It contains no user destinations or payload data.
public enum VPNFallbackMetricsParser {
    public static func parse(_ data: Data) -> [String: VPNFallbackObservation] {
        guard let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let observatory = root["observatory"] as? [String: Any] else { return [:] }

        var result: [String: VPNFallbackObservation] = [:]
        for (key, rawValue) in observatory {
            guard let value = rawValue as? [String: Any] else { continue }
            // protobuf's JSON tags omit a false boolean, so absence means the
            // observed route is dead rather than an invalid record.
            let alive = (value["alive"] as? Bool) ?? false
            let tag = (value["outbound_tag"] as? String)
                ?? (value["outboundTag"] as? String)
                ?? key
            guard !tag.isEmpty else { continue }
            let delay = integer(value["delay"]) ?? 99_999_999
            let lastTry = integer(value["last_try_time"])
                ?? integer(value["lastTryTime"])
                ?? 0
            result[tag] = VPNFallbackObservation(
                alive: alive,
                delayMs: Int(clamping: delay),
                lastTryTime: lastTry
            )
        }
        return result
    }

    private static func integer(_ value: Any?) -> Int64? {
        if let number = value as? NSNumber { return number.int64Value }
        if let string = value as? String { return Int64(string) }
        return nil
    }
}

public enum VPNFallbackSelection: Sendable, Equatable {
    case outbound(String)
    case terminal(String)

    public var outboundTag: String {
        switch self {
        case .outbound(let tag), .terminal(let tag): return tag
        }
    }
}

/// Sticky fallback controller layered over Xray's raw observatory samples.
/// The data plane remains inside the single Xray process; this controller only
/// changes the balancer override for new connections after confirmation.
public struct VPNFallbackStableSelector: Sendable {
    private struct Candidate: Sendable {
        var tag: String
        var index: Int
    }

    private let candidates: [Candidate]
    private let maximumDelayMs: Int
    private let terminalTag: String
    private var lastTryTimes: [String: Int64] = [:]
    private var proposalTag: String?
    private var proposalRounds = 0
    private var failedRounds = 0
    private var hasConfirmedSelected = false

    public private(set) var selectedOutboundTag: String

    public init(group: VPNFallbackGroup) {
        candidates = group.members.enumerated().map { index, member in
            Candidate(
                tag: XrayConfig.vpnFallbackMemberOutboundTag(member) ?? "",
                index: index
            )
        }.filter { !$0.tag.isEmpty }
        maximumDelayMs = group.maxLatencyMs
        terminalTag = group.finalAction == .direct ? "direct" : "block"
        selectedOutboundTag = candidates.first?.tag ?? terminalTag
    }

    /// Consumes only complete, fresh probe rounds. Concurrent probes can land
    /// in metrics at slightly different times; waiting for every candidate to
    /// advance prevents one partial round from counting twice.
    public mutating func consume(
        _ observations: [String: VPNFallbackObservation]
    ) -> VPNFallbackSelection? {
        guard !candidates.isEmpty else { return nil }
        for candidate in candidates {
            guard let observation = observations[candidate.tag],
                  observation.lastTryTime > (lastTryTimes[candidate.tag] ?? -1) else {
                return nil
            }
        }
        for candidate in candidates {
            lastTryTimes[candidate.tag] = observations[candidate.tag]?.lastTryTime
        }

        let best = bestCandidate(in: observations)
        let selectedIsCandidate = candidates.contains { $0.tag == selectedOutboundTag }
        let selectedIsHealthy = selectedIsCandidate
            && observations[selectedOutboundTag].map(isUsable) == true

        if selectedIsHealthy {
            hasConfirmedSelected = true
            failedRounds = 0
            guard let best, best != selectedOutboundTag else {
                resetProposal()
                return nil
            }
            return confirmProposal(best, terminal: false)
        }

        if !selectedIsCandidate {
            failedRounds = 0
            guard let best else {
                resetProposal()
                return nil
            }
            return confirmProposal(best, terminal: false)
        }

        // During initial bootstrap there is no known-good active route yet.
        // If the first complete observation already proves another route alive,
        // recover immediately instead of waiting through another dead window.
        if !hasConfirmedSelected, let best {
            return select(best, terminal: false)
        }

        failedRounds += 1
        resetProposal()
        guard failedRounds >= 2 else { return nil }
        if let best { return select(best, terminal: false) }
        return select(terminalTag, terminal: true)
    }

    private func bestCandidate(
        in observations: [String: VPNFallbackObservation]
    ) -> String? {
        candidates.compactMap { candidate -> (String, Double)? in
            guard let observation = observations[candidate.tag], isUsable(observation) else {
                return nil
            }
            // Matches Xray WeightManager: configured cost is 16^priority and
            // leastLoad applies sqrt(cost), therefore the effective factor is 4^priority.
            let score = Double(max(1, observation.delayMs)) * pow(4.0, Double(candidate.index))
            return (candidate.tag, score)
        }.min { lhs, rhs in
            if lhs.1 != rhs.1 { return lhs.1 < rhs.1 }
            return lhs.0 < rhs.0
        }?.0
    }

    private func isUsable(_ observation: VPNFallbackObservation) -> Bool {
        observation.alive
            && observation.delayMs >= 0
            && observation.delayMs <= maximumDelayMs
    }

    private mutating func confirmProposal(
        _ tag: String,
        terminal: Bool
    ) -> VPNFallbackSelection? {
        if proposalTag == tag {
            proposalRounds += 1
        } else {
            proposalTag = tag
            proposalRounds = 1
        }
        guard proposalRounds >= 2 else { return nil }
        return select(tag, terminal: terminal)
    }

    private mutating func select(
        _ tag: String,
        terminal: Bool
    ) -> VPNFallbackSelection {
        selectedOutboundTag = tag
        hasConfirmedSelected = !terminal
        failedRounds = 0
        resetProposal()
        return terminal ? .terminal(tag) : .outbound(tag)
    }

    private mutating func resetProposal() {
        proposalTag = nil
        proposalRounds = 0
    }
}

public enum VPNFallbackRuntimePhase: String, Sendable, Equatable {
    case warming
    case active
    case terminal
}

/// Неперсистентный снимок фактического выбора Xray leastLoad-balancer.
/// Статус относится к новым соединениям: уже открытые потоки не мигрируют
/// между outbound до переподключения.
public struct VPNFallbackRuntimeStatus: Sendable, Equatable {
    public var groupID: String
    public var selectedMemberID: String?
    public var selectedOutboundTag: String
    public var updatedAt: Date
    public var phase: VPNFallbackRuntimePhase

    public init(
        groupID: String,
        selectedMemberID: String?,
        selectedOutboundTag: String,
        updatedAt: Date = Date(),
        phase: VPNFallbackRuntimePhase = .active
    ) {
        self.groupID = groupID
        self.selectedMemberID = selectedMemberID
        self.selectedOutboundTag = selectedOutboundTag
        self.updatedAt = updatedAt
        self.phase = phase
    }

    public static func parse(
        group: VPNFallbackGroup,
        xrayOutput: String,
        now: Date = Date()
    ) -> VPNFallbackRuntimeStatus? {
        guard let outboundTag = XrayBalancerInfoParser.selectedOutboundTag(from: xrayOutput) else {
            return nil
        }
        let memberID = group.members.enumerated().first { index, member in
            XrayConfig.vpnFallbackMemberOutboundTag(member) == outboundTag
        }?.element.id

        return VPNFallbackRuntimeStatus(
            groupID: group.id,
            selectedMemberID: memberID,
            selectedOutboundTag: outboundTag,
            updatedAt: now
        )
    }
}

/// `xray api bi` выводит компактную таблицу. Разбор ограничен секцией Selects,
/// чтобы пустой override никогда не принимался за активный outbound.
public enum XrayBalancerInfoParser {
    public static func selectedOutboundTag(from output: String) -> String? {
        let lines = output.components(separatedBy: .newlines)
        guard let start = lines.firstIndex(where: {
            $0.trimmingCharacters(in: .whitespaces) == "- Selects:"
        }) else { return nil }

        for line in lines.dropFirst(start + 1) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("- ") { break }
            let columns = trimmed.split(whereSeparator: \Character.isWhitespace)
            guard columns.count >= 2, Int(columns[0]) != nil else { continue }
            return String(columns[1])
        }
        return nil
    }
}
