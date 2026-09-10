import Foundation

/// Отдельные physical path monitors наблюдают за реальным линком, а не за
/// default route через utun. Трекер сводит unavailable→available в одну смену
/// сети и не создаёт два последовательных transport refresh.
public struct PhysicalNetworkSignalTracker: Sendable {
    private var availability: [String: Bool] = [:]
    private var invalidatedWhileUnavailable: Set<String> = []

    public init() {}

    public var isAwaitingPathRecovery: Bool {
        !invalidatedWhileUnavailable.isEmpty
    }

    /// true означает, что сокеты предыдущего physical path больше нельзя
    /// считать рабочими.
    public mutating func observe(
        source: String,
        isAvailable: Bool,
        suppressStableAvailableChange: Bool = false
    ) -> Bool {
        guard let previous = availability[source] else {
            availability[source] = isAvailable
            return false
        }
        availability[source] = isAvailable

        if !isAvailable {
            guard previous else { return false }
            invalidatedWhileUnavailable.insert(source)
            return true
        }
        if !previous, invalidatedWhileUnavailable.remove(source) != nil {
            return false
        }

        // Required-interface monitor вызывает callback только при изменении
        // самого physical path. Даже при прежнем status старые transport-
        // сокеты должны быть обновлены.
        return !suppressStableAvailableChange
    }
}

/// Состояние короткого окна после события `NWPathMonitor`.
///
/// Системное событие часто приходит раньше обновления IP и gateway. Поэтому
/// старый или временно отсутствующий fingerprint не означает, что переход
/// завершён: окно продолжает опрос до появления нового готового пути.
public struct NetworkPathRecoveryWindow: Sendable {
    public enum Decision: Equatable, Sendable {
        case keepWatching
        case rebind(String)
    }

    public private(set) var confirmedFingerprint: String?
    private var pathWasUnavailable = false

    public init(confirmedFingerprint: String?) {
        self.confirmedFingerprint = confirmedFingerprint
    }

    /// Link loss invalidates transport sockets even when DHCP later restores
    /// exactly the same address and gateway.
    public mutating func markPathUnavailable() {
        pathWasUnavailable = true
    }

    public mutating func observe(_ fingerprint: String?) -> Decision {
        guard let fingerprint else {
            pathWasUnavailable = true
            return .keepWatching
        }
        guard pathWasUnavailable || fingerprint != confirmedFingerprint else {
            return .keepWatching
        }
        return .rebind(fingerprint)
    }

    public mutating func confirm(_ fingerprint: String) {
        confirmedFingerprint = fingerprint
        pathWasUnavailable = false
    }
}
