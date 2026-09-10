import Foundation
import Network
import SwiftUI
import WaypointCore

struct AppToast: Identifiable, Equatable {
    enum Tone: Equatable {
        case success
        case warning
        case error
    }

    let id = UUID()
    let text: String
    let tone: Tone
}

private struct SubscriptionLoadError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

/// Состояние приложения для интерфейса.
///
/// @MainActor: все свойства читает SwiftUI, поэтому меняются они только на
/// главном потоке; тяжёлые операции уходят в actor Engine.
@MainActor
@Observable
final class AppModel {
    private(set) var state: AppState
    private(set) var status = EngineStatus()
    private(set) var logs: [LogEntry] = []
    private(set) var bypass: BypassInfo?
    private(set) var xrayVersion: String?
    private(set) var xrayPath: String?
    /// Живой выбор Xray fallback-balancer; в state.json не сохраняется.
    private(set) var fallbackRuntimeStatuses: [String: VPNFallbackRuntimeStatus] = [:]
    private var configurationGeneration = 0
    private var lastConfirmedState: AppState
    private var configurationApplyTask: Task<Void, Never>?

    /// Результаты теста туннелей по id — показываются прямо в карточке.
    private(set) var testResults: [String: TunnelTestResult] = [:]
    private(set) var testingTunnelIds: Set<String> = []
    private(set) var isRefreshingTunnelLatencies = false

    /// Временное состояние подписок не сохраняется в state.json.
    private(set) var refreshingSubscriptionIds: Set<String> = []
    private(set) var subscriptionErrors: [String: String] = [:]

    private(set) var toast: AppToast?
    private(set) var localProxyRequested = false

    private let store: Store
    private let engine: Engine
    private var networkWatchTask: Task<Void, Never>?
    private var networkEventTask: Task<Void, Never>?
    private var networkEventGeneration = 0
    private var networkRebindInFlight: String?
    private var networkPathMonitors: [NWPathMonitor] = []
    private var physicalNetworkSignalTracker = PhysicalNetworkSignalTracker()
    private var networkWatchInitialized = false
    private var suppressStablePhysicalPathEventsUntil = Date.distantPast
    private var lastNetworkPathAvailable: Bool?
    private var lastPhysicalPathAvailable: Bool?
    private var networkPathInterruptionGeneration = 0
    private var recoveredNetworkPathInterruptionGeneration = 0
    private let networkMonitorQueue = DispatchQueue(
        label: "ru.mrvasil.waypoint.network-path",
        qos: .utility
    )
    private var subscriptionUpdateTask: Task<Void, Never>?
    private var latencyRefreshTask: Task<Void, Never>?
    private var latencyOperationGeneration = 0
    private var toastDismissTask: Task<Void, Never>?
    private var lastKnownNetworkPath: String?

    init() {
        let store = Store()
        let persistedState = store.snapshot()
        var initialState = persistedState
        if initialState.systemVPN.target == nil,
           let firstTunnelID = initialState.tunnels.first?.id {
            initialState.systemVPN.target = .tunnel(firstTunnelID)
        }
        initialState.pruneFavoriteTunnelIDs()
        _ = VPNQuickRoutes.synchronizeWhitelist(in: &initialState)
        if initialState != persistedState {
            store.replace(with: initialState)
        }
        self.store = store
        self.state = initialState
        self.lastConfirmedState = initialState
        self.engine = Engine(workDir: store.workDir)

        // Подписки навешиваются после инициализации: замыкания @Sendable не
        // могут захватывать ещё не построенный self.
        Task { await connect() }
    }

    /// Связывает движок с моделью и запускает наблюдение за сетью.
    private func connect() async {
        await engine.onLogs { entries in
            Task { @MainActor [weak self] in self?.logs = entries }
        }
        await engine.onStatus { st in
            Task { @MainActor [weak self] in
                guard let self else { return }
                let previousError = self.status.lastError
                self.status = st
                if let error = st.lastError, error != previousError {
                    self.presentToast(error, tone: .error)
                }
            }
        }
        await engine.onFallbackStatuses { statuses in
            Task { @MainActor [weak self] in
                self?.fallbackRuntimeStatuses = statuses
            }
        }
        await refreshXrayInfo()
        refreshBypass()
        startNetworkWatch()
        startSubscriptionUpdates()
    }

    // MARK: - Сведения об окружении

    private func refreshXrayInfo() async {
        let path = engine.resolveXrayPath(preferred: state.settings.xrayPath)
        xrayPath = path
        xrayVersion = path.flatMap { engine.version(of: $0) }
    }

    func refreshBypass() {
        bypass = engine.bypassInfo(for: state.settings)
    }

    // MARK: - Слежение за сменой сети

    /// Привязка к интерфейсу жёсткая: если Wi-Fi сменился на Ethernet или
    /// интерфейс переподнялся, привязка к старому имени оставит xray без сети.
    /// NWPath будит fail-closed rebind, а редкий poll страхует пропущенные events.
    private func startNetworkWatch() {
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            Task { @MainActor [weak self] in
                self?.networkPathDidUpdate(isAvailable: path.status == .satisfied)
            }
        }
        monitor.start(queue: networkMonitorQueue)
        networkPathMonitors.append(monitor)

        // Full-tunnel utun может оставлять общий NWPath в состоянии satisfied,
        // даже когда Wi-Fi уже отключён. Эти monitors следят именно за
        // физическими путями и видят смену Wi-Fi даже с прежними IP/gateway.
        startPhysicalNetworkMonitor(source: "wifi", type: .wifi)
        startPhysicalNetworkMonitor(source: "wired", type: .wiredEthernet)

        networkWatchTask = Task { [weak self] in
            guard let self else { return }
            let preferred = self.state.settings.bypassInterface
            let initialPath = await Task.detached(priority: .utility) {
                NetworkInterface.physicalPathFingerprint(
                    interface: preferred.isEmpty ? nil : preferred
                )
            }.value
            self.lastKnownNetworkPath = initialPath
            self.lastPhysicalPathAvailable = initialPath != nil
            self.networkWatchInitialized = true

            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 4_000_000_000)
                await self.checkNetworkChange()
            }
        }
    }

    private func startPhysicalNetworkMonitor(
        source: String,
        type: NWInterface.InterfaceType
    ) {
        let monitor = NWPathMonitor(requiredInterfaceType: type)
        monitor.pathUpdateHandler = { [weak self] path in
            let isAvailable = path.status == .satisfied
            Task { @MainActor [weak self] in
                self?.physicalNetworkPathDidUpdate(
                    source: source,
                    isAvailable: isAvailable
                )
            }
        }
        monitor.start(queue: networkMonitorQueue)
        networkPathMonitors.append(monitor)
    }

    private func networkPathDidUpdate(isAvailable: Bool) {
        guard networkWatchInitialized else {
            lastNetworkPathAvailable = isAvailable
            return
        }
        if !isAvailable, lastNetworkPathAvailable != false {
            networkPathInterruptionGeneration &+= 1
        }
        lastNetworkPathAvailable = isAvailable
        // На unavailable старый DHCP route ещё может быть в таблице. Ждём
        // available callback и переносим VPN сразу на уже готовый path.
        if isAvailable { scheduleNetworkEventCheck() }
    }

    private func physicalNetworkPathDidUpdate(source: String, isAvailable: Bool) {
        let invalidatesTransport = physicalNetworkSignalTracker.observe(
            source: source,
            isAvailable: isAvailable,
            suppressStableAvailableChange: Date() < suppressStablePhysicalPathEventsUntil
        )
        guard networkWatchInitialized else { return }
        if invalidatesTransport {
            networkPathInterruptionGeneration &+= 1
        }
        if isAvailable { scheduleNetworkEventCheck() }
    }

    private func scheduleNetworkEventCheck() {
        networkEventGeneration &+= 1
        guard networkEventTask == nil else { return }
        networkEventTask = Task { [weak self] in
            guard let self else { return }
            while !Task.isCancelled {
                let generation = self.networkEventGeneration
                await self.runNetworkRecoveryWindow()
                guard self.networkEventGeneration != generation else { break }
            }
            self.networkEventTask = nil
        }
    }

    /// `NWPath` часто приходит до DHCP/route update. Неизменившийся первый
    /// snapshot больше не завершает recovery: несколько раз проверяем путь в
    /// течение переходного окна, не сбрасывая таймер новыми событиями.
    private func runNetworkRecoveryWindow() async {
        var window = NetworkPathRecoveryWindow(confirmedFingerprint: lastKnownNetworkPath)
        // Интервалы, а не абсолютные offsets: в первые полсекунды после Wi-Fi
        // проверяем часто, затем реже ждём завершения DHCP.
        let delaysMilliseconds = [0, 50, 100, 150, 200, 300, 450, 650, 900, 1_200]

        for delay in delaysMilliseconds where !Task.isCancelled {
            if delay > 0 {
                do {
                    try await Task.sleep(for: .milliseconds(delay))
                } catch {
                    return
                }
            }
            let current = await currentNetworkFingerprint()
            recordPhysicalPathAvailability(current != nil)
            let interruptionGeneration = networkPathInterruptionGeneration
            let forceRebind = interruptionGeneration != recoveredNetworkPathInterruptionGeneration
            let stillShowsStalePath = physicalNetworkSignalTracker.isAwaitingPathRecovery
                && current == lastKnownNetworkPath
            if stillShowsStalePath { continue }
            if forceRebind {
                window.markPathUnavailable()
            }
            switch window.observe(current) {
            case .keepWatching:
                break
            case .rebind(let fingerprint):
                if await handleNetworkChange(to: fingerprint, forceRebind: forceRebind) {
                    window.confirm(fingerprint)
                    recoveredNetworkPathInterruptionGeneration = interruptionGeneration
                    return
                }
            }
        }
    }

    private func currentNetworkFingerprint() async -> String? {
        // networksetup/route are synchronous processes. Running them on the
        // MainActor every four seconds made the whole SwiftUI window hitch.
        let preferred = state.settings.bypassInterface
        return await Task.detached(priority: .utility) {
            NetworkInterface.physicalPathFingerprint(
                interface: preferred.isEmpty ? nil : preferred
            )
        }.value
    }

    private func checkNetworkChange() async {
        let fingerprint = await currentNetworkFingerprint()
        recordPhysicalPathAvailability(fingerprint != nil)
        guard let current = fingerprint else { return }
        let interruptionGeneration = networkPathInterruptionGeneration
        let forceRebind = interruptionGeneration != recoveredNetworkPathInterruptionGeneration
        if forceRebind,
           physicalNetworkSignalTracker.isAwaitingPathRecovery,
           current == lastKnownNetworkPath {
            return
        }
        if await handleNetworkChange(to: current, forceRebind: forceRebind) {
            recoveredNetworkPathInterruptionGeneration = interruptionGeneration
        }
    }

    private func recordPhysicalPathAvailability(_ isAvailable: Bool) {
        if !isAvailable, lastPhysicalPathAvailable != false {
            networkPathInterruptionGeneration &+= 1
        }
        lastPhysicalPathAvailable = isAvailable
    }

    @discardableResult
    private func handleNetworkChange(to current: String, forceRebind: Bool = false) async -> Bool {
        guard forceRebind || current != lastKnownNetworkPath else { return true }
        guard networkRebindInFlight != current else { return false }
        networkRebindInFlight = current
        defer {
            if networkRebindInFlight == current { networkRebindInFlight = nil }
        }

        cancelTunnelLatencyTests()
        testResults.removeAll()

        refreshBypass()
        guard await engine.isRunning() else {
            lastKnownNetworkPath = current
            refreshTunnelLatenciesIfNeeded()
            return true
        }
        let activeMode = await engine.status().mode
        // Системный VPN всегда привязан к physical interface независимо от
        // пользовательского переключателя обхода локального proxy. Поэтому
        // смену gateway нельзя игнорировать, когда bypassTunnels выключен.
        if activeMode != .systemVPN, !state.settings.bypassTunnels {
            lastKnownNetworkPath = current
            return true
        }
        do {
            suppressStablePhysicalPathEvents(for: 3)
            try await engine.reconnectForNetworkChange(
                state: runtimeState,
                settings: state.settings
            )
            lastKnownNetworkPath = current
            return true
        } catch {
            presentToast(error.localizedDescription, tone: .error)
            // Не подтверждаем fingerprint: следующий event/poll повторит
            // перенос, сохраняя /1 kill-switch маршруты на utun.
            return false
        }
    }

    // MARK: - Мутации состояния

    @discardableResult
    private func apply<T>(restart: Bool = true, _ body: (inout AppState) -> T) -> T {
        let result = store.mutate(body)
        state = store.snapshot()
        if restart {
            configurationGeneration &+= 1
            scheduleConfigurationApply()
        }
        return result
    }

    /// Все быстрые UI-мутации сводятся в одну последовательную очередь. Без
    /// этого actor reentrancy позволяла второму reload переписать candidate/result
    /// файлы, пока первый ещё ждал подтверждение privileged helper.
    private func scheduleConfigurationApply() {
        guard configurationApplyTask == nil else { return }
        configurationApplyTask = Task { [weak self] in
            await self?.drainConfigurationApplies()
        }
    }

    private func drainConfigurationApplies() async {
        while !Task.isCancelled {
            let generation = configurationGeneration
            await restartIfRunning(
                requestedState: runtimeState,
                requestedSettings: state.settings,
                requestedPersistedState: state,
                generation: generation
            )
            guard configurationGeneration != generation else { break }
        }
        configurationApplyTask = nil
    }

    private func restartIfRunning(
        requestedState: AppState? = nil,
        requestedSettings: WaypointCore.Settings? = nil,
        requestedPersistedState: AppState? = nil,
        generation: Int? = nil
    ) async {
        let persistedState = requestedPersistedState ?? state
        guard await engine.isRunning() else {
            lastConfirmedState = persistedState
            return
        }
        do {
            try await engine.restart(
                state: requestedState ?? runtimeState,
                settings: requestedSettings ?? state.settings
            )
            lastConfirmedState = persistedState
        } catch {
            if let generation,
               configurationGeneration == generation,
               await engine.status().mode == .systemVPN {
                store.replace(with: lastConfirmedState)
                state = store.snapshot()
                refreshBypass()
            }
            presentToast(error.localizedDescription, tone: .error)
        }
    }

    private var runtimeState: AppState {
        state.configuredForRuntime(localProxiesEnabled: localProxyRequested)
    }

    // MARK: - Туннели

    func addTunnels(_ tunnels: [Tunnel]) {
        guard !tunnels.isEmpty else { return }
        apply { state in
            state.tunnels.append(contentsOf: tunnels)
            if state.systemVPN.target == nil {
                state.systemVPN.target = state.tunnels.first.map { .tunnel($0.id) }
            }
        }
        presentToast(
            tunnels.count == 1
                ? L10n.format("Добавлен туннель «%@»", tunnels[0].name)
                : L10n.format("Добавлено туннелей: %lld", tunnels.count),
            tone: .success
        )
    }

    func removeTunnel(_ id: String) {
        if testingTunnelIds.contains(id) { cancelTunnelLatencyTests() }
        apply { st in
            st.tunnels.removeAll { $0.id == id }
            st.pruneFavoriteTunnelIDs()
            // Явно удалённый одиночный выход становится профилем Direct.
            // Цепочки/fallback сохраняем как невалидные: так UI показывает
            // поломку, а генератор блокирует трафик вместо утечки наружу.
            for i in st.proxies.indices where st.proxies[i].tunnelId == id {
                st.proxies[i].tunnelId = nil
                st.proxies[i].routingMode = .directAll
            }
            if st.systemVPNMainTunnelID() == id {
                st.systemVPN.target = st.tunnels.first.map { .tunnel($0.id) }
            }
        }
        testResults[id] = nil
    }

    func renameTunnel(_ id: String, to name: String) {
        apply { st in
            if let i = st.tunnels.firstIndex(where: { $0.id == id }) {
                st.tunnels[i].name = name
            }
        }
    }

    func toggleTunnelFavorite(_ id: String) {
        apply(restart: false) { state in
            state.setTunnelFavorite(id, isFavorite: !state.isTunnelFavorite(id))
        }
    }

    func testTunnel(_ tunnel: Tunnel) {
        beginTunnelLatencyTests([tunnel], showRunningWarning: true)
    }

    /// Первый показ списка автоматически заполняет отсутствующие значения.
    /// Повторная проверка всех узлов остаётся явным действием пользователя.
    func refreshTunnelLatenciesIfNeeded() {
        let missing = state.tunnels.filter { testResults[$0.id] == nil }
        beginTunnelLatencyTests(missing, showRunningWarning: false)
    }

    func refreshAllTunnelLatencies() {
        beginTunnelLatencyTests(state.tunnels, showRunningWarning: true)
    }

    private func beginTunnelLatencyTests(
        _ tunnels: [Tunnel],
        showRunningWarning: Bool
    ) {
        guard latencyRefreshTask == nil else { return }
        guard !tunnels.isEmpty else { return }
        guard !isRunning else {
            if showRunningWarning {
                presentToast(
                    "Для точного пинга сначала выключите VPN и локальный прокси",
                    tone: .warning
                )
            }
            return
        }
        guard xrayPath != nil else {
            if showRunningWarning { presentToast("Xray не найден", tone: .error) }
            return
        }

        let currentIDs = Set(state.tunnels.map(\.id))
        let selected = tunnels.filter { currentIDs.contains($0.id) }
        guard !selected.isEmpty else { return }

        latencyOperationGeneration += 1
        let generation = latencyOperationGeneration
        let selectedIDs = Set(selected.map(\.id))
        let settings = state.settings
        testingTunnelIds.formUnion(selectedIDs)
        isRefreshingTunnelLatencies = true

        latencyRefreshTask = Task { [weak self] in
            guard let self else { return }
            let results = await self.engine.testTunnels(selected, settings: settings) { [weak self] id, result in
                await self?.acceptTunnelLatencyResult(
                    id: id,
                    result: result,
                    generation: generation
                )
            }
            guard !Task.isCancelled,
                  generation == self.latencyOperationGeneration else { return }

            // Финальная синхронизация страхует случай, когда движок завершился
            // до публикации промежуточного результата.
            for (id, result) in results {
                self.acceptTunnelLatencyResult(id: id, result: result, generation: generation)
            }
            self.testingTunnelIds.subtract(selectedIDs)
            self.isRefreshingTunnelLatencies = false
            self.latencyRefreshTask = nil
        }
    }

    /// Публикует готовый результат сразу, не ожидая завершения всей пачки.
    private func acceptTunnelLatencyResult(
        id: String,
        result: TunnelTestResult,
        generation: Int
    ) {
        guard generation == latencyOperationGeneration,
              state.tunnels.contains(where: { $0.id == id }) else { return }
        testResults[id] = result
        testingTunnelIds.remove(id)
    }

    private func cancelTunnelLatencyTests() {
        guard latencyRefreshTask != nil || !testingTunnelIds.isEmpty else { return }
        latencyOperationGeneration += 1
        latencyRefreshTask?.cancel()
        latencyRefreshTask = nil
        testingTunnelIds.removeAll()
        isRefreshingTunnelLatencies = false
    }

    // MARK: - Прокси

    func addProxy(_ proxy: LocalProxy) {
        apply { $0.proxies.append(proxy) }
    }

    func updateProxy(_ proxy: LocalProxy) {
        apply { st in
            if let i = st.proxies.firstIndex(where: { $0.id == proxy.id }) {
                st.proxies[i] = proxy
            }
        }
    }

    func setProxyRoutingMode(_ id: String, mode: LocalProxy.RoutingMode) {
        apply { state in
            guard let index = state.proxies.firstIndex(where: { $0.id == id }) else { return }
            state.proxies[index].routingMode = mode
            if mode != .directAll, state.localProxyRouteIssue(state.proxies[index]) != nil {
                state.proxies[index].target = state.firstAvailableLocalProxyTarget()
            }
        }
    }

    func setProxyRouteTarget(_ id: String, target: VPNRouteTarget) {
        apply { state in
            guard target.kind == .tunnel || target.kind == .chain || target.kind == .fallback,
                  state.vpnRouteTargetIssue(target) == nil,
                  let index = state.proxies.firstIndex(where: { $0.id == id }) else { return }
            state.proxies[index].target = target
        }
    }

    func setProxyTunnel(_ id: String, tunnelID: String) {
        setProxyRouteTarget(id, target: .tunnel(tunnelID))
    }

    func removeProxy(_ id: String) {
        apply { $0.proxies.removeAll { $0.id == id } }
    }

    func toggleProxy(_ id: String) {
        apply { st in
            if let i = st.proxies.firstIndex(where: { $0.id == id }) {
                st.proxies[i].enabled.toggle()
            }
        }
    }

    // MARK: - Политики системного VPN

    func addVPNRoutingPolicy(_ policy: VPNRoutingPolicy) {
        apply { $0.vpnRoutingPolicies.append(policy) }
        presentToast(L10n.format("Политика «%@» добавлена", policy.name), tone: .success)
    }

    func updateVPNRoutingPolicy(_ policy: VPNRoutingPolicy) {
        apply { state in
            guard let index = state.vpnRoutingPolicies.firstIndex(where: { $0.id == policy.id }) else { return }
            state.vpnRoutingPolicies[index] = policy
        }
    }

    func toggleVPNRoutingPolicy(_ id: String) {
        apply { state in
            guard let index = state.vpnRoutingPolicies.firstIndex(where: { $0.id == id }) else { return }
            state.vpnRoutingPolicies[index].enabled.toggle()
        }
    }

    func moveVPNRoutingPolicy(_ id: String, offset: Int) {
        apply { state in
            guard offset != 0,
                  let source = state.vpnRoutingPolicies.firstIndex(where: { $0.id == id }) else { return }
            let destination = source + offset
            guard state.vpnRoutingPolicies.indices.contains(destination) else { return }
            state.vpnRoutingPolicies.swapAt(source, destination)
        }
    }

    func removeVPNRoutingPolicy(_ id: String) {
        let name = state.vpnRoutingPolicies.first(where: { $0.id == id })?.name ?? "Политика"
        apply { $0.vpnRoutingPolicies.removeAll { $0.id == id } }
        presentToast(L10n.format("«%@» удалена", name), tone: .success)
    }

    // MARK: - Цепочки системного VPN

    func addVPNTunnelChain(_ chain: VPNTunnelChain) {
        apply { $0.vpnTunnelChains.append(chain) }
        presentToast(L10n.format("Цепочка «%@» создана", chain.name), tone: .success)
    }

    func updateVPNTunnelChain(_ chain: VPNTunnelChain) {
        apply { state in
            guard let index = state.vpnTunnelChains.firstIndex(where: { $0.id == chain.id }) else { return }
            state.vpnTunnelChains[index] = chain
        }
    }

    func toggleVPNTunnelChain(_ id: String) {
        apply { state in
            guard let index = state.vpnTunnelChains.firstIndex(where: { $0.id == id }) else { return }
            state.vpnTunnelChains[index].enabled.toggle()
        }
    }

    func removeVPNTunnelChain(_ id: String) {
        let name = state.vpnTunnelChains.first(where: { $0.id == id })?.name ?? "Цепочка"
        apply { state in
            state.vpnTunnelChains.removeAll { $0.id == id }
            for index in state.vpnRoutingPolicies.indices
            where state.vpnRoutingPolicies[index].target == .chain(id) {
                state.vpnRoutingPolicies[index].enabled = false
            }
            for index in state.vpnFallbackGroups.indices {
                state.vpnFallbackGroups[index].members.removeAll { $0.target == .chain(id) }
            }
            for index in state.proxies.indices where state.proxies[index].target == .chain(id) {
                state.proxies[index].target = nil
                state.proxies[index].routingMode = .directAll
            }
        }
        presentToast(
            L10n.format("«%@» удалена; зависимые политики выключены", name),
            tone: .warning
        )
    }

    // MARK: - Fallback системного VPN

    func addVPNFallbackGroup(_ group: VPNFallbackGroup) {
        apply { $0.vpnFallbackGroups.append(group) }
        presentToast(L10n.format("Fallback «%@» создан", group.name), tone: .success)
    }

    func updateVPNFallbackGroup(_ group: VPNFallbackGroup) {
        apply { state in
            guard let index = state.vpnFallbackGroups.firstIndex(where: { $0.id == group.id }) else { return }
            state.vpnFallbackGroups[index] = group
        }
    }

    func toggleVPNFallbackGroup(_ id: String) {
        apply { state in
            guard let index = state.vpnFallbackGroups.firstIndex(where: { $0.id == id }) else { return }
            state.vpnFallbackGroups[index].enabled.toggle()
        }
    }

    func removeVPNFallbackGroup(_ id: String) {
        let name = state.vpnFallbackGroups.first(where: { $0.id == id })?.name ?? "Fallback"
        apply { state in
            state.vpnFallbackGroups.removeAll { $0.id == id }
            for index in state.vpnRoutingPolicies.indices
            where state.vpnRoutingPolicies[index].target == .fallback(id) {
                state.vpnRoutingPolicies[index].enabled = false
            }
            for index in state.proxies.indices where state.proxies[index].target == .fallback(id) {
                state.proxies[index].target = nil
                state.proxies[index].routingMode = .directAll
            }
        }
        presentToast(
            L10n.format("«%@» удалён; зависимые политики выключены", name),
            tone: .warning
        )
    }

    // MARK: - Постоянные маршруты

    func addPersistentRoute(_ route: PersistentRoute) {
        apply { $0.persistentRoutes.append(route) }
        presentToast(L10n.format("Маршрут «%@» добавлен", route.name), tone: .success)
    }

    func updatePersistentRoute(_ route: PersistentRoute) {
        apply { state in
            guard let index = state.persistentRoutes.firstIndex(where: { $0.id == route.id }) else { return }
            state.persistentRoutes[index] = route
        }
    }

    func togglePersistentRoute(_ id: String) {
        apply { state in
            guard let index = state.persistentRoutes.firstIndex(where: { $0.id == id }) else { return }
            state.persistentRoutes[index].enabled.toggle()
        }
    }

    func removePersistentRoute(_ id: String) {
        let name = state.persistentRoutes.first(where: { $0.id == id })?.name ?? "Маршрут"
        apply { $0.persistentRoutes.removeAll { $0.id == id } }
        presentToast(L10n.format("«%@» удалён", name), tone: .success)
    }

    // MARK: - Системный VPN

    func setSystemVPNMainRoute(_ target: VPNRouteTarget) {
        apply { state in
            guard target.kind == .direct
                    || target.kind == .tunnel
                    || target.kind == .chain
                    || target.kind == .fallback,
                  state.vpnRouteTargetIssue(target) == nil else { return }
            state.systemVPN.target = target
        }
    }

    func setSystemVPNTunnel(_ tunnelID: String) {
        setSystemVPNMainRoute(.tunnel(tunnelID))
    }

    var quickMRVasilRouteTarget: VPNRouteTarget? {
        VPNQuickRoutes.mrvasilTarget(in: state)
    }

    var quickWhitelistRouteTarget: VPNRouteTarget? {
        let ids = VPNQuickRoutes.whitelistTunnelIDs(in: state)
        if ids.count >= 2,
           let group = state.vpnFallbackGroup(id: VPNQuickRoutes.whitelistFallbackID),
           state.vpnFallbackGroupIssue(group) == nil {
            return .fallback(group.id)
        }
        return ids.first.map(VPNRouteTarget.tunnel)
    }

    /// Быстрая карточка одновременно назначает маршрут и включает VPN. При уже
    /// поднятом VPN обычная смена назначения проходит через hot routing.
    func activateSystemVPNRoute(_ target: VPNRouteTarget) {
        guard target.kind != .block, state.vpnRouteTargetIssue(target) == nil else {
            presentToast("Маршрут сейчас недоступен", tone: .warning)
            return
        }
        let alreadyActive = isSystemVPNActive
        if alreadyActive, state.systemVPN.target == target { return }
        apply(restart: alreadyActive) { $0.systemVPN.target = target }
        if !alreadyActive { startSystemVPN() }
    }

    func activateMRVasilQuickRoute() {
        guard let target = quickMRVasilRouteTarget else {
            presentToast("Fallback «mrvasil vpn» недоступен", tone: .warning)
            return
        }
        activateSystemVPNRoute(target)
    }

    func activateWhitelistQuickRoute() {
        var synchronized = state
        guard let target = VPNQuickRoutes.synchronizeWhitelist(in: &synchronized) else {
            presentToast("В подписке Akenai нет туннелей [Обход LTE]", tone: .warning)
            return
        }
        synchronized.systemVPN.target = target
        let alreadyActive = isSystemVPNActive
        apply(restart: alreadyActive) { $0 = synchronized }
        if !alreadyActive { startSystemVPN() }
    }

    var isSystemVPNActive: Bool {
        status.running && status.mode == .systemVPN
    }

    var isSystemVPNReady: Bool {
        isSystemVPNActive && status.ready
    }

    func startSystemVPN() {
        cancelTunnelLatencyTests()
        suppressStablePhysicalPathEvents(for: 5)
        Task {
            do {
                try await engine.startSystemVPN(state: runtimeState, settings: state.settings)
                lastConfirmedState = state
                refreshBypass()
            } catch {
                // Если VPN не поднялся во время переключения с работающего
                // прокси, возвращаем локальные порты вместо полного офлайна.
                if localProxyRequested {
                    try? await engine.start(state: runtimeState, settings: state.settings)
                }
                presentToast(error.localizedDescription, tone: .error)
            }
        }
    }

    func toggleSystemVPN() {
        if isSystemVPNActive {
            stopSystemVPNKeepingLocalProxy()
        } else {
            startSystemVPN()
        }
    }

    func deactivateSystemVPN() {
        guard isSystemVPNActive else { return }
        stopSystemVPNKeepingLocalProxy()
    }

    private func stopSystemVPNKeepingLocalProxy() {
        suppressStablePhysicalPathEvents(for: 5)
        Task {
            await engine.stop()
            guard localProxyRequested else { return }
            do {
                try await engine.start(state: runtimeState, settings: state.settings)
                lastConfirmedState = state
                refreshBypass()
            } catch {
                localProxyRequested = false
                presentToast(error.localizedDescription, tone: .error)
            }
        }
    }

    private func suppressStablePhysicalPathEvents(for seconds: TimeInterval) {
        suppressStablePhysicalPathEventsUntil = max(
            suppressStablePhysicalPathEventsUntil,
            Date().addingTimeInterval(seconds)
        )
    }

    /// Порт, свободный среди уже настроенных прокси.
    func suggestedPort() -> Int {
        let used = Set(state.proxies.map(\.port))
        var port = 10808
        while used.contains(port) { port += 1 }
        return port
    }

    // MARK: - Настройки

    func updateSettings(_ settings: WaypointCore.Settings) {
        cancelTunnelLatencyTests()
        testResults.removeAll()
        apply { $0.settings = settings }
        refreshBypass()
        Task { await refreshXrayInfo() }
    }

    // MARK: - Движок

    var isRunning: Bool { status.running }

    var isLocalProxyActive: Bool {
        guard localProxyRequested, status.running else { return false }
        if status.mode == .systemVPN { return status.ready }
        return status.mode == .localProxy
    }

    var isLocalProxyConnecting: Bool {
        localProxyRequested && !isLocalProxyActive
    }

    func start() {
        cancelTunnelLatencyTests()
        localProxyRequested = true
        Task {
            do {
                try await engine.start(state: runtimeState, settings: state.settings)
                refreshBypass()
            } catch {
                localProxyRequested = false
                presentToast(error.localizedDescription, tone: .error)
            }
        }
    }

    func stop() {
        localProxyRequested = false
        Task { await engine.stop() }
    }

    func toggleEngine() {
        isRunning ? stop() : start()
    }

    /// При активном VPN локальные SOCKS/HTTP работают как дополнительные
    /// inbound'ы того же xray. Их можно включать и выключать мягкой перезагрузкой
    /// конфига, не снимая utun и системные маршруты.
    func toggleLocalProxy() {
        if localProxyRequested {
            disableLocalProxy()
        } else {
            enableLocalProxy()
        }
    }

    private func enableLocalProxy() {
        cancelTunnelLatencyTests()
        localProxyRequested = true
        Task {
            do {
                if await engine.status().mode == .systemVPN {
                    try await engine.restart(state: runtimeState, settings: state.settings)
                } else {
                    try await engine.start(state: runtimeState, settings: state.settings)
                }
                refreshBypass()
            } catch {
                localProxyRequested = false
                presentToast(error.localizedDescription, tone: .error)
            }
        }
    }

    private func disableLocalProxy() {
        localProxyRequested = false
        Task {
            do {
                if await engine.status().mode == .systemVPN {
                    try await engine.restart(state: runtimeState, settings: state.settings)
                } else {
                    await engine.stop()
                }
            } catch {
                localProxyRequested = true
                presentToast(error.localizedDescription, tone: .error)
            }
        }
    }

    func validate() {
        Task {
            do {
                let result = try await engine.validate(state: state, settings: state.settings)
                presentToast(
                    result.ok ? "Конфиг корректен" : "xray отверг конфиг",
                    tone: result.ok ? .success : .error
                )
                if !result.ok {
                    await appendOutput(result.output)
                }
            } catch {
                presentToast(error.localizedDescription, tone: .error)
            }
        }
    }

    private func appendOutput(_ text: String) async {
        // Показываем хвост вывода: там причина отказа.
        for line in text.components(separatedBy: .newlines).suffix(10) where !line.isEmpty {
            logs.append(LogEntry(line))
        }
        if logs.count > 400 {
            logs.removeFirst(logs.count - 400)
        }
    }

    func clearLogs() {
        Task { await engine.clearLogs() }
    }

    func previewConfig() -> String {
        let config = XrayConfig.build(
            state: runtimeState,
            logLevel: state.settings.logLevel,
            bypassInterface: engine.bypassInterface(for: state.settings),
            systemVPNInterface: isSystemVPNActive ? status.vpnInterface : nil
        )
        guard let data = try? XrayConfig.encode(config),
              let text = String(data: data, encoding: .utf8) else {
            return "Не удалось собрать конфиг"
        }
        return text
    }

    // MARK: - Подписки

    /// Добавляет источник только после успешной загрузки, поэтому в списке не
    /// остаются пустые или ошибочные подписки.
    func addSubscription(name: String, url: String) async -> Bool {
        let cleanName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let cleanURL = url.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !cleanName.isEmpty, !cleanURL.isEmpty else { return false }
        guard !state.subscriptions.contains(where: { $0.url == cleanURL }) else {
            presentToast("Эта подписка уже добавлена", tone: .warning)
            return false
        }

        let subscription = Subscription(name: cleanName, url: cleanURL)
        refreshingSubscriptionIds.insert(subscription.id)
        defer { refreshingSubscriptionIds.remove(subscription.id) }

        do {
            let result = try await engine.fetchSubscription(url: cleanURL)
            try ensureSubscriptionHasTunnels(result)
            apply { state in
                state.subscriptions.append(subscription)
                SubscriptionReconciler.refresh(
                    subscriptionID: subscription.id,
                    incoming: result.tunnels,
                    state: &state
                )
                _ = VPNQuickRoutes.synchronizeWhitelist(in: &state)
            }
            subscriptionErrors[subscription.id] = parseWarning(for: result)
            presentToast(
                result.errors.isEmpty
                    ? L10n.format("Подписка «%@» добавлена: %lld", cleanName, result.tunnels.count)
                    : L10n.format(
                        "Добавлено %lld, не разобрано %lld",
                        result.tunnels.count,
                        result.errors.count
                    ),
                tone: result.errors.isEmpty ? .success : .warning
            )
            return true
        } catch {
            presentToast(error.localizedDescription, tone: .error)
            return false
        }
    }

    @discardableResult
    func refreshSubscription(_ subscriptionID: String, notify: Bool = true, restart: Bool = true) async -> Bool {
        guard !refreshingSubscriptionIds.contains(subscriptionID),
              let subscription = state.subscriptions.first(where: { $0.id == subscriptionID }) else {
            return false
        }

        refreshingSubscriptionIds.insert(subscriptionID)
        defer { refreshingSubscriptionIds.remove(subscriptionID) }

        do {
            let result = try await engine.fetchSubscription(url: subscription.url)
            try ensureSubscriptionHasTunnels(result)

            // Подписку могли удалить, пока выполнялся сетевой запрос.
            guard state.subscriptions.contains(where: { $0.id == subscriptionID }) else { return false }
            cancelTunnelLatencyTests()
            let previousTunnels = Dictionary(uniqueKeysWithValues: state.tunnels.map { ($0.id, $0) })
            let update = apply(restart: restart) { state in
                let update = SubscriptionReconciler.refresh(
                    subscriptionID: subscriptionID,
                    incoming: result.tunnels,
                    state: &state
                )
                _ = VPNQuickRoutes.synchronizeWhitelist(in: &state)
                if state.systemVPN.target == nil {
                    state.systemVPN.target = state.tunnels.first.map { .tunnel($0.id) }
                }
                return update
            }
            for id in update.removedTunnelIDs { testResults[id] = nil }
            for tunnel in state.tunnels where previousTunnels[tunnel.id] != tunnel {
                testResults[tunnel.id] = nil
            }
            subscriptionErrors[subscriptionID] = parseWarning(for: result)

            if notify {
                presentToast(
                    result.errors.isEmpty
                        ? L10n.format("«%@» обновлена: %lld", subscription.name, result.tunnels.count)
                        : L10n.format(
                            "Обновлено %lld, не разобрано %lld",
                            result.tunnels.count,
                            result.errors.count
                        ),
                    tone: result.errors.isEmpty ? .success : .warning
                )
            }
            return true
        } catch {
            subscriptionErrors[subscriptionID] = error.localizedDescription
            if notify { presentToast(error.localizedDescription, tone: .error) }
            return false
        }
    }

    func refreshAllSubscriptions(notify: Bool = false) async {
        let ids = state.subscriptions.map(\.id)
        guard !ids.isEmpty else { return }

        var refreshedCount = 0
        for id in ids where !Task.isCancelled {
            if await refreshSubscription(id, notify: false, restart: false) {
                refreshedCount += 1
            }
        }
        if refreshedCount > 0 {
            configurationGeneration &+= 1
            scheduleConfigurationApply()
        }
        if notify {
            let failedCount = ids.count - refreshedCount
            presentToast(
                failedCount == 0
                    ? L10n.format("Подписки обновлены: %lld", refreshedCount)
                    : L10n.format("Обновлено %lld, с ошибкой %lld", refreshedCount, failedCount),
                tone: failedCount == 0 ? .success : .warning
            )
        }
    }

    func removeSubscription(_ subscriptionID: String) {
        let name = state.subscriptions.first(where: { $0.id == subscriptionID })?.name ?? "Подписка"
        cancelTunnelLatencyTests()
        let removedIDs = apply { state in
            let removedIDs = SubscriptionReconciler.remove(subscriptionID: subscriptionID, state: &state)
            _ = VPNQuickRoutes.synchronizeWhitelist(in: &state)
            if state.systemVPN.target == nil {
                state.systemVPN.target = state.tunnels.first.map { .tunnel($0.id) }
            }
            return removedIDs
        }
        for id in removedIDs { testResults[id] = nil }
        subscriptionErrors[subscriptionID] = nil
        presentToast(L10n.format("«%@» удалена", name), tone: .success)
    }

    private func startSubscriptionUpdates() {
        subscriptionUpdateTask?.cancel()
        subscriptionUpdateTask = Task { [weak self] in
            guard let self else { return }
            await self.refreshAllSubscriptions()
            self.refreshTunnelLatenciesIfNeeded()
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(15 * 60))
                } catch {
                    return
                }
                await self.refreshAllSubscriptions()
                self.refreshTunnelLatenciesIfNeeded()
            }
        }
    }

    private func ensureSubscriptionHasTunnels(_ result: ParseResult) throws {
        guard !result.tunnels.isEmpty else {
            let suffix = result.errors.first.map { ": \(L10n.string($0.message))" } ?? ""
            throw SubscriptionLoadError(
                message: L10n.format("В подписке не найдено туннелей%@", suffix)
            )
        }
    }

    private func parseWarning(for result: ParseResult) -> String? {
        result.errors.isEmpty
            ? nil
            : L10n.format("Не разобрано записей: %lld", result.errors.count)
    }

    // MARK: - Прочее

    func copyToClipboard(_ text: String) {
        Pasteboard.copy(text)
        presentToast(L10n.format("Скопировано: %@", text), tone: .success)
    }

    func dismissToast() {
        toastDismissTask?.cancel()
        toastDismissTask = nil
        toast = nil
    }

    private func presentToast(_ text: String, tone: AppToast.Tone) {
        let nextToast = AppToast(text: text, tone: tone)
        toastDismissTask?.cancel()
        toast = nextToast

        toastDismissTask = Task { [weak self, toastID = nextToast.id] in
            do {
                try await Task.sleep(for: .seconds(2.5))
            } catch {
                return
            }

            guard let self, self.toast?.id == toastID else { return }
            self.toast = nil
            self.toastDismissTask = nil
        }
    }
}
