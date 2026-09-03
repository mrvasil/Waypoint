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
    private var networkPathMonitor: NWPathMonitor?
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
        var initialState = store.snapshot()
        if initialState.systemVPN.target == nil,
           let firstTunnelID = initialState.tunnels.first?.id {
            store.mutate { $0.systemVPN.target = .tunnel(firstTunnelID) }
            initialState = store.snapshot()
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
        monitor.pathUpdateHandler = { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.scheduleNetworkEventCheck()
            }
        }
        monitor.start(queue: networkMonitorQueue)
        networkPathMonitor = monitor

        networkWatchTask = Task { [weak self] in
            guard let self else { return }
            let preferred = self.state.settings.bypassInterface
            let initialPath = await Task.detached(priority: .utility) {
                NetworkInterface.physicalPathFingerprint(
                    interface: preferred.isEmpty ? nil : preferred
                )
            }.value
            self.lastKnownNetworkPath = initialPath

            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 4_000_000_000)
                _ = await self.checkNetworkChange()
            }
        }
    }

    private func scheduleNetworkEventCheck() {
        networkEventTask?.cancel()
        networkEventTask = Task { [weak self] in
            // NWPath сообщает о смене раньше, чем route table успевает получить
            // новый gateway. Несколько коротких попыток дают быстрый recovery
            // без ложного рестарта на промежуточном состоянии сети.
            try? await Task.sleep(for: .milliseconds(250))
            for _ in 0..<8 where !Task.isCancelled {
                guard let self else { return }
                if await self.checkNetworkChange() { return }
                try? await Task.sleep(for: .milliseconds(350))
            }
        }
    }

    @discardableResult
    private func checkNetworkChange() async -> Bool {
        // networksetup/route are synchronous processes. Running them on the
        // MainActor every four seconds made the whole SwiftUI window hitch.
        let preferred = state.settings.bypassInterface
        let current = await Task.detached(priority: .utility) {
            NetworkInterface.physicalPathFingerprint(
                interface: preferred.isEmpty ? nil : preferred
            )
        }.value
        guard let current else { return false }
        guard current != lastKnownNetworkPath else { return true }
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
                ? "Добавлен туннель «\(tunnels[0].name)»"
                : "Добавлено туннелей: \(tunnels.count)",
            tone: .success
        )
    }

    func removeTunnel(_ id: String) {
        if testingTunnelIds.contains(id) { cancelTunnelLatencyTests() }
        apply { st in
            st.tunnels.removeAll { $0.id == id }
            // Прокси, привязанные к удалённому туннелю, идут напрямую.
            for i in st.proxies.indices where st.proxies[i].tunnelId == id {
                st.proxies[i].tunnelId = nil
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
            if mode != .directAll, state.tunnel(id: state.proxies[index].tunnelId) == nil {
                state.proxies[index].tunnelId = state.tunnels.first?.id
            }
        }
    }

    func setProxyTunnel(_ id: String, tunnelID: String) {
        apply { state in
            guard state.tunnels.contains(where: { $0.id == tunnelID }),
                  let index = state.proxies.firstIndex(where: { $0.id == id }) else { return }
            state.proxies[index].tunnelId = tunnelID
        }
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
        presentToast("Политика «\(policy.name)» добавлена", tone: .success)
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
        presentToast("«\(name)» удалена", tone: .success)
    }

    // MARK: - Цепочки системного VPN

    func addVPNTunnelChain(_ chain: VPNTunnelChain) {
        apply { $0.vpnTunnelChains.append(chain) }
        presentToast("Цепочка «\(chain.name)» создана", tone: .success)
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
        }
        presentToast("«\(name)» удалена; зависимые политики выключены", tone: .warning)
    }

    // MARK: - Fallback системного VPN

    func addVPNFallbackGroup(_ group: VPNFallbackGroup) {
        apply { $0.vpnFallbackGroups.append(group) }
        presentToast("Fallback «\(group.name)» создан", tone: .success)
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
        }
        presentToast("«\(name)» удалён; зависимые политики выключены", tone: .warning)
    }

    // MARK: - Постоянные маршруты

    func addPersistentRoute(_ route: PersistentRoute) {
        apply { $0.persistentRoutes.append(route) }
        presentToast("Маршрут «\(route.name)» добавлен", tone: .success)
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
        presentToast("«\(name)» удалён", tone: .success)
    }

    // MARK: - Системный VPN

    func setSystemVPNMainRoute(_ target: VPNRouteTarget) {
        apply { state in
            guard target.kind == .tunnel || target.kind == .chain || target.kind == .fallback,
                  state.vpnRouteTargetIssue(target) == nil else { return }
            state.systemVPN.target = target
        }
    }

    func setSystemVPNTunnel(_ tunnelID: String) {
        setSystemVPNMainRoute(.tunnel(tunnelID))
    }

    var isSystemVPNActive: Bool {
        status.running && status.mode == .systemVPN
    }

    var isSystemVPNReady: Bool {
        isSystemVPNActive && status.ready
    }

    func startSystemVPN() {
        cancelTunnelLatencyTests()
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

    private func stopSystemVPNKeepingLocalProxy() {
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
            }
            subscriptionErrors[subscription.id] = parseWarning(for: result)
            presentToast(
                result.errors.isEmpty
                    ? "Подписка «\(cleanName)» добавлена: \(result.tunnels.count)"
                    : "Добавлено \(result.tunnels.count), не разобрано \(result.errors.count)",
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
                        ? "«\(subscription.name)» обновлена: \(result.tunnels.count)"
                        : "Обновлено \(result.tunnels.count), не разобрано \(result.errors.count)",
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
                    ? "Подписки обновлены: \(refreshedCount)"
                    : "Обновлено \(refreshedCount), с ошибкой \(failedCount)",
                tone: failedCount == 0 ? .success : .warning
            )
        }
    }

    func removeSubscription(_ subscriptionID: String) {
        let name = state.subscriptions.first(where: { $0.id == subscriptionID })?.name ?? "Подписка"
        cancelTunnelLatencyTests()
        let removedIDs = apply { state in
            let removedIDs = SubscriptionReconciler.remove(subscriptionID: subscriptionID, state: &state)
            if state.systemVPN.target == nil {
                state.systemVPN.target = state.tunnels.first.map { .tunnel($0.id) }
            }
            return removedIDs
        }
        for id in removedIDs { testResults[id] = nil }
        subscriptionErrors[subscriptionID] = nil
        presentToast("«\(name)» удалена", tone: .success)
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
            let suffix = result.errors.first.map { ": \($0.message)" } ?? ""
            throw SubscriptionLoadError(message: "В подписке не найдено туннелей\(suffix)")
        }
    }

    private func parseWarning(for result: ParseResult) -> String? {
        result.errors.isEmpty ? nil : "Не разобрано записей: \(result.errors.count)"
    }

    // MARK: - Прочее

    func copyToClipboard(_ text: String) {
        Pasteboard.copy(text)
        presentToast("Скопировано: \(text)", tone: .success)
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
