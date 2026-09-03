import SwiftUI
import TPHCore

struct ContentView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    @SceneStorage("selectedSection") private var selectedSection = AppSection.overview.rawValue
    @State private var columnVisibility = NavigationSplitViewVisibility.all
    @State private var searchText = ""
    @State private var showAddTunnel = false
    @State private var showAddProxy = false
    @State private var showSettings = false
    @State private var showConfig = false
    @State private var editingProxy: LocalProxy?

    private var section: AppSection {
        AppSection(rawValue: selectedSection) ?? .overview
    }

    var body: some View {
        NavigationSplitView(columnVisibility: $columnVisibility) {
            AppSidebar(selection: $selectedSection)
        } detail: {
            detail
                .navigationTitle(section.title)
        }
        .navigationSplitViewStyle(.balanced)
        .animation(reduceMotion ? nil : .smooth(duration: 0.26), value: columnVisibility)
        .searchable(text: $searchText, placement: .toolbar, prompt: "Поиск")
        .toolbar { appToolbar }
        .frame(minWidth: 780, minHeight: 560)
        .sheet(isPresented: $showAddTunnel) { AddTunnelSheet() }
        .sheet(isPresented: $showAddProxy) { ProxySheet(proxy: nil) }
        .sheet(item: $editingProxy) { proxy in ProxySheet(proxy: proxy) }
        .sheet(isPresented: $showSettings) { SettingsSheet() }
        .sheet(isPresented: $showConfig) { ConfigSheet(text: model.previewConfig()) }
        .overlay(alignment: .bottom) { toastView }
        .animation(reduceMotion ? nil : .snappy(duration: 0.22), value: model.toast)
    }

    @ViewBuilder
    private var detail: some View {
        switch section {
        case .overview:
            DashboardView(
                onAddTunnel: { showAddTunnel = true },
                onAddProxy: { showAddProxy = true },
                onOpenSection: { destination in
                    withAnimation(reduceMotion ? nil : .smooth(duration: 0.22)) {
                        selectedSection = destination.rawValue
                    }
                }
            )
        case .tunnels:
            TunnelsView(searchText: searchText) {
                showAddTunnel = true
            }
        case .proxies:
            ProxiesView(searchText: searchText) { proxy in
                editingProxy = proxy
            } onAdd: {
                showAddProxy = true
            }
        case .routing:
            RoutingView()
        case .logs:
            LogsView(searchText: searchText) {
                showConfig = true
            }
        }
    }

    @ToolbarContentBuilder
    private var appToolbar: some ToolbarContent {
        ToolbarItemGroup(placement: .primaryAction) {
            switch section {
            case .overview:
                Menu {
                    Button("Добавить туннель", systemImage: "point.3.connected.trianglepath.dotted") {
                        showAddTunnel = true
                    }
                    Button("Создать прокси", systemImage: "arrow.triangle.branch") {
                        showAddProxy = true
                    }
                } label: {
                    Label("Добавить", systemImage: "plus")
                }
                .help("Добавить")
            case .tunnels:
                Button {
                    model.refreshAllTunnelLatencies()
                } label: {
                    Image(systemName: "gauge.with.dots.needle.33percent")
                        .symbolEffect(
                            .pulse.byLayer,
                            options: .repeating,
                            isActive: model.isRefreshingTunnelLatencies
                        )
                        .frame(width: 18, height: 18)
                }
                .accessibilityLabel(
                    model.isRefreshingTunnelLatencies
                        ? "Измерение задержки через туннели"
                        : "Измерить задержку"
                )
                .disabled(model.state.tunnels.isEmpty || model.isRefreshingTunnelLatencies)
                .help(
                    model.isRefreshingTunnelLatencies
                        ? "Измерение задержки через туннели"
                        : model.isRunning
                            ? "Сначала выключите VPN или прокси — второй Xray не запускается"
                            : "Проверить все туннели одним Xray"
                )

                Button("Добавить туннель", systemImage: "plus") {
                    showAddTunnel = true
                }
                .help("Добавить туннель")
            case .proxies:
                Button("Создать прокси", systemImage: "plus") {
                    showAddProxy = true
                }
                .help("Создать прокси")
            case .routing:
                EmptyView()
            case .logs:
                Button("Проверить конфиг", systemImage: "checkmark.shield") {
                    model.validate()
                }
                .help("Проверить конфиг")
            }

            Button("Настройки", systemImage: "gearshape") {
                showSettings = true
            }
            .help("Настройки")
        }

        if #available(macOS 26.0, *) {
            ToolbarSpacer(.fixed, placement: .primaryAction)
        }

        ToolbarConnectionControls()
    }

    @ViewBuilder
    private var toastView: some View {
        if let toast = model.toast {
            HStack(spacing: 10) {
                Image(systemName: toast.tone.symbol)
                    .font(.system(size: 12, weight: .bold))
                    .foregroundStyle(toast.tone.color)
                    .frame(width: 16, height: 16)

                Text(toast.text)
            }
                .font(.callout.weight(.medium))
                .foregroundStyle(.primary)
                .padding(.horizontal, 15)
                .padding(.vertical, 10)
                .appGlass(cornerRadius: 16)
                .padding(.bottom, 18)
                .contentShape(.rect)
                .onTapGesture { model.dismissToast() }
                .help("Закрыть уведомление")
                .accessibilityElement(children: .combine)
                .transition(.move(edge: .bottom).combined(with: .opacity))
        }
    }
}

private extension AppToast.Tone {
    var symbol: String {
        switch self {
        case .success: "checkmark"
        case .warning, .error: "exclamationmark"
        }
    }

    var color: Color {
        switch self {
        case .success: .green
        case .warning: .orange
        case .error: .red
        }
    }
}
