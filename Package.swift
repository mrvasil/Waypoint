// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "TunnelProxyHub",
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "TunnelProxyHub", targets: ["TunnelProxyHub"]),
        .executable(name: "TPHVPNHelper", targets: ["TPHVPNHelper"]),
        .executable(name: "TPHVPNLauncher", targets: ["TPHVPNLauncher"]),
        .executable(name: "tph-vpn-lifecycle-tests", targets: ["TPHVPNLifecycleTests"]),
        .executable(name: "tph-tests", targets: ["TPHTests"]),
    ],
    targets: [
        // Логика вынесена в библиотеку, чтобы её использовали и приложение, и тесты.
        .target(name: "TPHCore", path: "Sources/TPHCore"),
        .executableTarget(
            name: "TunnelProxyHub",
            dependencies: ["TPHCore"],
            path: "Sources/TunnelProxyHub",
            linkerSettings: [.linkedFramework("Carbon")]
        ),
        // Минимальный привилегированный процесс: создаёт utun и системные
        // маршруты, затем запускает xray уже с uid/gid обычного пользователя.
        .executableTarget(
            name: "TPHVPNHelper",
            dependencies: ["TPHVPNLifecycle"],
            path: "Sources/TPHVPNHelper"
        ),
        .target(
            name: "TPHVPNLifecycle",
            path: "Sources/TPHVPNLifecycle",
            publicHeadersPath: "include"
        ),
        .executableTarget(
            name: "TPHVPNLifecycleTests",
            dependencies: ["TPHVPNLifecycle"],
            path: "Sources/TPHVPNLifecycleTests"
        ),
        // Непривилегированный launcher один раз устанавливает ограниченный LaunchDaemon,
        // а при последующих запусках общается с ним через Unix socket.
        .executableTarget(
            name: "TPHVPNLauncher",
            path: "Sources/TPHVPNLauncher",
            linkerSettings: [.linkedFramework("Security")]
        ),
        // Тесты — отдельный исполняемый таргет, а не .testTarget: XCTest и
        // swift-testing поставляются только с полным Xcode, которого здесь нет.
        // Запуск: swift run tph-tests
        .executableTarget(
            name: "TPHTests",
            dependencies: ["TPHCore"],
            path: "Sources/TPHTests"
        ),
    ]
)
