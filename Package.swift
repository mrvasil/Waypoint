// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Waypoint",
    defaultLocalization: "ru",
    platforms: [.macOS(.v15)],
    products: [
        .executable(name: "Waypoint", targets: ["Waypoint"]),
        .executable(name: "WaypointVPNHelper", targets: ["WaypointVPNHelper"]),
        .executable(name: "WaypointVPNLauncher", targets: ["WaypointVPNLauncher"]),
        .executable(name: "waypoint-vpn-lifecycle-tests", targets: ["WaypointVPNLifecycleTests"]),
        .executable(name: "waypoint-tests", targets: ["WaypointTests"]),
    ],
    targets: [
        // Логика вынесена в библиотеку, чтобы её использовали и приложение, и тесты.
        .target(
            name: "WaypointCore",
            path: "Sources/WaypointCore",
            resources: [.process("Resources")]
        ),
        .executableTarget(
            name: "Waypoint",
            dependencies: ["WaypointCore"],
            path: "Sources/Waypoint",
            linkerSettings: [.linkedFramework("Carbon")]
        ),
        // Минимальный привилегированный процесс: создаёт utun и системные
        // маршруты, затем запускает xray уже с uid/gid обычного пользователя.
        .executableTarget(
            name: "WaypointVPNHelper",
            dependencies: ["WaypointVPNLifecycle"],
            path: "Sources/WaypointVPNHelper"
        ),
        .target(
            name: "WaypointVPNLifecycle",
            path: "Sources/WaypointVPNLifecycle",
            publicHeadersPath: "include"
        ),
        .executableTarget(
            name: "WaypointVPNLifecycleTests",
            dependencies: ["WaypointVPNLifecycle"],
            path: "Sources/WaypointVPNLifecycleTests"
        ),
        // Непривилегированный launcher один раз устанавливает ограниченный LaunchDaemon,
        // а при последующих запусках общается с ним через Unix socket.
        .executableTarget(
            name: "WaypointVPNLauncher",
            path: "Sources/WaypointVPNLauncher",
            linkerSettings: [.linkedFramework("Security")]
        ),
        // Тесты — отдельный исполняемый таргет, а не .testTarget: XCTest и
        // swift-testing поставляются только с полным Xcode, которого здесь нет.
        // Запуск: swift run waypoint-tests
        .executableTarget(
            name: "WaypointTests",
            dependencies: ["WaypointCore"],
            path: "Sources/WaypointTests"
        ),
    ]
)
