import Foundation

if CommandLine.arguments.contains("--dump") {
    LiveChecks.dumpTestConfig()
    exit(0)
}

if CommandLine.arguments.contains("--live") {
    await LiveChecks.run()
    exit(0)
}

if CommandLine.arguments.contains("--live-latency") {
    exit(await LiveChecks.runTunnelLatencies() ? 0 : 1)
}

if CommandLine.arguments.contains("--validate-routing") {
    exit(await LiveChecks.validateRoutingProfile() ? 0 : 1)
}

if CommandLine.arguments.contains("--validate-hot-routing") {
    exit(await LiveChecks.validateHotRoutingAPI() ? 0 : 1)
}

if CommandLine.arguments.contains("--live-system-vpn") {
    exit(await LiveChecks.runSystemVPN() ? 0 : 1)
}

let harness = Harness()
ParserChecks.run(harness)
ConfigChecks.run(harness)
FallbackRuntimeChecks.run(harness)
SystemVPNRuntimeChecks.run(harness)
NetworkChangeChecks.run(harness)
VPNQuickRouteChecks.run(harness)
SubscriptionChecks.run(harness)
LocalizationChecks.run(harness)
harness.finish()
