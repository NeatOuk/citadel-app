// Per-app proxy routing (phase 2, later step): flows of apps whose policy
// says "via proxy X" will be tunnelled through X (HTTP CONNECT, HTTPS,
// SOCKS5), failing closed like citadel-proxy on Linux. For now it takes no
// flows, so everything goes direct.
import Foundation
import NetworkExtension

final class TransparentProxyProvider: NETransparentProxyProvider {
    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = [NENetworkRule(remoteNetwork: nil, remotePrefix: 0, localNetwork: nil,
                                                       localPrefix: 0, protocol: .TCP, direction: .outbound)]
        setTunnelNetworkSettings(settings) { error in completionHandler(error) }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        false                                   // not handled: the flow goes direct
    }
}
