// The XPC link between the Citadel host app and the network filter system
// extension. Compiled into both targets.
import Foundation

/// Served by the extension (a privileged Mach service).
@objc protocol FilterXPC {
    /// Load the daemon's spec (citadel-macos-1 JSON).
    func apply(_ spec: Data, withReply reply: @escaping (Bool, String) -> Void)
    /// citadel-enforcer-style status JSON: active, drops, rules, version, pending.
    func status(withReply reply: @escaping (Data) -> Void)
    /// Resume paused flows: allowed or dropped.
    func resolve(_ flowIDs: [String], allow: Bool)
    /// Stop filtering: forget the spec, let paused flows through.
    func off(withReply reply: @escaping (Bool) -> Void)
}

/// Served by the host app, called by the extension.
@objc protocol HostXPC {
    /// A new connection is paused until the gate answers (JSON: id, exe, raddr, rport, host, proto, pid).
    func flowPaused(_ info: Data)
}

enum CitadelIDs {
    static let filterBundle = "io.github.neatouk.Citadel.Filter"
    /// Helper protocol the host+extension speak, as citadel-helper versions do (1.3: proxy-capable).
    static let helperProtocol = "1.3.0"
    static let version = "0.1.0"
}

/// The extension's Mach service name, from its Info.plist (team prefix + bundle id).
func filterMachServiceName(bundle: Bundle) -> String? {
    let ne = bundle.object(forInfoDictionaryKey: "NetworkExtension") as? [String: Any]
    return ne?["NEMachServiceName"] as? String
}

/// This process's signing team, or nil for an unsigned (development/CI) build.
func ownTeamIdentifier() -> String? {
    var code: SecCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else { return nil }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
          let dict = info as? [String: Any] else { return nil }
    return dict[kSecCodeInfoTeamIdentifier as String] as? String
}

/// Only processes signed by the same team may talk to us (skipped when unsigned).
func requireSameTeam(_ connection: NSXPCConnection) {
    if let team = ownTeamIdentifier() {
        connection.setCodeSigningRequirement("anchor apple generic and certificate leaf[subject.OU] = \"\(team)\"")
    }
}
