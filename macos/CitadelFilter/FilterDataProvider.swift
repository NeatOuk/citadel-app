// Decides every new outbound connection with CitadelCore, the same logic as
// Citadel on Linux. Phase 2 skeleton: policies come from a JSON file the
// host writes; the gate (pausing a flow until the user answers) and the
// link to citadel-daemon are the next steps.
import CitadelCore
import Foundation
import NetworkExtension
import os.log

final class FilterDataProvider: NEFilterDataProvider {
    private let log = Logger(subsystem: "io.github.neatouk.Citadel.Filter", category: "filter")
    private let store = PolicyStore.shared

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        // every outbound TCP/UDP flow comes to handleNewFlow; the rest passes
        let outbound = NENetworkRule(remoteNetwork: nil, remotePrefix: 0, localNetwork: nil, localPrefix: 0,
                                     protocol: .any, direction: .outbound)
        let settings = NEFilterSettings(rules: [NEFilterRule(networkRule: outbound, action: .filterData)],
                                        defaultAction: .allow)
        apply(settings) { error in
            if let error { self.log.error("filter settings failed: \(error.localizedDescription, privacy: .public)") }
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socket = flow as? NEFilterSocketFlow,
              let remote = socket.remoteEndpoint as? NWHostEndpoint else { return .allow() }
        var conn = Conn()
        conn.raddr = remote.hostname
        conn.rport = Int(remote.port) ?? 0
        conn.host = socket.remoteHostname ?? ""
        let app = AppIdentity(token: flow.sourceAppAuditToken)
        conn.exe = app.path
        conn.app = (app.path as NSString).lastPathComponent
        let snapshot = store.snapshot()
        let d = decide(conn, snapshot.rules, snapshot.context)
        switch d.verdict {
        case "deny":
            log.info("blocked \(conn.app, privacy: .public) -> \(conn.raddr, privacy: .public):\(conn.rport)")
            return .drop()
        case "prompt":
            // next step: pause the flow and ask the gate (citadel-daemon)
            return .allow()
        default:
            return .allow()
        }
    }
}

/// The app behind a flow, from its audit token: pid, then the program path.
struct AppIdentity {
    let pid: pid_t
    let path: String

    init(token: Data?) {
        var pid: pid_t = 0
        if let token, token.count >= MemoryLayout<audit_token_t>.size {
            // audit_token_t is eight 32-bit words; the process id is word 5
            pid = token.withUnsafeBytes { raw in pid_t(bitPattern: raw.load(fromByteOffset: 5 * 4, as: UInt32.self)) }
        }
        self.pid = pid
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let n = pid > 0 ? proc_pidpath(pid, &buf, UInt32(buf.count)) : 0
        self.path = n > 0 ? String(cString: buf) : ""
    }
}

/// The current policies and context. The host app (later: citadel-daemon via
/// the host) writes them as JSON; the filter reads them on change.
final class PolicyStore {
    static let shared = PolicyStore()
    struct Snapshot {
        var rules: [Rule] = []
        var context = Context()
    }
    private let lock = NSLock()
    private var current = Snapshot()

    func snapshot() -> Snapshot {
        lock.lock(); defer { lock.unlock() }
        return current
    }

    func update(fromJSON data: Data) {
        guard let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return }
        var s = Snapshot()
        s.rules = (j["rules"] as? [[String: Any]] ?? []).map(Rule.init(json:))
        s.context = Context(json: j["ctx"] as? [String: Any] ?? [:])
        lock.lock(); current = s; lock.unlock()
    }
}
