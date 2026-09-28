// Decides every new outbound connection with CitadelCore, the same logic as
// Citadel on Linux. Policies come from citadel-daemon through the host app.
// A connection no policy covers is paused and waits at the gate: the host
// tells the daemon, and the answer resumes it (allowed or dropped). With no
// host, or when nobody answers in time, the gate's default applies.
import CitadelCore
import Foundation
import NetworkExtension
import os.log

final class FilterDataProvider: NEFilterDataProvider {
    static weak var current: FilterDataProvider?
    let log = Logger(subsystem: CitadelIDs.filterBundle, category: "filter")
    let store = PolicyStore.shared
    let gate = GateBook<NEFilterFlow>()
    private var timer: DispatchSourceTimer?
    private(set) var drops = 0

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        FilterDataProvider.current = self
        FilterService.shared.start()
        // every outbound TCP/UDP flow comes to handleNewFlow; the rest passes
        let outbound = NENetworkRule(remoteNetwork: nil, remotePrefix: 0, localNetwork: nil, localPrefix: 0,
                                     protocol: .any, direction: .outbound)
        let settings = NEFilterSettings(rules: [NEFilterRule(networkRule: outbound, action: .filterData)],
                                        defaultAction: .allow)
        apply(settings) { error in
            if let error { self.log.error("filter settings failed: \(error.localizedDescription, privacy: .public)") }
            completionHandler(error)
        }
        let t = DispatchSource.makeTimerSource(queue: .global())
        t.schedule(deadline: .now() + 1, repeating: 1)
        t.setEventHandler { [weak self] in self?.expireGate() }
        t.resume()
        timer = t
    }

    override func stopFilter(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        timer?.cancel()
        releaseAll()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let spec = store.current() else { return .allow() }          // nothing applied yet: not filtering
        guard let socket = flow as? NEFilterSocketFlow,
              let remote = socket.remoteEndpoint as? NWHostEndpoint else { return .allow() }
        var conn = Conn()
        conn.raddr = remote.hostname
        conn.rport = Int(remote.port) ?? 0
        conn.host = socket.remoteHostname ?? ""
        let app = AppIdentity(token: flow.sourceAppAuditToken)
        conn.exe = app.path
        conn.app = (app.path as NSString).lastPathComponent
        // "started by": only worth the process-table walk when a policy asks for it
        let via = spec.rules.contains { $0.via != "*" && !$0.via.isEmpty && $0.app == conn.exe } || spec.context.mode == "guarded"
            ? Launcher.via(pid: Int(app.pid), lookup: ProcessTable.info) : nil
        conn.viaId = via?.id ?? ""
        conn.list = store.feeds().match(host: conn.host, ip: conn.raddr)
        let d = decide(conn, spec.rules, spec.context)
        switch d.verdict {
        case "deny":
            drops += 1
            log.info("blocked \(conn.app, privacy: .public) -> \(conn.raddr, privacy: .public):\(conn.rport)")
            return .drop()
        case "prompt":
            let id = flow.identifier.uuidString
            guard FilterService.shared.flowPaused(id: id, conn: conn, via: via, pid: app.pid, proto: socket.socketProtocol) else {
                return spec.gateAllows ? .allow() : .drop()                    // no one to ask
            }
            gate.add(id, flow, timeout: spec.gateTimeout + 5)                  // the daemon answers first
            return .pause()
        default:
            return .allow()
        }
    }

    func resolve(_ ids: [String], allow: Bool) {
        for flow in gate.take(ids) {
            if !allow { drops += 1 }
            resumeFlow(flow, with: allow ? NEFilterNewFlowVerdict.allow() : NEFilterNewFlowVerdict.drop())
        }
    }

    private func expireGate() {
        let allows = store.current()?.gateAllows ?? true
        for flow in gate.expired() {
            resumeFlow(flow, with: allows ? NEFilterNewFlowVerdict.allow() : NEFilterNewFlowVerdict.drop())
        }
    }

    /// Let everything that waits go (filtering switched off, or the host left).
    func releaseAll() {
        let allows = store.current()?.gateAllows ?? true
        for flow in gate.drain() {
            resumeFlow(flow, with: allows ? NEFilterNewFlowVerdict.allow() : NEFilterNewFlowVerdict.drop())
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

/// The spec the daemon applied, or nil when filtering is off.
final class PolicyStore {
    static let shared = PolicyStore()           // the filter and the proxy provider share it
    private let lock = NSLock()
    private var spec: Spec?
    private var blocklist = Blocklist()

    func current() -> Spec? { lock.lock(); defer { lock.unlock() }; return spec }
    func set(_ s: Spec?) { lock.lock(); spec = s; lock.unlock() }
    func feeds() -> Blocklist { lock.lock(); defer { lock.unlock() }; return blocklist }
    func setFeeds(_ b: Blocklist) { lock.lock(); blocklist = b; lock.unlock() }
}

/// The extension's XPC service for the host app.
final class FilterService: NSObject, NSXPCListenerDelegate, FilterXPC {
    static let shared = FilterService()
    private var listener: NSXPCListener?
    private var host: NSXPCConnection?
    private let lock = NSLock()

    func start() {
        guard listener == nil, let name = filterMachServiceName(bundle: .main) else { return }
        let l = NSXPCListener(machServiceName: name)
        l.delegate = self
        l.resume()
        listener = l
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection c: NSXPCConnection) -> Bool {
        requireSameTeam(c)
        c.exportedInterface = NSXPCInterface(with: FilterXPC.self)
        c.exportedObject = self
        c.remoteObjectInterface = NSXPCInterface(with: HostXPC.self)
        c.invalidationHandler = { [weak self, weak c] in
            self?.lock.lock()
            if self?.host === c { self?.host = nil }
            self?.lock.unlock()
        }
        lock.lock(); host = c; lock.unlock()
        c.resume()
        return true
    }

    /// Something for citadel-daemon (e.g. a proxy error), through the host.
    func report(_ event: [String: Any]) {
        lock.lock(); let h = host; lock.unlock()
        guard let proxy = h?.remoteObjectProxyWithErrorHandler({ _ in }) as? HostXPC,
              let data = try? JSONSerialization.data(withJSONObject: event) else { return }
        proxy.event(data)
    }

    /// Tell the host a flow waits at the gate. False when no host is connected.
    func flowPaused(id: String, conn: Conn, via: Via?, pid: pid_t, proto: Int32) -> Bool {
        lock.lock(); let h = host; lock.unlock()
        guard let proxy = h?.remoteObjectProxyWithErrorHandler({ _ in }) as? HostXPC else { return false }
        let info: [String: Any] = ["type": "flow", "id": id, "exe": conn.exe, "raddr": conn.raddr, "rport": conn.rport,
                                   "host": conn.host, "proto": proto == IPPROTO_UDP ? "udp" : "tcp", "pid": Int(pid),
                                   "via": via?.name ?? "", "viaId": via?.id ?? "", "viaKind": via?.kind ?? ""]
        guard let data = try? JSONSerialization.data(withJSONObject: info) else { return false }
        proxy.flowPaused(data)
        return true
    }

    // MARK: FilterXPC
    func apply(_ spec: Data, withReply reply: @escaping (Bool, String) -> Void) {
        guard let s = Spec(json: spec) else { reply(false, "not a citadel-macos-1 spec"); return }
        PolicyStore.shared.set(s)
        reply(true, "")
    }

    func status(withReply reply: @escaping (Data) -> Void) {
        let p = FilterDataProvider.current
        let spec = p?.store.current()
        let info: [String: Any] = ["active": spec != nil, "drops": p?.drops ?? 0, "rules": spec?.rules.count ?? 0,
                                   "logging": false, "proxy": false, "pending": p?.gate.count ?? 0,
                                   "version": CitadelIDs.helperProtocol, "impl": "macos-filter " + CitadelIDs.version]
        reply((try? JSONSerialization.data(withJSONObject: info)) ?? Data())
    }

    func resolve(_ flowIDs: [String], allow: Bool) {
        FilterDataProvider.current?.resolve(flowIDs, allow: allow)
    }

    func setFeeds(_ feeds: Data, withReply reply: @escaping (Bool) -> Void) {
        guard let b = Blocklist(data: feeds) else { reply(false); return }
        PolicyStore.shared.setFeeds(b)
        reply(true)
    }

    func off(withReply reply: @escaping (Bool) -> Void) {
        PolicyStore.shared.set(nil)
        FilterDataProvider.current?.releaseAll()
        reply(true)
    }
}
