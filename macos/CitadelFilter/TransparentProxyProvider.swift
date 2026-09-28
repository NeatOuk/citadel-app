// Per-app proxy routing on macOS: the connections of apps whose policy says
// "via proxy X" are tunnelled through X (HTTP CONNECT, HTTPS = CONNECT over
// TLS, or SOCKS5), like citadel-proxy does on Linux. It fails closed: if the
// proxy can't be reached or refuses, the app's connection is closed, never
// sent direct, and the error goes to citadel-daemon's proxy log.
import CitadelCore
import Foundation
import Network
import NetworkExtension
import os.log

final class TransparentProxyProvider: NETransparentProxyProvider {
    private let log = Logger(subsystem: CitadelIDs.filterBundle, category: "proxy")

    override func startProxy(options: [String: Any]? = nil, completionHandler: @escaping (Error?) -> Void) {
        FilterService.shared.start()
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.includedNetworkRules = [NENetworkRule(remoteNetwork: nil, remotePrefix: 0, localNetwork: nil,
                                                       localPrefix: 0, protocol: .TCP, direction: .outbound)]
        setTunnelNetworkSettings(settings) { error in completionHandler(error) }
    }

    override func stopProxy(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        completionHandler()
    }

    /// true: we carry the flow (through a proxy); false: it goes direct.
    override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        guard let tcp = flow as? NEAppProxyTCPFlow, let spec = PolicyStore.shared.current(), spec.routesThroughProxy,
              let remote = tcp.remoteEndpoint as? NWHostEndpoint else { return false }
        let app = AppIdentity(token: flow.metaData.sourceAppAuditToken)
        var conn = Conn()
        conn.raddr = remote.hostname
        conn.rport = Int(remote.port) ?? 0
        conn.host = tcp.remoteHostname ?? ""
        conn.exe = app.path
        conn.app = (app.path as NSString).lastPathComponent
        conn.viaId = Launcher.via(pid: Int(app.pid), lookup: ProcessTable.info)?.id ?? ""
        guard let route = spec.route(for: conn) else { return false }
        guard let config = spec.proxies.first(where: { $0.id == route.id }) else {
            // the policy names a proxy that no longer exists: fail closed
            fail(tcp, proxyID: route.id, conn: conn, message: "the proxy of this route no longer exists")
            return true
        }
        ProxyTunnel(flow: tcp, conn: conn, config: config, log: log).start()
        return true
    }

    private func fail(_ flow: NEAppProxyTCPFlow, proxyID: String, conn: Conn, message: String) {
        flow.open(withLocalEndpoint: nil) { _ in
            flow.closeReadWithError(nil)
            flow.closeWriteWithError(nil)
        }
        FilterService.shared.report(["type": "error", "id": proxyID, "dst": conn.raddr, "port": conn.rport, "error": message])
    }
}

/// One app connection carried through a proxy.
final class ProxyTunnel {
    private let flow: NEAppProxyTCPFlow
    private let conn: Conn
    private let config: ProxyConfig
    private let log: Logger
    private var upstream: NWConnection?
    private var closed = false
    private let queue = DispatchQueue(label: "citadel.proxy.tunnel")
    private static var liveTunnels: [ObjectIdentifier: ProxyTunnel] = [:]
    private static let liveLock = NSLock()

    init(flow: NEAppProxyTCPFlow, conn: Conn, config: ProxyConfig, log: Logger) {
        self.flow = flow; self.conn = conn; self.config = config; self.log = log
    }

    func start() {
        Self.liveLock.lock(); Self.liveTunnels[ObjectIdentifier(self)] = self; Self.liveLock.unlock()
        let target = verifiedTarget()
        let params: NWParameters
        if config.type == "https" {
            let tls = NWProtocolTLS.Options()
            if !config.verifyTLS {
                sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, _, done in done(true) }, queue)
            }
            params = NWParameters(tls: tls)
        } else {
            params = .tcp
        }
        let c = NWConnection(host: NWEndpoint.Host(config.host), port: NWEndpoint.Port(integerLiteral: UInt16(clamping: config.port)),
                             using: params)
        upstream = c
        c.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.handshake(target: target)
            case .failed(let e), .waiting(let e):
                self.fail("proxy unreachable: \(e.localizedDescription)")
            default:
                break
            }
        }
        c.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 10) { [weak self] in
            if let self, !self.closed, self.upstream?.state != .ready { self.fail("proxy did not answer in time") }
        }
    }

    /// The host name when it resolves to the address the app connected to, else the address.
    private func verifiedTarget() -> String {
        let name = conn.host
        guard !name.isEmpty else { return conn.raddr }
        var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ai_protocol: 0,
                             ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(name, nil, &hints, &res) == 0, let first = res else { return conn.raddr }
        defer { freeaddrinfo(res) }
        var addrs: [String] = []
        var p: UnsafeMutablePointer<addrinfo>? = first
        while let ai = p {
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                addrs.append(String(cString: host))
            }
            p = ai.pointee.ai_next
        }
        return hostNameUsable(name, for: conn.raddr, resolved: addrs) ? name : conn.raddr
    }

    // MARK: handshake

    private func handshake(target: String) {
        if config.type == "socks5" {
            let login = config.user != nil
            send(ProxyHandshake.socks5Greeting(withLogin: login)) {
                self.read(2) { reply in
                    do {
                        let method = try ProxyHandshake.socks5Method(reply, haveLogin: login)
                        if method == 2 {
                            self.send(ProxyHandshake.socks5Login(user: self.config.user ?? "", password: self.config.password ?? "")) {
                                self.read(2) { r in
                                    do { try ProxyHandshake.socks5LoginOK(r); self.socksConnect(target) } catch { self.fail(error) }
                                }
                            }
                        } else {
                            self.socksConnect(target)
                        }
                    } catch { self.fail(error) }
                }
            }
        } else {
            send(ProxyHandshake.httpConnect(host: target, port: conn.rport, user: config.user, password: config.password)) {
                self.readHead(Data())
            }
        }
    }

    private func socksConnect(_ target: String) {
        send(ProxyHandshake.socks5Connect(host: target, port: conn.rport)) {
            self.read(5) { head in
                do {
                    let total = try ProxyHandshake.socks5ReplyLength(head)
                    self.read(total - 5) { _ in self.openFlow() }
                } catch { self.fail(error) }
            }
        }
    }

    private func readHead(_ sofar: Data) {
        upstream?.receive(minimumIncompleteLength: 1, maximumLength: 8192) { data, _, done, error in
            if let error { self.fail(error); return }
            var buf = sofar
            if let data { buf.append(data) }
            if let end = ProxyHandshake.httpHeadEnd(buf) {
                do {
                    try ProxyHandshake.httpConnectOK(buf.prefix(end))
                    self.openFlow(early: buf.count > end ? buf.suffix(from: buf.startIndex + end) : nil)
                } catch { self.fail(error) }
            } else if done || buf.count > 16384 {
                self.fail("proxy sent no valid answer")
            } else {
                self.readHead(buf)
            }
        }
    }

    // MARK: relay

    private func openFlow(early: Data? = nil) {
        flow.open(withLocalEndpoint: nil) { error in
            if let error { self.fail(error); return }
            if let early, !early.isEmpty { self.flow.write(early) { _ in } }
            self.pumpAppToProxy()
            self.pumpProxyToApp()
        }
    }

    private func pumpAppToProxy() {
        flow.readData { data, error in
            if error != nil || data == nil || data!.isEmpty {
                self.upstream?.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .contentProcessed { _ in })
                self.finishIfDone(appDone: true)
                return
            }
            self.upstream?.send(content: data, completion: .contentProcessed { e in
                if e != nil { self.close() } else { self.pumpAppToProxy() }
            })
        }
    }

    private func pumpProxyToApp() {
        upstream?.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, done, error in
            if let data, !data.isEmpty {
                self.flow.write(data) { e in
                    if e != nil { self.close(); return }
                    if done { self.flow.closeWriteWithError(nil); self.finishIfDone(proxyDone: true) } else { self.pumpProxyToApp() }
                }
            } else if done || error != nil {
                self.flow.closeWriteWithError(nil)
                self.finishIfDone(proxyDone: true)
            } else {
                self.pumpProxyToApp()
            }
        }
    }

    private var appDone = false, proxyDone = false
    private func finishIfDone(appDone a: Bool = false, proxyDone p: Bool = false) {
        queue.async {
            if a { self.appDone = true }
            if p { self.proxyDone = true }
            if self.appDone && self.proxyDone { self.close() }
        }
    }

    // MARK: helpers

    private func send(_ data: Data, then: @escaping () -> Void) {
        upstream?.send(content: data, completion: .contentProcessed { e in if let e { self.fail(e) } else { then() } })
    }

    /// Exactly n bytes from the proxy.
    private func read(_ n: Int, _ then: @escaping (Data) -> Void, sofar: Data = Data()) {
        if n <= 0 { then(sofar); return }
        upstream?.receive(minimumIncompleteLength: 1, maximumLength: n - sofar.count) { data, _, done, error in
            if let error { self.fail(error); return }
            var buf = sofar
            if let data { buf.append(data) }
            if buf.count >= n { then(buf) } else if done { self.fail("proxy closed the connection") }
            else { self.read(n, then, sofar: buf) }
        }
    }

    private func fail(_ error: Error) {
        fail((error as? ProxyHandshake.Failure)?.message ?? error.localizedDescription)
    }

    /// Fail closed: the app's connection is closed, never sent direct.
    private func fail(_ message: String) {
        guard !closed else { return }
        log.error("proxy \(self.config.name, privacy: .public) failed for \(self.conn.raddr, privacy: .public): \(message, privacy: .public)")
        FilterService.shared.report(["type": "error", "id": config.id, "dst": conn.raddr, "port": conn.rport, "error": message])
        flow.open(withLocalEndpoint: nil) { _ in }
        close()
    }

    private func close() {
        guard !closed else { return }
        closed = true
        flow.closeReadWithError(nil)
        flow.closeWriteWithError(nil)
        upstream?.cancel()
        Self.liveLock.lock(); Self.liveTunnels.removeValue(forKey: ObjectIdentifier(self)); Self.liveLock.unlock()
    }
}
