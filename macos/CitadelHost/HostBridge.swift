// The host app's bridge: citadel-daemon talks to it over a Unix socket
// ($TMPDIR/citadel/host.sock, JSON lines, same user only) the way it talks
// to citadel-helper on Linux; the host passes the calls to the network
// filter extension over XPC and forwards paused flows back to the daemon.
// See citadel/platform/hostbridge.py for the other end.
import Darwin
import Foundation
import NetworkExtension
import os.log

final class HostBridge: NSObject, HostXPC {
    static let shared = HostBridge()
    private let log = Logger(subsystem: "io.github.neatouk.Citadel", category: "bridge")
    private var filter: NSXPCConnection?
    private var subscribers: [FileHandle] = []
    private let lock = NSLock()

    // MARK: - Unix socket for citadel-daemon

    static var socketPath: String {
        let base = (NSTemporaryDirectory() as NSString).appendingPathComponent("citadel")
        return (base as NSString).appendingPathComponent("host.sock")
    }

    func start() {
        let path = Self.socketPath
        let dir = (path as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { log.error("socket() failed"); return }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8CString)
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in
            for (i, b) in bytes.prefix(buf.count - 1).enumerated() { buf[i] = UInt8(bitPattern: b) }
        }
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard ok == 0, Darwin.listen(fd, 8) == 0 else { log.error("bind/listen failed on \(path, privacy: .public)"); close(fd); return }
        chmod(path, 0o600)
        Thread.detachNewThread { [weak self] in
            while true {
                let client = Darwin.accept(fd, nil, nil)
                if client < 0 { continue }
                var uid: uid_t = 0, gid: gid_t = 0
                guard getpeereid(client, &uid, &gid) == 0, uid == getuid() else { close(client); continue }
                Thread.detachNewThread { self?.serve(client) }
            }
        }
        log.info("listening on \(path, privacy: .public)")
    }

    private func serve(_ fd: Int32) {
        let conn = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var buffer = Data()
        while true {
            let chunk = conn.availableData
            if chunk.isEmpty { break }
            buffer.append(chunk)
            while let nl = buffer.firstIndex(of: 0x0A) {
                let line = buffer.subdata(in: buffer.startIndex..<nl)
                buffer.removeSubrange(buffer.startIndex...nl)
                guard let msg = try? JSONSerialization.jsonObject(with: line) as? [String: Any] else { continue }
                if msg["cmd"] as? String == "subscribe" {
                    lock.lock(); subscribers.append(conn); lock.unlock()
                    continue                                      // keep the connection for events
                }
                handle(msg) { reply in
                    if let data = try? JSONSerialization.data(withJSONObject: reply) {
                        conn.write(data + Data([0x0A]))
                    }
                }
            }
        }
        lock.lock(); subscribers.removeAll { $0 === conn }; lock.unlock()
    }

    /// One daemon request -> {"id", "code", "out", "err"} (citadel-enforcer style).
    private func handle(_ msg: [String: Any], reply: @escaping ([String: Any]) -> Void) {
        let id = msg["id"] ?? 0
        let args = msg["args"] as? [String: Any] ?? [:]
        func done(_ code: Int, _ out: String = "", _ err: String = "") { reply(["id": id, "code": code, "out": out, "err": err]) }
        guard let f = filterProxy(onError: { done(1, "", "Citadel's network extension is not reachable: \($0.localizedDescription)") })
        else { done(1, "", "Citadel's network extension is not installed or not enabled"); return }
        switch msg["cmd"] as? String {
        case "status":
            f.status { data in done(0, String(decoding: data, as: UTF8.self)) }
        case "apply":
            guard let spec = args["spec"], let data = try? JSONSerialization.data(withJSONObject: spec) else { done(1, "", "no spec"); return }
            ExtensionController.shared.setFilter(enabled: true)
            f.apply(data) { ok, err in done(ok ? 0 : 1, "", err) }
        case "feeds":
            guard let data = try? JSONSerialization.data(withJSONObject: args) else { done(1, "", "bad feeds"); return }
            f.setFeeds(data) { ok in done(ok ? 0 : 1) }
        case "resolve":
            let ids = args["flows"] as? [String] ?? []
            f.resolve(ids, allow: (args["allow"] as? Bool) ?? true)
            done(0)
        case "off":
            f.off { ok in done(ok ? 0 : 1) }
            ExtensionController.shared.setFilter(enabled: false)
        case "kill":
            // macOS: new policies already apply to new connections; dropping
            // established ones comes with the flow watcher (next step)
            done(0, "0")
        default:
            done(2, "", "unknown command")
        }
    }

    // MARK: - XPC to the extension

    private func filterProxy(onError: @escaping (Error) -> Void) -> FilterXPC? {
        lock.lock(); defer { lock.unlock() }
        if filter == nil {
            guard let ext = extensionBundle(), let name = filterMachServiceName(bundle: ext) else { return nil }
            let c = NSXPCConnection(machServiceName: name, options: .privileged)
            requireSameTeam(c)
            c.remoteObjectInterface = NSXPCInterface(with: FilterXPC.self)
            c.exportedInterface = NSXPCInterface(with: HostXPC.self)
            c.exportedObject = self
            c.invalidationHandler = { [weak self] in self?.lock.lock(); self?.filter = nil; self?.lock.unlock() }
            c.interruptionHandler = { [weak self] in self?.lock.lock(); self?.filter = nil; self?.lock.unlock() }
            c.resume()
            filter = c
        }
        return filter?.remoteObjectProxyWithErrorHandler(onError) as? FilterXPC
    }

    private func extensionBundle() -> Bundle? {
        let url = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/SystemExtensions")
            .appendingPathComponent(CitadelIDs.filterBundle + ".systemextension")
        return Bundle(url: url)
    }

    // MARK: HostXPC (called by the extension)

    func flowPaused(_ info: Data) {
        lock.lock(); let subs = subscribers; lock.unlock()
        if subs.isEmpty {
            // no daemon listening: the extension's own deadline applies the default
            return
        }
        for s in subs { s.write(info + Data([0x0A])) }
    }
}
