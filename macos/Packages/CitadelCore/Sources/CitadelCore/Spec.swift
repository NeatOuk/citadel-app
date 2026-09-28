// The spec citadel-daemon sends the network extension on macOS
// (citadel/model.py build_spec_darwin), and the book of paused flows that
// wait at the gate.
import Foundation

/// A proxy from Settings, with its login (sent in memory only).
public struct ProxyConfig: Equatable {
    public var id = "", name = "", type = "http", host = "", port = 0
    public var user: String? = nil, password: String? = nil
    public var verifyTLS = true
    public init() {}
    public init(json j: [String: Any]) {
        id = j["id"] as? String ?? ""
        name = j["name"] as? String ?? id
        type = j["type"] as? String ?? "http"
        host = j["host"] as? String ?? ""
        port = (j["port"] as? NSNumber)?.intValue ?? 0
        user = j["user"] as? String
        password = j["password"] as? String
        verifyTLS = (j["verifyTls"] as? NSNumber)?.boolValue ?? true
    }
}

public struct Spec {
    public var rules: [Rule] = []
    public var context = Context()
    /// What an unanswered gate request becomes when its time runs out.
    public var gateAllows = true
    public var gateTimeout: TimeInterval = 90
    public var defaultRoute = "direct"
    public var proxies: [ProxyConfig] = []

    /// Does any policy (or the default route) send traffic through a proxy?
    public var routesThroughProxy: Bool {
        guard !proxies.isEmpty else { return false }
        return defaultRoute != "direct" || rules.contains { $0.action == "allow" && $0.route != "default" && $0.route != "direct" }
    }

    /// The proxy (or a missing one) that carries this connection, nil for direct.
    public func route(for c: Conn) -> Proxy? {
        routeFor(c, rules, context, defaultRoute: defaultRoute,
                 proxies: proxies.map { Proxy(id: $0.id, name: $0.name, listen: 0) })
    }

    public init() {}

    public init?(json data: Data) {
        guard let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              (j["format"] as? String) == "citadel-macos-1" else { return nil }
        rules = (j["rules"] as? [[String: Any]] ?? []).map(Rule.init(json:))
        context = Context(json: j["ctx"] as? [String: Any] ?? [:])
        let gate = j["gate"] as? [String: Any] ?? [:]
        gateAllows = (gate["default"] as? String) != "deny"
        if let t = (gate["timeout"] as? NSNumber)?.doubleValue, t > 0 { gateTimeout = t }
        defaultRoute = j["defaultRoute"] as? String ?? "direct"
        proxies = (j["proxies"] as? [[String: Any]] ?? []).map(ProxyConfig.init(json:))
    }
}

/// Flows paused until the gate answers, each with a deadline. Thread-safe.
public final class GateBook<Item> {
    private struct Entry { let item: Item; let deadline: Date }
    private var entries: [String: Entry] = [:]
    private let lock = NSLock()

    public init() {}

    public var count: Int { lock.lock(); defer { lock.unlock() }; return entries.count }

    public func add(_ id: String, _ item: Item, timeout: TimeInterval, now: Date = Date()) {
        lock.lock(); defer { lock.unlock() }
        entries[id] = Entry(item: item, deadline: now.addingTimeInterval(timeout))
    }

    /// The paused items for these ids, removed from the book (unknown ids are ignored).
    public func take(_ ids: [String]) -> [Item] {
        lock.lock(); defer { lock.unlock() }
        return ids.compactMap { entries.removeValue(forKey: $0)?.item }
    }

    /// Items whose time ran out, removed from the book.
    public func expired(now: Date = Date()) -> [Item] {
        lock.lock(); defer { lock.unlock() }
        let late = entries.filter { $0.value.deadline <= now }
        late.keys.forEach { entries.removeValue(forKey: $0) }
        return late.map { $0.value.item }
    }

    /// Everything still waiting, removed (e.g. the host went away).
    public func drain() -> [Item] {
        lock.lock(); defer { lock.unlock() }
        let all = entries.map { $0.value.item }
        entries.removeAll()
        return all
    }
}
