// CitadelCore: the part of Citadel's decision logic the macOS Network
// Extension runs for every new connection. A port of citadel/model.py
// (itself identical to the Omarchy plugin's Model.js); Tests/ replays the
// cases in Fixtures/parity.json, written by tests/tools/make_swift_fixtures.py,
// and requires the same answers.
import Foundation

// MARK: - Values

/// A policy, as the daemon sends it (see citadel/model.py make_rule).
public struct Rule: Equatable {
    public var id: String
    public var profile: String = "*"
    public var app: String = "*"
    public var via: String = "*"
    public var host: String = "*"
    public var port: Int? = nil              // nil = any port ("*")
    public var action: String = "allow"      // allow | deny
    public var route: String = "default"     // default | direct | proxy id
    public var duration: String = "forever"  // forever | untilQuit
    public var pids: [Int] = []

    public init(id: String) { self.id = id }

    public init(json j: [String: Any]) {
        id = j["id"] as? String ?? ""
        profile = j["profile"] as? String ?? "*"
        app = j["app"] as? String ?? "*"
        via = j["via"] as? String ?? "*"
        host = j["host"] as? String ?? "*"
        port = (j["port"] as? NSNumber)?.intValue
        action = j["action"] as? String ?? "allow"
        route = j["route"] as? String ?? "default"
        duration = j["duration"] as? String ?? "forever"
        pids = (j["pids"] as? [NSNumber])?.map { $0.intValue } ?? []
    }
}

/// A connection, as the monitor (or the extension) describes it.
public struct Conn {
    public var exe: String = ""
    public var app: String = ""
    public var raddr: String = ""
    public var rport: Int = 0
    public var host: String = ""
    public var viaId: String = ""
    public var system: Bool = false
    public var list: String = ""

    public init() {}

    public init(json j: [String: Any]) {
        exe = j["exe"] as? String ?? ""
        app = j["app"] as? String ?? ""
        raddr = j["raddr"] as? String ?? ""
        rport = (j["rport"] as? NSNumber)?.intValue ?? 0
        host = j["host"] as? String ?? ""
        viaId = j["viaId"] as? String ?? ""
        system = (j["system"] as? NSNumber)?.boolValue ?? false
        list = j["list"] as? String ?? ""
    }
}

public struct Context {
    public var profile: String = "Default"
    public var mode: String = "guarded"       // guarded | open | lockdown
    public var resolved: [String: [String]] = [:]
    public var alivePids: Set<Int> = []
    public var session: [String: String] = [:]

    public init() {}

    public init(json j: [String: Any]) {
        profile = j["profile"] as? String ?? "Default"
        mode = j["mode"] as? String ?? "guarded"
        resolved = j["resolved"] as? [String: [String]] ?? [:]
        let alive = j["alivePids"] as? [String: Any] ?? [:]
        alivePids = Set(alive.compactMap { k, v in (v as? NSNumber)?.boolValue == true ? Int(k) : nil })
        session = j["session"] as? [String: String] ?? [:]
    }
}

public struct Decision: Equatable {
    public var verdict: String               // allow | deny | prompt | system
    public var source: String                // rule | blocklist | once | silent | none | system
    public var rule: Rule?
    public var list: String?
}

public struct Proxy {
    public var id: String
    public var name: String
    public var listen: Int
    public init(id: String, name: String, listen: Int) { self.id = id; self.name = name; self.listen = listen }
    public init(json j: [String: Any]) {
        id = j["id"] as? String ?? ""
        name = j["name"] as? String ?? ""
        listen = (j["listen"] as? NSNumber)?.intValue ?? 0
    }
}

// MARK: - Addresses

func parseIPv4(_ s: String) -> UInt32? {
    let parts = s.split(separator: ".", omittingEmptySubsequences: false)
    guard parts.count == 4 else { return nil }
    var n: UInt32 = 0
    for p in parts {
        guard (1...3).contains(p.count), p.allSatisfy({ $0.isASCII && $0.isNumber }), let b = UInt32(p), b <= 255 else { return nil }
        n = n * 256 + b
    }
    return n
}

enum Net {
    case v4(net: UInt32, bits: Int)
    case v6(bits: String, prefix: Int)
}

/// "1.2.3.0/24", "1.2.3.4", an IPv6 literal (with optional /len), or nil.
func parseNet(_ s: String) -> Net? {
    let str = s.trimmingCharacters(in: .whitespaces)
    let parts = str.components(separatedBy: "/")
    var bits: Int? = nil
    var badBits = false
    if parts.count > 1 {
        let t = parts[1].trimmingCharacters(in: .whitespaces)
        if t.isEmpty { bits = 0 } else if let b = Int(t) { bits = b } else { badBits = true }
    }
    if let v4 = parseIPv4(parts[0]) {
        if badBits { return nil }
        let b = bits ?? 32
        guard (0...32).contains(b) else { return nil }
        return .v4(net: v4, bits: b)
    }
    let allowed = Set("0123456789abcdefABCDEF:.")
    if parts[0].contains(":") && !parts[0].isEmpty && parts[0].allSatisfy({ allowed.contains($0) }) {
        return .v6(bits: expandIPv6(parts[0]), prefix: badBits ? 0 : (bits ?? 128))
    }
    return nil
}

/// 128 characters of '0'/'1', as model.py expands IPv6 (JS parseInt rules).
func expandIPv6(_ s: String) -> String {
    let str = s.lowercased()
    let halves = str.components(separatedBy: "::")
    let head = halves[0].isEmpty ? [] : halves[0].components(separatedBy: ":")
    let tail = halves.count > 1 && !halves[1].isEmpty ? halves[1].components(separatedBy: ":") : []
    let fill = max(0, 8 - head.count - tail.count)
    let groups = head + Array(repeating: "0", count: fill) + tail
    var out = ""
    for g in groups {
        let digits = (g.isEmpty ? "0" : g).prefix { $0.isHexDigit }
        if let v = UInt64(digits, radix: 16), !digits.isEmpty {
            let b = String(v, radix: 2)
            out += String(repeating: "0", count: max(0, 16 - b.count)) + b
        } else {
            out += "0000000000000NaN"
        }
    }
    return out
}

public func isAddressLike(_ s: String) -> Bool { parseNet(s) != nil }

public func netContains(_ netStr: String, _ ip: String) -> Bool {
    guard let n = parseNet(netStr), let a = parseNet(ip) else { return false }
    switch (n, a) {
    case let (.v4(net, bits), .v4(addr, _)):
        if bits == 0 { return true }
        let shift = UInt32(32 - bits)
        return (net >> shift) == (addr >> shift)
    case let (.v6(nb, prefix), .v6(ab, _)):
        let k = max(0, prefix)
        return nb.prefix(k) == ab.prefix(k)
    default:
        return false
    }
}

// MARK: - Rules

public func normHost(_ h: String?) -> String {
    var s = (h ?? "*").trimmingCharacters(in: .whitespaces).lowercased()
    if s.hasSuffix(".") { s.removeLast() }
    return s.isEmpty ? "*" : s
}

/// "*" or a port 1-65535 (rounded), as model.py norm_port.
public func normPort(_ p: Any?) -> Any {
    if p == nil || p is NSNull { return "*" }
    var n: Double? = nil
    if let s = p as? String {
        let t = s.trimmingCharacters(in: .whitespaces)
        if t.isEmpty || t == "*" { return "*" }
        n = Double(t)
    } else if let num = p as? NSNumber {
        n = num.doubleValue
    }
    guard let v = n, v >= 1, v <= 65535 else { return "*" }
    return Int((v + 0.5).rounded(.down))
}

public func specificity(_ r: Rule) -> Int {
    let app = r.app != "*" && !r.app.isEmpty
    let host = r.host != "*" && !r.host.isEmpty
    var s = app && host ? 30 : host ? 20 : app ? 10 : 0
    if r.port != nil { s += 5 }
    if r.via != "*" && !r.via.isEmpty { s += 3 }
    return s
}

public func hostMatches(_ ruleHost: String, _ c: Conn, _ resolved: [String: [String]]?) -> Bool {
    let h = normHost(ruleHost)
    if h == "*" { return true }
    if isAddressLike(h) { return netContains(h, c.raddr) }
    let name = normHost(c.host)
    if name != "*" && (name == h || name.hasSuffix("." + h)) { return true }
    return resolved?[h]?.contains(c.raddr) ?? false
}

public func ruleActive(_ r: Rule, _ ctx: Context) -> Bool {
    if !r.profile.isEmpty && r.profile != "*" && r.profile != ctx.profile { return false }
    if r.duration == "untilQuit" { return r.pids.contains { ctx.alivePids.contains($0) } }
    return true
}

public func ruleMatches(_ r: Rule, _ c: Conn, _ ctx: Context) -> Bool {
    if !ruleActive(r, ctx) { return false }
    if !r.app.isEmpty && r.app != "*" && r.app != c.exe { return false }
    if !r.via.isEmpty && r.via != "*" && r.via != c.viaId { return false }
    if let p = r.port, p != c.rport { return false }
    return hostMatches(r.host, c, ctx.resolved)
}

/// Most specific matching rule; Block wins ties.
public func bestRule(_ c: Conn, _ rules: [Rule], _ ctx: Context) -> Rule? {
    var best: Rule? = nil
    var bestScore = -1
    for r in rules where ruleMatches(r, c, ctx) {
        let score = specificity(r) * 2 + (r.action == "deny" ? 1 : 0)
        if score > bestScore { best = r; bestScore = score }
    }
    return best
}

public func alertKey(_ c: Conn) -> String {
    let host = normHost(c.host)
    let who = !c.exe.isEmpty ? c.exe : (!c.app.isEmpty ? c.app : "?")
    return [who, c.viaId, host != "*" ? host : c.raddr, String(c.rport)].joined(separator: "|")
}

public func decide(_ c: Conn, _ rules: [Rule], _ ctx: Context) -> Decision {
    if c.system { return Decision(verdict: "system", source: "system", rule: nil, list: nil) }
    if let r = bestRule(c, rules, ctx) { return Decision(verdict: r.action, source: "rule", rule: r, list: nil) }
    if !c.list.isEmpty { return Decision(verdict: "deny", source: "blocklist", rule: nil, list: c.list) }
    if let s = ctx.session[alertKey(c)], !s.isEmpty { return Decision(verdict: s, source: "once", rule: nil, list: nil) }
    if ctx.mode == "open" { return Decision(verdict: "allow", source: "silent", rule: nil, list: nil) }
    if ctx.mode == "lockdown" { return Decision(verdict: "deny", source: "silent", rule: nil, list: nil) }
    return Decision(verdict: "prompt", source: "none", rule: nil, list: nil)
}

/// The proxy that carries this connection, or nil for direct. A route to a
/// proxy that no longer exists is reported as id + "missing proxy".
public func routeFor(_ c: Conn, _ rules: [Rule], _ ctx: Context, defaultRoute: String, proxies: [Proxy]) -> Proxy? {
    if c.system { return nil }
    if let r = bestRule(c, rules, ctx), r.action == "deny" { return nil }
    let routed = bestRule(c, rules.filter { $0.action == "allow" && !$0.route.isEmpty && $0.route != "default" }, ctx)
    let route = routed?.route ?? (defaultRoute.isEmpty ? "direct" : defaultRoute)
    if route == "direct" { return nil }
    return proxies.first { $0.id == route } ?? Proxy(id: route, name: "missing proxy", listen: 0)
}
