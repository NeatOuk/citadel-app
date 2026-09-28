// Threat feeds inside the network extension: IP ranges and domain lists,
// matched like citadel/monitor/common.py (ip_list_match, list_match):
// the first IP list whose range holds the address, else the first domain
// list holding the host or one of its parent domains.
import Foundation

public struct Blocklist {
    private struct IPList {
        let id: String
        var v4: [Int: Set<UInt32>] = [:]        // prefix length -> network addresses
        var v6: [Int: Set<String>] = [:]        // prefix length -> leading bits
    }
    private var ipLists: [IPList] = []
    private var domainLists: [(id: String, domains: Set<String>)] = []

    public init() {}

    /// [{"id", "kind": "ip"|"domain", "entries": [...]}] in feed order.
    public init(json lists: [[String: Any]]) {
        for l in lists {
            let id = l["id"] as? String ?? ""
            let entries = l["entries"] as? [String] ?? []
            if (l["kind"] as? String) == "ip" {
                var list = IPList(id: id)
                for e in entries {
                    switch parseNet(e) {
                    case let .v4(net, bits)?:
                        let masked = bits == 0 ? 0 : (net >> UInt32(32 - bits)) << UInt32(32 - bits)
                        list.v4[bits, default: []].insert(masked)
                    case let .v6(b, prefix)?:
                        list.v6[prefix, default: []].insert(String(b.prefix(prefix)))
                    case nil:
                        continue
                    }
                }
                ipLists.append(list)
            } else {
                domainLists.append((id, Set(entries.map { $0.lowercased() })))
            }
        }
    }

    /// The `feeds` message: {"feeds": [...]} as the daemon sends it.
    public init?(data: Data) {
        guard let j = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let lists = j["feeds"] as? [[String: Any]] else { return nil }
        self.init(json: lists)
    }

    public var isEmpty: Bool { ipLists.isEmpty && domainLists.isEmpty }

    /// The id of the first feed that lists this address or host, else "".
    public func match(host: String, ip: String) -> String {
        if !ip.isEmpty, let hit = ipMatch(ip) { return hit }
        var h = host.lowercased()
        while h.hasSuffix(".") { h.removeLast() }
        if h.isEmpty || domainLists.isEmpty { return "" }
        let parts = h.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard parts.count > 1 else { return "" }
        for i in 0..<(parts.count - 1) {
            let cand = parts[i...].joined(separator: ".")
            for l in domainLists where l.domains.contains(cand) { return l.id }
        }
        return ""
    }

    private func ipMatch(_ ip: String) -> String? {
        switch parseNet(ip) {
        case let .v4(addr, _)?:
            for l in ipLists {
                for (bits, nets) in l.v4 {
                    let masked = bits == 0 ? 0 : (addr >> UInt32(32 - bits)) << UInt32(32 - bits)
                    if nets.contains(masked) { return l.id }
                }
            }
        case let .v6(b, _)?:
            for l in ipLists {
                for (prefix, nets) in l.v6 where nets.contains(String(b.prefix(prefix))) { return l.id }
            }
        case nil:
            break
        }
        return nil
    }
}
