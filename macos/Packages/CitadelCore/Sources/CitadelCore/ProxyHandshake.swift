// The bytes of a tunnel through a proxy, as citadel-proxy (Python) sends
// and reads them on Linux: SOCKS5 (RFC 1928, username/password RFC 1929)
// and HTTP CONNECT (optionally over TLS for HTTPS proxies, with Basic auth).
import Foundation

public enum ProxyHandshake {
    public struct Failure: Error, Equatable {
        public let message: String
        init(_ m: String) { message = m }
    }

    // MARK: SOCKS5

    /// Greeting: offer "no auth", plus "username/password" when we have a login.
    public static func socks5Greeting(withLogin: Bool) -> Data {
        Data(withLogin ? [0x05, 0x02, 0x00, 0x02] : [0x05, 0x01, 0x00])
    }

    /// The method the proxy chose (0 = none, 2 = username/password) from its 2-byte reply.
    public static func socks5Method(_ reply: Data, haveLogin: Bool) throws -> UInt8 {
        let b = [UInt8](reply)
        guard b.count >= 2, b[0] == 0x05 else { throw Failure("not a SOCKS5 proxy") }
        switch b[1] {
        case 0x00: return 0
        case 0x02:
            guard haveLogin else { throw Failure("proxy wants a username/password") }
            return 2
        default: throw Failure("proxy offers no usable login method")
        }
    }

    public static func socks5Login(user: String, password: String) -> Data {
        let u = Array(user.utf8.prefix(255)), p = Array(password.utf8.prefix(255))
        return Data([0x01, UInt8(u.count)] + u + [UInt8(p.count)] + p)
    }

    public static func socks5LoginOK(_ reply: Data) throws {
        let b = [UInt8](reply)
        guard b.count >= 2, b[1] == 0x00 else { throw Failure("proxy rejected the username/password") }
    }

    /// CONNECT to an IPv4/IPv6 address, or to a host name (address type 3).
    public static func socks5Connect(host: String, port: Int) -> Data {
        var out: [UInt8] = [0x05, 0x01, 0x00]
        if let v4 = parseIPv4(host) {
            out += [0x01, UInt8(v4 >> 24 & 0xff), UInt8(v4 >> 16 & 0xff), UInt8(v4 >> 8 & 0xff), UInt8(v4 & 0xff)]
        } else if case let .v6(bits, _)? = parseNet(host), host.contains(":") {
            out.append(0x04)
            var i = bits.startIndex
            for _ in 0..<16 {
                let j = bits.index(i, offsetBy: 8)
                out.append(UInt8(bits[i..<j], radix: 2) ?? 0)
                i = j
            }
        } else {
            let name = Array(host.utf8.prefix(255))
            out += [0x03, UInt8(name.count)] + name
        }
        out += [UInt8(port >> 8 & 0xff), UInt8(port & 0xff)]
        return Data(out)
    }

    /// Total length of the CONNECT reply once its first 5 bytes are known, or throws on refusal.
    public static func socks5ReplyLength(_ head: Data) throws -> Int {
        let b = [UInt8](head)
        guard b.count >= 5, b[0] == 0x05 else { throw Failure("not a SOCKS5 proxy") }
        if b[1] != 0 {
            let reasons: [UInt8: String] = [1: "general failure", 2: "not allowed by ruleset", 3: "network unreachable",
                                            4: "host unreachable", 5: "connection refused", 6: "TTL expired"]
            throw Failure("proxy: " + (reasons[b[1]] ?? "error \(b[1])"))
        }
        switch b[3] {
        case 0x01: return 4 + 4 + 2
        case 0x04: return 4 + 16 + 2
        case 0x03: return 4 + 1 + Int(b[4]) + 2
        default: throw Failure("proxy sent an unknown address type")
        }
    }

    // MARK: HTTP CONNECT

    public static func httpConnect(host: String, port: Int, user: String? = nil, password: String? = nil) -> Data {
        let h = host.contains(":") ? "[\(host)]" : host
        var lines = ["CONNECT \(h):\(port) HTTP/1.1", "Host: \(h):\(port)"]
        if let user {
            let token = Data("\(user):\(password ?? "")".utf8).base64EncodedString()
            lines.append("Proxy-Authorization: Basic \(token)")
        }
        return Data((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
    }

    /// Whether the response head (up to the blank line) is complete: the index after it.
    public static func httpHeadEnd(_ data: Data) -> Int? {
        let b = [UInt8](data)
        guard b.count >= 4 else { return nil }
        for i in 0...(b.count - 4) where b[i] == 13 && b[i + 1] == 10 && b[i + 2] == 13 && b[i + 3] == 10 { return i + 4 }
        return nil
    }

    /// Throws unless the proxy answered 200.
    public static func httpConnectOK(_ head: Data) throws {
        let first = String(decoding: head.prefix { $0 != 13 && $0 != 10 }, as: UTF8.self)
        let parts = first.split(separator: " ")
        guard parts.count >= 2, parts[1] == "200" else { throw Failure("proxy answered " + String(first.prefix(80))) }
    }
}

/// A host name the app asked for may be used instead of the IP only when it
/// resolves to that IP (as citadel-proxy's verified_name): an app can't name
/// another host to get past a block.
public func hostNameUsable(_ name: String, for ip: String, resolved: [String]) -> Bool {
    guard !name.isEmpty, !isAddressLike(name), name.count <= 253 else { return false }
    let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_")
    guard name.allSatisfy({ allowed.contains($0) }) else { return false }
    return resolved.contains { r in r == ip || r == "::ffff:" + ip }
}
