// Bytes must match what citadel-proxy (Python) sends on Linux.
import Foundation
import XCTest
@testable import CitadelCore

final class ProxyHandshakeTests: XCTestCase {
    typealias H = ProxyHandshake

    func testSocks5() throws {
        XCTAssertEqual([UInt8](H.socks5Greeting(withLogin: true)), [5, 2, 0, 2])
        XCTAssertEqual([UInt8](H.socks5Greeting(withLogin: false)), [5, 1, 0])
        XCTAssertEqual(try H.socks5Method(Data([5, 2]), haveLogin: true), 2)
        XCTAssertThrowsError(try H.socks5Method(Data([5, 2]), haveLogin: false))
        XCTAssertThrowsError(try H.socks5Method(Data([5, 0xff]), haveLogin: true))
        XCTAssertEqual([UInt8](H.socks5Login(user: "alice", password: "s3cret")),
                       [1, 5] + Array("alice".utf8) + [6] + Array("s3cret".utf8))
        XCTAssertNoThrow(try H.socks5LoginOK(Data([1, 0])))
        XCTAssertThrowsError(try H.socks5LoginOK(Data([1, 1])))
        XCTAssertEqual([UInt8](H.socks5Connect(host: "10.99.0.1", port: 9000)), [5, 1, 0, 1, 10, 99, 0, 1, 0x23, 0x28])
        let v6 = [UInt8](H.socks5Connect(host: "2001:db8::1", port: 443))
        XCTAssertEqual(Array(v6.prefix(4)), [5, 1, 0, 4])
        XCTAssertEqual(Array(v6[4..<8]), [0x20, 0x01, 0x0d, 0xb8])
        XCTAssertEqual(v6[19], 1)
        XCTAssertEqual(Array(v6.suffix(2)), [0x01, 0xbb])
        XCTAssertEqual([UInt8](H.socks5Connect(host: "example.com", port: 80)),
                       [5, 1, 0, 3, 11] + Array("example.com".utf8) + [0, 80])
        XCTAssertEqual(try H.socks5ReplyLength(Data([5, 0, 0, 1, 0])), 10)
        XCTAssertEqual(try H.socks5ReplyLength(Data([5, 0, 0, 3, 7])), 14)
        XCTAssertThrowsError(try H.socks5ReplyLength(Data([5, 5, 0, 1, 0]))) { e in
            XCTAssertEqual((e as? H.Failure)?.message, "proxy: connection refused")
        }
    }

    func testHttpConnect() throws {
        let req = String(decoding: H.httpConnect(host: "10.99.0.1", port: 9000, user: "alice", password: "s3cret"), as: UTF8.self)
        XCTAssertEqual(req, "CONNECT 10.99.0.1:9000 HTTP/1.1\r\nHost: 10.99.0.1:9000\r\n"
                          + "Proxy-Authorization: Basic YWxpY2U6czNjcmV0\r\n\r\n")
        XCTAssertTrue(String(decoding: H.httpConnect(host: "2001:db8::1", port: 443), as: UTF8.self)
                        .hasPrefix("CONNECT [2001:db8::1]:443 HTTP/1.1"))
        let head = Data("HTTP/1.1 200 Connection established\r\n\r\nrest".utf8)
        XCTAssertEqual(H.httpHeadEnd(head), 39)
        XCTAssertNil(H.httpHeadEnd(Data("HTTP/1.1 200 OK\r\n".utf8)))
        XCTAssertNoThrow(try H.httpConnectOK(head))
        XCTAssertThrowsError(try H.httpConnectOK(Data("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n".utf8)))
    }

    func testVerifiedHostName() {
        XCTAssertTrue(hostNameUsable("outlook.office.com", for: "52.96.1.2", resolved: ["52.96.1.2", "52.96.1.3"]))
        XCTAssertFalse(hostNameUsable("evil.example", for: "52.96.1.2", resolved: ["6.6.6.6"]))
        XCTAssertFalse(hostNameUsable("a.example\r\nX: 1", for: "1.2.3.4", resolved: ["1.2.3.4"]))
        XCTAssertFalse(hostNameUsable("1.2.3.4", for: "1.2.3.4", resolved: ["1.2.3.4"]))
    }
}
