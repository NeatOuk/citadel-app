import Foundation
import XCTest
@testable import CitadelCore

final class SpecTests: XCTestCase {
    func testDecodesTheDaemonsSpec() throws {
        let json = """
        {"format":"citadel-macos-1",
         "rules":[{"id":"r1","profile":"*","app":"/usr/bin/curl","via":"*","host":"example.com","port":"*",
                   "action":"deny","route":"default","duration":"forever","pids":[]}],
         "ctx":{"profile":"Home","mode":"guarded","resolved":{"example.com":["93.184.216.34"]},"session":{},"alivePids":{}},
         "gate":{"default":"deny","timeout":30},"defaultRoute":"direct","proxies":[]}
        """
        let spec = try XCTUnwrap(Spec(json: Data(json.utf8)))
        XCTAssertEqual(spec.rules.count, 1)
        XCTAssertFalse(spec.gateAllows)
        XCTAssertEqual(spec.gateTimeout, 30)
        var c = Conn()
        c.exe = "/usr/bin/curl"; c.raddr = "93.184.216.34"; c.rport = 443
        XCTAssertEqual(decide(c, spec.rules, spec.context).verdict, "deny", "matched through the resolved address")
        c.exe = "/usr/bin/git"
        XCTAssertEqual(decide(c, spec.rules, spec.context).verdict, "prompt")
    }

    func testRoutes() throws {
        let json = """
        {"format":"citadel-macos-1","rules":[{"id":"r","app":"/usr/bin/curl","host":"*","port":"*","action":"allow",
          "route":"p1","profile":"*","via":"*","duration":"forever","pids":[]}],
         "ctx":{"profile":"Default","mode":"guarded"},"gate":{},"defaultRoute":"direct",
         "proxies":[{"id":"p1","name":"Office","type":"socks5","host":"192.0.2.10","port":1080,"user":"alice","password":"x"}]}
        """
        let spec = try XCTUnwrap(Spec(json: Data(json.utf8)))
        XCTAssertTrue(spec.routesThroughProxy)
        XCTAssertEqual(spec.proxies.first?.user, "alice")
        var c = Conn(); c.exe = "/usr/bin/curl"; c.raddr = "203.0.113.5"; c.rport = 443
        XCTAssertEqual(spec.route(for: c)?.id, "p1")
        c.exe = "/usr/bin/git"
        XCTAssertNil(spec.route(for: c), "no route: direct")
    }

    func testRejectsOtherFormats() {
        XCTAssertNil(Spec(json: Data(#"{"rules":[]}"#.utf8)))
        XCTAssertNil(Spec(json: Data("not json".utf8)))
    }

    func testGateBook() {
        let book = GateBook<String>()
        let t0 = Date(timeIntervalSince1970: 1000)
        book.add("a", "flow-a", timeout: 10, now: t0)
        book.add("b", "flow-b", timeout: 60, now: t0)
        XCTAssertEqual(book.count, 2)
        XCTAssertEqual(book.expired(now: t0.addingTimeInterval(5)), [])
        XCTAssertEqual(book.expired(now: t0.addingTimeInterval(11)), ["flow-a"])
        XCTAssertEqual(book.take(["b", "zzz"]), ["flow-b"])
        XCTAssertEqual(book.count, 0)
        book.add("c", "flow-c", timeout: 60, now: t0)
        XCTAssertEqual(book.drain(), ["flow-c"])
    }
}
