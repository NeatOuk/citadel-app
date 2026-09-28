// Replays Fixtures/parity.json: the answers citadel/model.py (and so the
// Omarchy plugin's Model.js) gives. CitadelCore must give the same ones.
import Foundation
import XCTest
@testable import CitadelCore

final class ParityTests: XCTestCase {
    private func fixture() throws -> [String: Any] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "parity", withExtension: "json", subdirectory: "Fixtures"))
        return try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
    }

    func testDecisionsRoutesAndKeys() throws {
        let f = try fixture()
        let groups = try XCTUnwrap(f["groups"] as? [[String: Any]])
        var checked = 0
        for (g, group) in groups.enumerated() {
            let rules = (group["rules"] as? [[String: Any]] ?? []).map(Rule.init(json:))
            let conns = (group["conns"] as? [[String: Any]] ?? []).map(Conn.init(json:))
            let ctx = Context(json: group["ctx"] as? [String: Any] ?? [:])
            let proxies = (group["proxies"] as? [[String: Any]] ?? []).map(Proxy.init(json:))
            let defaultRoute = group["defaultRoute"] as? String ?? "direct"
            let results = group["results"] as? [[String: Any]] ?? []
            for (i, c) in conns.enumerated() {
                let want = results[i]
                let w = want["decide"] as? [String: Any] ?? [:]
                let d = decide(c, rules, ctx)
                let where_ = "group \(g) conn \(i)"
                XCTAssertEqual(d.verdict, w["verdict"] as? String, "verdict, \(where_)")
                XCTAssertEqual(d.source, w["source"] as? String, "source, \(where_)")
                XCTAssertEqual(d.rule?.id, w["rule"] as? String, "rule, \(where_)")
                XCTAssertEqual(d.list, w["list"] as? String, "list, \(where_)")
                XCTAssertEqual(alertKey(c), want["alertKey"] as? String, "alertKey, \(where_)")
                XCTAssertEqual(routeFor(c, rules, ctx, defaultRoute: defaultRoute, proxies: proxies)?.id,
                               want["route"] as? String, "route, \(where_)")
                if let spec = want["specificity"] as? [NSNumber] {
                    XCTAssertEqual(rules.map(specificity), spec.map { $0.intValue }, "specificity, group \(g)")
                }
                checked += 1
            }
        }
        XCTAssertGreaterThan(checked, 500)
    }

    func testAddresses() throws {
        let f = try fixture()
        for case let c as [String: Any] in f["netContains"] as? [Any] ?? [] {
            let net = c["net"] as! String, ip = c["ip"] as! String
            XCTAssertEqual(netContains(net, ip), (c["want"] as! NSNumber).boolValue, "netContains(\(net), \(ip))")
        }
    }

    func testNormalisation() throws {
        let f = try fixture()
        for case let c as [String: Any] in f["normHost"] as? [Any] ?? [] {
            XCTAssertEqual(normHost(c["in"] as? String), c["want"] as? String, "normHost(\(String(describing: c["in"])))")
        }
        for case let c as [String: Any] in f["normPort"] as? [Any] ?? [] {
            let got = normPort(c["in"])
            if let w = c["want"] as? String {
                XCTAssertEqual(got as? String, w, "normPort(\(String(describing: c["in"])))")
            } else {
                XCTAssertEqual(got as? Int, (c["want"] as? NSNumber)?.intValue, "normPort(\(String(describing: c["in"])))")
            }
        }
    }
}
