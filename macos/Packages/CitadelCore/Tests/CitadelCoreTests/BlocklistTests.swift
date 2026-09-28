// Feed matching must answer like the Linux monitor's list_match (the
// fixture's expected ids come from it).
import Foundation
import XCTest
@testable import CitadelCore

final class BlocklistTests: XCTestCase {
    func testMatchesLikeTheMonitor() throws {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "parity", withExtension: "json", subdirectory: "Fixtures"))
        let f = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        let b = try XCTUnwrap(f["blocklist"] as? [String: Any])
        let list = Blocklist(json: b["feeds"] as? [[String: Any]] ?? [])
        for case let q as [String: Any] in b["queries"] as? [Any] ?? [] {
            let host = q["host"] as? String ?? "", ip = q["ip"] as? String ?? ""
            XCTAssertEqual(list.match(host: host, ip: ip), q["want"] as? String, "match(\(host), \(ip))")
        }
    }

    func testFeedsMessage() {
        let data = Data(#"{"feeds":[{"id":"x","kind":"domain","entries":["ads.example.com"]}]}"#.utf8)
        XCTAssertEqual(Blocklist(data: data)?.match(host: "a.ads.example.com", ip: ""), "x")
        XCTAssertNil(Blocklist(data: Data("{}".utf8)))
    }
}
