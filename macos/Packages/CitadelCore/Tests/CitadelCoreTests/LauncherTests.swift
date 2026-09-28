// The launcher ("started by") must match the monitor's origin() on the
// fixture's process trees, with the same name sets.
import Foundation
import XCTest
@testable import CitadelCore

final class LauncherTests: XCTestCase {
    private func fixture() throws -> [String: Any] {
        let url = try XCTUnwrap(Bundle.module.url(forResource: "parity", withExtension: "json", subdirectory: "Fixtures"))
        let f = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [String: Any])
        return try XCTUnwrap(f["launcher"] as? [String: Any])
    }

    func testSameNameSets() throws {
        let sets = try XCTUnwrap(fixture()["sets"] as? [String: [String]])
        XCTAssertEqual(Set(sets["shells"] ?? []), Launcher.shells)
        XCTAssertEqual(Set(sets["interpreters"] ?? []), Launcher.interpreters)
        XCTAssertEqual(Set(sets["terminals"] ?? []), Launcher.terminals)
        XCTAssertEqual(Set(sets["managers"] ?? []), Launcher.managers)
    }

    func testViaLikeTheMonitor() throws {
        let cases = try XCTUnwrap(fixture()["cases"] as? [[String: Any]])
        XCTAssertGreaterThan(cases.count, 50)
        for (n, c) in cases.enumerated() {
            var table: [Int: ProcInfo] = [:]
            for case let p as [String: Any] in c["procs"] as? [Any] ?? [] {
                let pid = (p["pid"] as! NSNumber).intValue
                table[pid] = ProcInfo(pid: pid, ppid: (p["ppid"] as! NSNumber).intValue, comm: p["comm"] as! String,
                                      exe: p["exe"] as! String, args: p["args"] as! [String])
            }
            let got = Launcher.via(pid: (c["pid"] as! NSNumber).intValue) { table[$0] }
            let want = c["want"] as? [String: String]
            XCTAssertEqual(got?.id, want?["id"], "case \(n) id")
            XCTAssertEqual(got?.name, want?["name"], "case \(n) name")
            XCTAssertEqual(got?.kind, want?["kind"], "case \(n) kind")
        }
    }
}
