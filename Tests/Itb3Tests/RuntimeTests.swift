/*
 * Runtime diagnostics surface: GOMAXPROCS query / set / restore, the
 * heap-profile writer, the pool-counter snapshot and its slot layout,
 * the hash-registry enumeration, and the diagnostic's survival of a
 * text wider than the relay layer's inline buffer.
 */

import Foundation
import Glibc
import XCTest
@testable import Itb3

final class RuntimeTests: XCTestCase {
    /// Zero queries, a positive value sets and returns the previous
    /// one; the query never changes the setting.
    func testGOMAXPROCS() {
        let orig = ItbRuntime.setGOMAXPROCS(0)
        XCTAssertGreaterThan(orig, 0)
        XCTAssertEqual(ItbRuntime.setGOMAXPROCS(-3), orig, "a negative query must not change the value")
        XCTAssertEqual(ItbRuntime.setGOMAXPROCS(orig + 1), orig)
        XCTAssertEqual(ItbRuntime.setGOMAXPROCS(0), orig + 1)
        XCTAssertEqual(ItbRuntime.setGOMAXPROCS(orig), orig + 1)
    }

    /// A real path yields a non-empty file; an empty path with the
    /// environment fallback unset is rejected.
    func testWriteHeapProfile() throws {
        let path = FileManager.default.temporaryDirectory
            .appendingPathComponent("itb-swift-heap-\(getpid()).pprof").path
        try ItbRuntime.writeHeapProfile(path)
        let size = (try FileManager.default.attributesOfItem(atPath: path)[.size] as? Int) ?? 0
        XCTAssertGreaterThan(size, 0, "heap profile file is empty")
        try? FileManager.default.removeItem(atPath: path)

        unsetenv("ITB_MEMPROFILE")
        XCTAssertThrowsError(try ItbRuntime.writeHeapProfile("")) { error in
            XCTAssertEqual((error as? ItbError)?.status, .badInput)
        }
    }

    /// The length query sizes the buffer, and the filled buffer
    /// carries the tier count in slot 0 under the 1 + 5*T + 8 layout.
    func testPoolStats() throws {
        let len = ItbRuntime.poolStatsLen
        XCTAssertGreaterThanOrEqual(len, 9)
        let slots = try ItbRuntime.poolStats()
        XCTAssertEqual(slots.count, len)
        let tiers = Int(slots[0])
        XCTAssertGreaterThan(tiers, 0)
        XCTAssertEqual(1 + 5 * tiers + 8, len, "tier count does not match the slot count")
    }

    /// The shipped registry in canonical order, led by the Non-PRF
    /// inner primitive and carrying the harness default.
    func testHashNames() throws {
        let names = try hashNames()
        XCTAssertEqual(names.first, "aesitb128")
        XCTAssertTrue(names.contains("areion512"), "registry: \(names)")
    }

    /// The auto DRBG tier is one of the two fill ciphers, resolved
    /// per host.
    func testDrbgAutoTier() {
        let tier = ItbRuntime.drbgAutoTier
        XCTAssertTrue(tier == "aes-256-ctr" || tier == "chacha20", "drbg auto tier: \(tier)")
    }

    /// The diagnostic is the only text an error carries, so no fixed
    /// buffer may bound it. The relay layer snapshots the library's
    /// text into an inline 2 KiB buffer and widens on the
    /// short-buffer return; a path the caller makes far longer than
    /// that is echoed back inside the os diagnostic, so an intact
    /// tail proves the widening branch ran rather than the text
    /// having been truncated at the boundary.
    func testWideDiagnosticSurvivesTheBoundary() {
        let tail = "zzzz-tail-marker"
        let longName = String(repeating: "a", count: 4000) + tail
        let path = "/tmp/" + longName
        XCTAssertThrowsError(try ItbRuntime.writeHeapProfile(path)) { error in
            guard let err = error as? ItbError else {
                return XCTFail("not an ItbError: \(error)")
            }
            XCTAssertGreaterThan(err.message.utf8.count, 2048,
                                 "diagnostic was clipped to the inline buffer: \(err.message.utf8.count) bytes")
            XCTAssertTrue(err.message.contains(tail),
                          "the end of the diagnostic was lost")
            XCTAssertTrue(err.message.hasSuffix("file name too long"),
                          "the reason at the end of the sentence was lost: \(err.message.suffix(40))")
        }
    }
}
