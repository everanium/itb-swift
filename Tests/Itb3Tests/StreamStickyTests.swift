/*
 * StreamStickyTests.swift — a decrypt session fed a tampered wire
 * fails with a sticky MAC failure.
 *
 * A single bit flip can land in the container's CSPRNG residue —
 * over-sized container area that carries no payload — where the
 * decrypt legitimately completes clean. The test therefore probes
 * successive flip positions, each against a fresh session on a fresh
 * copy of the wire, until one lands in authenticated content; the
 * observed failure must be MAC failure and must be sticky. The probe
 * is black-box — no wire-layout knowledge is used.
 */

import Foundation
import XCTest
@testable import Itb3

final class StreamStickyTests: XCTestCase {
    /// Feeds one tampered wire copy through a fresh decrypt session.
    /// Returns false when the session finishes clean (flip landed in
    /// unauthenticated residue), true when it failed with the
    /// expected sticky MAC failure.
    private func probeOnce(_ receiver: Pipeline, _ wire: Data,
                           flip pos: Int) throws -> Bool {
        var tampered = wire
        tampered[pos] ^= 0x01

        let session = try receiver.decryptStream()
        defer { session.free() }

        // The failure may surface on write (chain already failed) or
        // on a later read — either way a read must eventually report
        // it, so write/end results are deliberately ignored here.
        try? session.write(tampered)
        try? session.end()

        do {
            while true {
                let (_, finished) = try session.read(max: 4096)
                if finished {
                    return false // flip landed in unauthenticated residue
                }
            }
        } catch let error as ItbError {
            XCTAssertEqual(error.status, .macFailure,
                           "flip @\(pos): expected MAC failure, got \(error)")
            // Sticky: a subsequent read reports the same status.
            XCTAssertThrowsError(try session.read(max: 16)) { second in
                XCTAssertEqual((second as? ItbError)?.status, error.status)
            }
            return true
        }
    }

    func testTamperedWireFailsSticky() throws {
        let sender = try Pipeline(profile: "streaming-aead-triple-mac-v1")
        let receiver = try Pipeline(load: try sender.save())

        let plain = testPayload(65536, seed: 0x7A3B)
        let wire = try sender.encryptStreamPump(plain)
        XCTAssertFalse(wire.isEmpty)

        var seenFailure = false
        for attempt in 0..<32 where !seenFailure {
            let pos = (wire.count * 3 / 4 + attempt * 1031) % wire.count
            seenFailure = try probeOnce(receiver, wire, flip: pos)
        }
        XCTAssertTrue(seenFailure,
                      "no flip position produced an authentication failure")

        // The untampered wire still round-trips on a fresh session.
        let back = try receiver.decryptStreamPump(wire)
        XCTAssertEqual(back, plain)
    }
}
