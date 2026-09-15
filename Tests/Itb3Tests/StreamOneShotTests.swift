/*
 * StreamOneShotTests.swift — round trip through the whole-buffer
 * stream one-shot pair on a Streaming AEAD profile, wire
 * interchangeability with the stream pumps, and tamper rejection.
 */

import Foundation
import XCTest
@testable import Itb3

final class StreamOneShotTests: XCTestCase {
    func testOneShotRoundTrip() throws {
        let sender = try Pipeline(profile: "streaming-aead-triple-mac-v1")
        let receiver = try Pipeline(load: try sender.save())

        let plain = testPayload(1 << 20, seed: 0x51D3_A7C1)
        let wire = try sender.encryptStreamOneShot(plain)
        XCTAssertFalse(wire.isEmpty)
        let back = try receiver.decryptStreamOneShot(wire)
        XCTAssertEqual(back, plain)
    }

    func testOneShotMatchesPumpWire() throws {
        let sender = try Pipeline(profile: "streaming-aead-triple-mac-v1")
        let receiver = try Pipeline(load: try sender.save())

        let plain = testPayload(65536, seed: 0xB005_EED1)
        let wire = try sender.encryptStreamOneShot(plain)

        // The one-shot wire is a stream wire: the pump decrypts it,
        // and the one-shot decrypts a pump-produced wire.
        XCTAssertEqual(try receiver.decryptStreamPump(wire), plain)

        let pumpWire = try sender.encryptStreamPump(plain)
        XCTAssertEqual(try receiver.decryptStreamOneShot(pumpWire), plain)
    }

    func testTamperedWireFails() throws {
        let sender = try Pipeline(profile: "streaming-aead-triple-mac-v1")
        let receiver = try Pipeline(load: try sender.save())

        let plain = testPayload(65536, seed: 0x0E5B)
        let wire = try sender.encryptStreamOneShot(plain)

        // A single bit flip can land in the container's CSPRNG
        // residue, where the decrypt legitimately completes clean —
        // probe successive positions until one lands in authenticated
        // content. The probe is black-box.
        var seenFailure = false
        for attempt in 0..<32 where !seenFailure {
            let pos = (wire.count * 3 / 4 + attempt * 1031) % wire.count
            var tampered = wire
            tampered[pos] ^= 0x01
            do {
                let back = try receiver.decryptStreamOneShot(tampered)
                // Flip landed in unauthenticated residue.
                XCTAssertEqual(back, plain)
            } catch let error as ItbError {
                XCTAssertEqual(error.status, .macFailure,
                               "flip @\(pos): expected MAC failure, got \(error)")
                seenFailure = true
            }
        }
        XCTAssertTrue(seenFailure,
                      "no flip position produced an authentication failure")

        // The untampered wire still round-trips.
        XCTAssertEqual(try receiver.decryptStreamOneShot(wire), plain)
    }

    func testAsyncOneShotRoundTrip() async throws {
        let sender = try Pipeline(profile: "streaming-aead-triple-mac-v1")
        let receiver = try Pipeline(load: try sender.save())

        let plain = testPayload(300_000, seed: 0xA5C3)
        let wire: Data = try await sender.encryptStreamOneShot(plain)
        let back: Data = try await receiver.decryptStreamOneShot(wire)
        XCTAssertEqual(back, plain)
    }
}
