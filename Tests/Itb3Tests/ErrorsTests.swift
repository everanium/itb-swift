/*
 * ErrorsTests.swift — error-mapping surface: opaque-string relay,
 * unknown profile, profile registration with an 8-entry `hashes`
 * constellation, duplicate registration, and the mapped status
 * codes.
 */

import Foundation
import XCTest
@testable import Itb3

final class ErrorsTests: XCTestCase {
    func testUnknownProfile() {
        XCTAssertThrowsError(try Pipeline(profile: "no-such-profile")) { error in
            guard let err = error as? ItbError else {
                return XCTFail("not an ItbError: \(error)")
            }
            XCTAssertEqual(err.status, .unknownProfile)
            XCTAssertFalse(err.message.isEmpty, "diagnostic must be non-empty")
        }
        XCTAssertThrowsError(try lookup(name: "no-such-profile")) { error in
            XCTAssertEqual((error as? ItbError)?.status, .unknownProfile)
        }
    }

    func testNegativeMaxWorkersOptsIsClamped() throws {
        let neg = try Opts().set("maxWorkers", "-1")
        let pipe = try Pipeline(profile: "singlemsg-triple-mac-v1", opts: neg)
        XCTAssertFalse(try pipe.save().isEmpty)
    }

    func testUnknownOptsKey() throws {
        // Typoed lowercase s — rejected Go-side, not by the binding.
        let bad = try Opts().set("chunksize", "4096")
        XCTAssertThrowsError(
            try Pipeline(profile: "singlemsg-triple-mac-v1", opts: bad)
        ) { error in
            XCTAssertEqual((error as? ItbError)?.status, .badInput)
        }
    }

    func testUnknownInnerHash() throws {
        // An unknown inner-hash name is relayed to Go and rejected
        // there — the binding performs no name validation of its own.
        let hash = try Opts().set("innerHash", "no-such-hash")
        XCTAssertThrowsError(
            try Pipeline(profile: "singlemsg-triple-mac-v1", opts: hash))
    }

    func testRegisterAndDuplicate() throws {
        // 8-entry width-256 hashes constellation, layers off.
        var reg = Profile()
        reg.mode = "singlemsg-nomac"
        reg.width = 256
        reg.mixedHashes = ["blake3", "blake2s", "areion256", "blake2b256",
                           "chacha20", "blake3", "blake2s", "areion256"]
        reg.keyBits = 1024
        try register(name: "swift-binding-test-mixed", profile: reg)

        // The registered profile round-trips and reads back.
        let sender = try Pipeline(profile: "swift-binding-test-mixed")
        let receiver = try Pipeline(load: try sender.save())
        let plain = Data("custom profile".utf8)
        let back = try receiver.decryptMessage(try sender.encryptMessage(plain))
        XCTAssertEqual(back, plain)
        let looked = try lookup(name: "swift-binding-test-mixed")
        XCTAssertEqual(looked.name, "swift-binding-test-mixed")
        XCTAssertEqual(looked.mixedHashes, reg.mixedHashes)

        // Duplicate name is a distinct status.
        XCTAssertThrowsError(
            try register(name: "swift-binding-test-mixed", profile: reg)
        ) { error in
            XCTAssertEqual((error as? ItbError)?.status, .profileExists)
        }

        // A non-empty name inside the record must equal the argument.
        var mismatch = try lookup(name: "singlemsg-triple-nomac-v1")
        mismatch.name = "some-other-name"
        XCTAssertThrowsError(
            try register(name: "swift-binding-test-mismatch", profile: mismatch)
        ) { error in
            XCTAssertEqual((error as? ItbError)?.status, .badInput)
        }
    }

    func testStatusLabels() {
        XCTAssertFalse(Status.ok.label.isEmpty)
        XCTAssertFalse(Status.macFailure.label.isEmpty)
        XCTAssertFalse(Status.internalError.label.isEmpty)
    }

    func testFreedStreamRejectsUse() throws {
        let pipe = try Pipeline(profile: "streaming-aead-triple-mac-v1")
        let session = try pipe.encryptStream()
        session.free()
        session.free() // idempotent
        XCTAssertThrowsError(try session.write(Data([1, 2, 3]))) { error in
            XCTAssertEqual((error as? ItbError)?.status, .badInput)
        }
    }
}
