/*
 * SmokeTests.swift — Init → save → load → encryptMessage →
 * decryptMessage round trip, plus the Result-shaped and async
 * variants of the same path.
 */

import Foundation
import XCTest
@testable import Itb3

final class SmokeTests: XCTestCase {
    func testMessageRoundTrip() throws {
        let sender = try Pipeline(profile: "singlemsg-triple-mac-v1")
        XCTAssertFalse(try sender.save().isEmpty, "blob must be non-empty")

        let receiver = try Pipeline(load: try sender.save())

        let plain = Data("smoke round-trip payload".utf8)
        let wire = try sender.encryptMessage(plain)
        XCTAssertNotEqual(wire, plain, "wire must differ from plaintext")

        let back = try receiver.decryptMessage(wire)
        XCTAssertEqual(back, plain)
    }

    func testMessageRoundTripResult() throws {
        let sender = try Pipeline(profile: "singlemsg-triple-mac-v1")
        let receiver = try Pipeline(load: try sender.save())

        let plain = testPayload(4096, seed: 0x5EED)
        switch sender.encryptMessageResult(plain) {
        case .failure(let err):
            XCTFail("encrypt: \(err)")
        case .success(let wire):
            switch receiver.decryptMessageResult(wire) {
            case .failure(let err):
                XCTFail("decrypt: \(err)")
            case .success(let back):
                XCTAssertEqual(back, plain)
            }
        }
    }

    func testMessageRoundTripAsync() async throws {
        let sender = try Pipeline(profile: "singlemsg-triple-mac-v1")
        let receiver = try Pipeline(load: try sender.save())

        let plain = testPayload(65536, seed: 0xA51C)
        let wire = try await sender.encryptMessage(plain)
        let back = try await receiver.decryptMessage(wire)
        XCTAssertEqual(back, plain)
    }
}
