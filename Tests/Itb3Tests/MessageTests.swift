/*
 * MessageTests.swift — Single Message round trip across every
 * shipped cipher-bearing profile at small (4 KiB) and medium
 * (256 KiB) payloads.
 */

import Foundation
import XCTest
@testable import Itb3

final class MessageTests: XCTestCase {
    static let profiles = [
        "streaming-aead-triple-mac-v1",
        "streaming-noaead-triple-v1",
        "singlemsg-triple-mac-v1",
        "singlemsg-triple-nomac-v1",
        "streaming-aead-triple-mac-mixed-v1",
        "streaming-noaead-triple-mixed-v1",
        "singlemsg-triple-mac-mixed-v1",
        "singlemsg-triple-nomac-mixed-v1",
    ]

    func testRoundTripEveryProfile() throws {
        for profile in Self.profiles {
            for size in [4 * 1024, 256 * 1024] {
                let sender = try Pipeline(profile: profile)
                let receiver = try Pipeline(load: try sender.save())
                let plain = testPayload(size, seed: UInt64(size))
                let wire = try sender.encryptMessage(plain)
                let back = try receiver.decryptMessage(wire)
                XCTAssertEqual(back, plain, "\(profile) @\(size)")
            }
        }
    }
}
