/*
 * RekeyTests.swift — Init → rekey → load receiver with the rotated
 * blob → round trip.
 */

import Foundation
import XCTest
@testable import Itb3

final class RekeyTests: XCTestCase {
    func testRekeyRefreshesBlobAndRoundTrips() throws {
        let sender = try Pipeline(profile: "singlemsg-triple-mac-v1")
        let before = try sender.save()

        let perm = Data(repeating: 0x11, count: 32)
        let wrap = Data(repeating: 0x22, count: 32)
        let rotated = try sender.rekey(permMaster: perm, wrapMaster: wrap)
        XCTAssertNotEqual(rotated, before, "rekey must refresh the blob")
        XCTAssertEqual(try sender.save(), rotated, "save must report the rotated blob")

        let receiver = try Pipeline(load: rotated)
        let plain = testPayload(32768, seed: 0xBEEF)
        let wire = try sender.encryptMessage(plain)
        let back = try receiver.decryptMessage(wire)
        XCTAssertEqual(back, plain)
    }
}
