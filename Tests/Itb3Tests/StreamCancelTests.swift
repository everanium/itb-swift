/*
 * StreamCancelTests.swift — freeing an encrypt session mid-flight
 * (without end) releases resources cleanly and leaves the Pipeline
 * usable; ARC deinit covers the implicit-release path.
 */

import Foundation
import XCTest
@testable import Itb3

final class StreamCancelTests: XCTestCase {
    func testCancelMidFlightLeavesPipelineUsable() throws {
        let sender = try Pipeline(profile: "streaming-aead-triple-mac-v1")

        let chunk = testPayload(100_000, seed: 0xA5A5_A5A5)
        let session = try sender.encryptStream()
        try session.write(chunk)
        // Freed here without end() — StreamFree cancels the session.
        session.free()

        // A second session dropped to ARC without an explicit free.
        do {
            let dropped = try sender.encryptStream()
            try dropped.write(chunk)
        }

        // The Pipeline stays usable after the cancelled sessions.
        let receiver = try Pipeline(load: try sender.save())
        let wire = try sender.encryptStreamPump(chunk)
        let back = try receiver.decryptStreamPump(wire)
        XCTAssertEqual(back, chunk)
    }
}
