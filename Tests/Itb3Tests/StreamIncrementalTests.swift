/*
 * StreamIncrementalTests.swift — explicit write / end / read round
 * trip with pathological batch sizes (17-byte feed, 23-byte drain),
 * finishing the drain through the session's AsyncSequence.
 */

import Foundation
import XCTest
@testable import Itb3

final class StreamIncrementalTests: XCTestCase {
    private func feedDrain(_ session: StreamSession, _ src: Data) async throws -> Data {
        for off in stride(from: 0, to: src.count, by: 17) {
            let end = min(off + 17, src.count)
            try await session.write(src.subdata(in: off..<end))
        }
        try await session.end()
        var out = Data()
        for try await chunk in session.chunks(max: 23) {
            out.append(chunk)
        }
        return out
    }

    func testPathologicalBatchSizes() async throws {
        let sender = try Pipeline(profile: "streaming-aead-triple-mac-v1")
        let receiver = try Pipeline(load: try sender.save())

        let plain = testPayload(200_000, seed: 0x1717)
        let wire = try await feedDrain(try sender.encryptStream(), plain)
        XCTAssertFalse(wire.isEmpty)
        let back = try await feedDrain(try receiver.decryptStream(), wire)
        XCTAssertEqual(back, plain)
    }
}
