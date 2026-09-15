/*
 * StreamPumpTests.swift — round trip through the whole-buffer stream
 * pumps on a Streaming AEAD profile at 1 MiB, plus the AsyncSequence
 * transform round trip over the same profile.
 */

import Foundation
import XCTest
@testable import Itb3

final class StreamPumpTests: XCTestCase {
    func testPumpRoundTrip() throws {
        let sender = try Pipeline(profile: "streaming-aead-triple-mac-v1")
        let receiver = try Pipeline(load: try sender.save())

        let plain = testPayload(1 << 20, seed: 0x9E37_79B9)
        let wire = try sender.encryptStreamPump(plain)
        XCTAssertFalse(wire.isEmpty)
        let back = try receiver.decryptStreamPump(wire)
        XCTAssertEqual(back, plain)
    }

    func testAsyncSequenceRoundTrip() async throws {
        let sender = try Pipeline(profile: "streaming-aead-triple-mac-v1")
        let receiver = try Pipeline(load: try sender.save())

        let plain = testPayload(300_000, seed: 0xCAFE)
        // Feed the plaintext as an async sequence of 64 KiB chunks.
        let chunks = stride(from: 0, to: plain.count, by: 1 << 16).map {
            plain.subdata(in: $0..<min($0 + (1 << 16), plain.count))
        }
        var wire = Data()
        for try await produced in sender.encryptStream(from: AsyncArray(chunks)) {
            wire.append(produced)
        }
        var back = Data()
        for try await produced in receiver.decryptStream(from: AsyncArray([wire])) {
            back.append(produced)
        }
        XCTAssertEqual(back, plain)
    }
}

/// Minimal async wrapper over an array, for feeding the transforms.
struct AsyncArray<Element: Sendable>: AsyncSequence, Sendable {
    let items: [Element]

    init(_ items: [Element]) {
        self.items = items
    }

    func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(items: items)
    }

    struct AsyncIterator: AsyncIteratorProtocol {
        var items: [Element]

        mutating func next() async -> Element? {
            items.isEmpty ? nil : items.removeFirst()
        }
    }
}
