/*
 * EncryptStream.swift — incremental stream sessions over itb_stream.
 *
 * StreamSession is the shared base for both directions: a dumb byte
 * pump (write / end / read) whose chunking, MAC, envelope, and wire
 * format all stay inside libitb3. A session strongly pins its parent
 * Pipeline so ARC can never release the Pipeline while a session is
 * open; the session itself frees its C handle on deinit (or on an
 * explicit free()), and itb_stream_free cancels safely from any
 * state — mid-flight, mid-error, or after a clean drain.
 */

import CItb
import Foundation

public class StreamSession: @unchecked Sendable {
    /// Strong reference: the session must not outlive its Pipeline.
    public let parent: Pipeline
    private var raw: OpaquePointer?
    private let lock = NSLock()

    init(raw: OpaquePointer, parent: Pipeline) {
        self.raw = raw
        self.parent = parent
    }

    deinit {
        free()
    }

    /// Cancels (if still running) and releases the session.
    /// Idempotent; every later call on the session fails with
    /// `.badInput`.
    public func free() {
        lock.lock()
        let handle = raw
        raw = nil
        lock.unlock()
        if let handle {
            itb_stream_free(handle)
        }
    }

    private func handle() throws -> OpaquePointer {
        lock.lock()
        defer { lock.unlock() }
        guard let raw else {
            throw ItbError(c: ITB_STATUS_BAD_INPUT)
        }
        return raw
    }

    /// Feeds bytes into the session. Blocks until the cipher chain
    /// accepts them; errors are sticky. Empty data is a no-op.
    public func write(_ data: Data) throws {
        let handle = try handle()
        try data.withItbBytes { ptr, len in
            try check(itb_stream_write(handle, ptr, len))
        }
    }

    /// Signals end-of-input. Idempotent; a write after end fails with
    /// `.badInput`.
    public func end() throws {
        try check(itb_stream_end(try handle()))
    }

    /// Drains up to `max` produced bytes. `finished` turns true once
    /// the session has ended AND the output is fully drained. Partial
    /// drains are the normal mode; a pre-end read never blocks, an
    /// after-end read on an empty spool blocks until the terminal
    /// bytes arrive or the session errors.
    public func read(max: Int = 1 << 16) throws -> (data: Data, finished: Bool) {
        let handle = try handle()
        var buf = Data(count: max)
        var n = 0
        var fin: Int32 = 0
        try buf.withUnsafeMutableBytes { rawBuf in
            let base = rawBuf.bindMemory(to: UInt8.self).baseAddress
            try check(itb_stream_read(handle, base, max, &n, &fin))
        }
        buf.removeSubrange(n..<buf.count)
        return (buf, fin != 0)
    }

    /// Async variant of `write`.
    public func write(_ data: Data) async throws {
        try await offBlocking { try self.write(data) }
    }

    /// Async variant of `end`.
    public func end() async throws {
        try await offBlocking { try self.end() }
    }

    /// Async variant of `read`.
    public func read(max: Int = 1 << 16) async throws -> (data: Data, finished: Bool) {
        try await offBlocking { try self.read(max: max) }
    }

    /// The produced bytes as an `AsyncSequence` of chunks, ending
    /// after the terminal drain. Intended for the drain side of a
    /// session (typically after `end()`); while input is still being
    /// fed, an empty spool yields a short pause instead of a chunk.
    public func chunks(max: Int = 1 << 16) -> StreamChunks {
        StreamChunks(session: self, max: max)
    }
}

/// AsyncSequence of drained output chunks of a StreamSession.
public struct StreamChunks: AsyncSequence, Sendable {
    public typealias Element = Data

    let session: StreamSession
    let max: Int

    public func makeAsyncIterator() -> AsyncIterator {
        AsyncIterator(session: session, max: max)
    }

    public struct AsyncIterator: AsyncIteratorProtocol {
        let session: StreamSession
        let max: Int
        var finished = false

        public mutating func next() async throws -> Data? {
            while !finished {
                try Task.checkCancellation()
                let (data, fin) = try await session.read(max: max)
                finished = fin
                if !data.isEmpty {
                    return data
                }
                if !fin {
                    // Pre-end empty spool: back off instead of spinning.
                    try await Task.sleep(nanoseconds: 1_000_000)
                }
            }
            return nil
        }
    }
}

/// Incremental encrypt session: plaintext in, wire out.
public final class EncryptStream: StreamSession, @unchecked Sendable {}
