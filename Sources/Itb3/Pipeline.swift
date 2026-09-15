/*
 * Pipeline.swift — Triple Pipeline session over itb_pipeline.
 *
 * A reference type: ARC finalisation calls itb_pipeline_free (which
 * runs Close Go-side, zeroing key material). Buffer sizing — the
 * caller-allocated-buffer convention with the retry-once on
 * BUFFER_TOO_SMALL — lives entirely inside the C binding layer; the
 * Swift layer moves opaque bytes and relays status codes.
 *
 * Concurrency: the class is marked @unchecked Sendable so the async
 * variants can hop to a background task. The C-side contract carries
 * over unchanged — rekey must not run concurrently with cipher calls
 * or open stream sessions on the same Pipeline.
 */

import CItb
import Foundation

public final class Pipeline: @unchecked Sendable {
    let raw: OpaquePointer

    // MARK: Lifecycle

    private init(raw: OpaquePointer) {
        self.raw = raw
    }

    /// Constructs a fresh Pipeline against the named profile.
    public convenience init(profile: String, opts: Opts? = nil) throws {
        var out: OpaquePointer?
        try check(itb_pipeline_init(profile, opts?.raw, &out))
        guard let out else {
            throw ItbError(c: ITB_STATUS_INTERNAL)
        }
        self.init(raw: out)
    }

    /// Reconstructs a Pipeline from a blob produced by `save` / `rekey`.
    /// Omit the masters to use the blob-embedded pair; supply both to
    /// override them (the pair is validated by libitb3). The profile
    /// shape travels inside the blob — no profile name, no opts. A
    /// blob whose record names a primitive absent from the local build
    /// throws `.recipePrimitiveUnknown`; a record failing the profile
    /// field rules `.blobMalformedRecipe`.
    public convenience init(load blob: Data,
                            permMaster: Data? = nil, wrapMaster: Data? = nil) throws {
        var out: OpaquePointer?
        try blob.withItbBytes { blobPtr, blobLen in
            try (permMaster ?? Data()).withItbBytes { permPtr, permLen in
                try (wrapMaster ?? Data()).withItbBytes { wrapPtr, wrapLen in
                    try check(itb_pipeline_load(blobPtr, blobLen,
                                                permLen > 0 ? permPtr : nil, permLen,
                                                wrapLen > 0 ? wrapPtr : nil, wrapLen,
                                                &out))
                }
            }
        }
        guard let out else {
            throw ItbError(c: ITB_STATUS_INTERNAL)
        }
        self.init(raw: out)
    }

    /// `init(load:)` for a blob stored at `path`; the file is read
    /// inside libitb3 (a missing or unreadable file throws `.badInput`
    /// with the diagnostic attached).
    public convenience init(loadFile path: String,
                            permMaster: Data? = nil, wrapMaster: Data? = nil) throws {
        var out: OpaquePointer?
        try (permMaster ?? Data()).withItbBytes { permPtr, permLen in
            try (wrapMaster ?? Data()).withItbBytes { wrapPtr, wrapLen in
                try check(itb_pipeline_load_f(path,
                                              permLen > 0 ? permPtr : nil, permLen,
                                              wrapLen > 0 ? wrapPtr : nil, wrapLen,
                                              &out))
            }
        }
        guard let out else {
            throw ItbError(c: ITB_STATUS_INTERNAL)
        }
        self.init(raw: out)
    }

    deinit {
        itb_pipeline_free(raw)
    }

    // MARK: Session blob

    /// The current session-bundle blob for the receiver side (the
    /// init blob, or the bytes of the latest `rekey`). A closed
    /// Pipeline throws `.tripleClosed`.
    public func save() throws -> Data {
        try takeBytes { out, outLen in
            itb_pipeline_save(raw, out, outLen)
        }
    }

    /// Writes the current blob to `path` inside libitb3 (mode 0600; the
    /// containing directory must exist).
    public func saveF(_ path: String) throws {
        try check(itb_pipeline_save_f(raw, path))
    }

    /// Sets the worker cap for every subsequent cipher call. `n` is
    /// clamped by libitb3 (`<= 0` selects auto, `> 256` becomes 256);
    /// only the handle state is reported. The cap is per-machine and
    /// never travels in the blob.
    public func maxWorkers(_ n: Int32) throws {
        try check(itb_pipeline_max_workers(raw, n))
    }

    /// Rotates the parallax + wrapper masters and returns the fresh
    /// blob (also available through `save`). Empty masters request
    /// fresh CSPRNG material Go-side.
    @discardableResult
    public func rekey(permMaster: Data = Data(), wrapMaster: Data = Data()) throws -> Data {
        try permMaster.withItbBytes { permPtr, permLen in
            try wrapMaster.withItbBytes { wrapPtr, wrapLen in
                try takeBytes { out, outLen in
                    itb_pipeline_rekey(raw,
                                       permLen > 0 ? permPtr : nil, permLen,
                                       wrapLen > 0 ? wrapPtr : nil, wrapLen,
                                       out, outLen)
                }
            }
        }
    }

    // MARK: Single Message

    /// Single Message encrypt: one call, one self-contained wire.
    public func encryptMessage(_ plain: Data) throws -> Data {
        try plain.withItbBytes { ptr, len in
            try takeBytes { out, outLen in
                itb_pipeline_encrypt_message(raw, ptr, len, out, outLen)
            }
        }
    }

    /// Receive-side counterpart of `encryptMessage`.
    public func decryptMessage(_ wire: Data) throws -> Data {
        try wire.withItbBytes { ptr, len in
            try takeBytes { out, outLen in
                itb_pipeline_decrypt_message(raw, ptr, len, out, outLen)
            }
        }
    }

    /// `Result`-shaped variant of `encryptMessage`.
    public func encryptMessageResult(_ plain: Data) -> Result<Data, ItbError> {
        captureResult { try encryptMessage(plain) }
    }

    /// `Result`-shaped variant of `decryptMessage`.
    public func decryptMessageResult(_ wire: Data) -> Result<Data, ItbError> {
        captureResult { try decryptMessage(wire) }
    }

    /// Async variant of `encryptMessage` (the blocking C call runs on
    /// a background task).
    public func encryptMessage(_ plain: Data) async throws -> Data {
        try await offBlocking { try self.encryptMessage(plain) }
    }

    /// Async variant of `decryptMessage`.
    public func decryptMessage(_ wire: Data) async throws -> Data {
        try await offBlocking { try self.decryptMessage(wire) }
    }

    // MARK: Whole-buffer stream one-shot

    /// One-shot stream encrypt for callers holding the whole
    /// plaintext in memory: a single FFI round trip through the
    /// Pipeline's stream chain. For bounded-memory streaming use
    /// `encryptStream()` / `encryptStreamPump`.
    public func encryptStreamOneShot(_ plain: Data) throws -> Data {
        try plain.withItbBytes { ptr, len in
            try takeBytes { out, outLen in
                itb_pipeline_encrypt_stream_one_shot(raw, ptr, len, out, outLen)
            }
        }
    }

    /// Receive-side counterpart of `encryptStreamOneShot`.
    public func decryptStreamOneShot(_ wire: Data) throws -> Data {
        try wire.withItbBytes { ptr, len in
            try takeBytes { out, outLen in
                itb_pipeline_decrypt_stream_one_shot(raw, ptr, len, out, outLen)
            }
        }
    }

    /// Async variant of `encryptStreamOneShot`.
    public func encryptStreamOneShot(_ plain: Data) async throws -> Data {
        try await offBlocking { try self.encryptStreamOneShot(plain) }
    }

    /// Async variant of `decryptStreamOneShot`.
    public func decryptStreamOneShot(_ wire: Data) async throws -> Data {
        try await offBlocking { try self.decryptStreamOneShot(wire) }
    }

    // MARK: Whole-buffer stream pumps

    /// Pumps the whole plaintext through an incremental encrypt
    /// session and returns the concatenated wire.
    public func encryptStreamPump(_ plain: Data) throws -> Data {
        try plain.withItbBytes { ptr, len in
            try takeBytes { out, outLen in
                itb_pipeline_encrypt_stream_pump(raw, ptr, len, out, outLen)
            }
        }
    }

    /// Receive-side counterpart of `encryptStreamPump`.
    public func decryptStreamPump(_ wire: Data) throws -> Data {
        try wire.withItbBytes { ptr, len in
            try takeBytes { out, outLen in
                itb_pipeline_decrypt_stream_pump(raw, ptr, len, out, outLen)
            }
        }
    }

    /// Async variant of `encryptStreamPump`.
    public func encryptStreamPump(_ plain: Data) async throws -> Data {
        try await offBlocking { try self.encryptStreamPump(plain) }
    }

    /// Async variant of `decryptStreamPump`.
    public func decryptStreamPump(_ wire: Data) async throws -> Data {
        try await offBlocking { try self.decryptStreamPump(wire) }
    }

    // MARK: Incremental stream sessions

    /// Opens an incremental encrypt session (plaintext in, wire out).
    /// The session pins this Pipeline for its whole lifetime.
    public func encryptStream() throws -> EncryptStream {
        var out: OpaquePointer?
        try check(itb_pipeline_encrypt_stream_begin(raw, &out))
        guard let out else {
            throw ItbError(c: ITB_STATUS_INTERNAL)
        }
        return EncryptStream(raw: out, parent: self)
    }

    /// Receive-side counterpart (wire in, plaintext out).
    public func decryptStream() throws -> DecryptStream {
        var out: OpaquePointer?
        try check(itb_pipeline_decrypt_stream_begin(raw, &out))
        guard let out else {
            throw ItbError(c: ITB_STATUS_INTERNAL)
        }
        return DecryptStream(raw: out, parent: self)
    }

    /// Encrypts an async sequence of plaintext chunks into an
    /// `AsyncThrowingStream` of wire chunks (session begin → feed +
    /// drain per chunk → end → final drain).
    public func encryptStream<S: AsyncSequence & Sendable>(
        from source: S, readMax: Int = 1 << 16
    ) -> AsyncThrowingStream<Data, Error> where S.Element == Data {
        streamTransform(from: source, readMax: readMax) { try self.encryptStream() }
    }

    /// Decrypts an async sequence of wire chunks into an
    /// `AsyncThrowingStream` of plaintext chunks.
    public func decryptStream<S: AsyncSequence & Sendable>(
        from source: S, readMax: Int = 1 << 16
    ) -> AsyncThrowingStream<Data, Error> where S.Element == Data {
        streamTransform(from: source, readMax: readMax) { try self.decryptStream() }
    }

    private func streamTransform<S: AsyncSequence & Sendable>(
        from source: S, readMax: Int,
        begin: @escaping @Sendable () throws -> StreamSession
    ) -> AsyncThrowingStream<Data, Error> where S.Element == Data {
        AsyncThrowingStream { continuation in
            let task = Task.detached {
                do {
                    let session = try begin()
                    defer { session.free() }
                    for try await chunk in source {
                        try Task.checkCancellation()
                        try await session.write(chunk)
                        // Pre-end reads never block: drain the spool.
                        while true {
                            let (data, _) = try await session.read(max: readMax)
                            if data.isEmpty {
                                break
                            }
                            continuation.yield(data)
                        }
                    }
                    try await session.end()
                    while true {
                        try Task.checkCancellation()
                        let (data, finished) = try await session.read(max: readMax)
                        if !data.isEmpty {
                            continuation.yield(data)
                        }
                        if finished {
                            break
                        }
                    }
                    continuation.finish()
                } catch {
                    continuation.finish(throwing: error)
                }
            }
            continuation.onTermination = { _ in
                task.cancel()
            }
        }
    }
}

// MARK: - FFI byte-transport helpers

extension Data {
    /// Passes the byte content to an FFI body. Empty data hands over
    /// a dummy non-nil pointer with length 0, matching the C tools'
    /// always-allocated convention.
    func withItbBytes<R>(_ body: (UnsafePointer<UInt8>?, Int) throws -> R) rethrows -> R {
        if isEmpty {
            var dummy: UInt8 = 0
            return try body(&dummy, 0)
        }
        return try withUnsafeBytes { rawBuf in
            try body(rawBuf.bindMemory(to: UInt8.self).baseAddress, rawBuf.count)
        }
    }
}

/// Runs an out-buffer C entry (`uint8_t **out, size_t *out_len`),
/// copies the produced bytes into a Data, and releases the C buffer
/// via itb_bytes_free.
func takeBytes(
    _ call: (UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
             UnsafeMutablePointer<Int>) -> itb_status
) throws -> Data {
    var out: UnsafeMutablePointer<UInt8>?
    var outLen = 0
    try check(call(&out, &outLen))
    defer { itb_bytes_free(out) }
    guard let out, outLen > 0 else {
        return Data()
    }
    return Data(bytes: out, count: outLen)
}

/// Hops a blocking C call onto a detached background task.
func offBlocking<T: Sendable>(
    _ body: @escaping @Sendable () throws -> T
) async throws -> T {
    try await Task.detached { try body() }.value
}

/// Captures a throwing body into a `Result` (non-ItbError failures
/// degrade to `.internalError`, which does not occur on this surface).
func captureResult(_ body: () throws -> Data) -> Result<Data, ItbError> {
    do {
        return .success(try body())
    } catch let error as ItbError {
        return .failure(error)
    } catch {
        return .failure(ItbError(c: ITB_STATUS_INTERNAL))
    }
}
