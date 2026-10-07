/*
 * The worker: its thread body (one warmup iteration, the warmup
 * barrier, the main loop), one iteration, the session pump loop the
 * stream shape drives, and the round-trip comparison that decides
 * between a worker error and a data mismatch. The state a worker
 * shares with the others lives here too — the C reference keeps it in
 * a header because C has no modules; a Swift module needs no such
 * unit, so it sits with the code that uses it.
 */

import Foundation
import Glibc
import Itb3
import Synchronization

/// Cipher surfaces the --shape flag selects.
enum Shape: Int {
    case stream          // session pump: begin / write / read / end
    case message         // Single Message: one whole-buffer call
    case streamOneShot   // stream surface, one whole-buffer call
    case both            // all three, rotating by iteration number

    static let names = ["stream", "message", "stream_one_shot", "both"]

    var name: String {
        Shape.names[rawValue]
    }

    static func parse(_ s: String) -> Shape? {
        guard let i = names.firstIndex(of: s) else {
            return nil
        }
        return Shape(rawValue: i)
    }
}

/// --goroutines ceiling; the harness targets modest hosts and each
/// worker pins payload-sized buffers for the whole run.
let loopMaxWorkers = 10

/// The concurrency mode this binding implements, as the summary
/// reports it (shared-handle / independent-handles / single).
let loopConcurrency = "shared-handle"

/// Largest slice fed to a stream session per write; the drain after
/// every write uses the same bound.
let loopPumpSlice = 1 << 20

// MARK: - Locks

/// Swift-specific. A pthread reader / writer lock behind a stable
/// heap address: a `pthread_rwlock_t` held as a stored property would
/// be passed to the C entries as a temporary copy.
final class RWLock: @unchecked Sendable {
    private let p = UnsafeMutablePointer<pthread_rwlock_t>.allocate(capacity: 1)

    init() {
        pthread_rwlock_init(p, nil)
    }

    deinit {
        pthread_rwlock_destroy(p)
        p.deallocate()
    }

    func readLock() {
        pthread_rwlock_rdlock(p)
    }

    func writeLock() {
        pthread_rwlock_wrlock(p)
    }

    func unlock() {
        pthread_rwlock_unlock(p)
    }
}

/// Swift-specific. A pthread barrier behind a stable heap address,
/// for the same reason as RWLock.
final class Barrier: @unchecked Sendable {
    private let p = UnsafeMutablePointer<pthread_barrier_t>.allocate(capacity: 1)

    init(_ count: UInt32) {
        pthread_barrier_init(p, nil, count)
    }

    deinit {
        pthread_barrier_destroy(p)
        p.deallocate()
    }

    func wait() {
        pthread_barrier_wait(p)
    }
}

// MARK: - Failure carriers

/// A cipher, rekey or load call that came back non-OK, with the name
/// of the call inside a multi-call surface (the pump loop) so the
/// worker error names the step that failed.
struct CallFailure: Error {
    let what: String
    let code: Int32
    let message: String

    init(what: String, _ error: ItbError) {
        self.what = what
        code = error.code
        message = error.message
    }

    /// The contract's diagnostic form: the numeric code from the
    /// binding's own status surface, then the sentence the library
    /// left behind.
    var detail: String {
        "status \(code): \(message)"
    }
}

// MARK: - Worker and run state

/// One worker's private state: its plaintext, its reusable output
/// buffers, its generator, its counters, and the error it stopped on.
final class Worker: @unchecked Sendable {
    let id: Int
    unowned let run: RunState
    var thread = pthread_t()

    var plaintext: UnsafeMutablePointer<UInt8>
    let plaintextLen: Int
    let payloadMode: PayloadMode
    let seeded: Bool
    var rng: UInt64

    /// Pump-loop accumulators, reused across iterations.
    var wire = [UInt8]()
    var plain = [UInt8]()

    /// Counters read by the summary after every worker has returned.
    let iters = Atomic<Int64>(0)
    let bytesEnc = Atomic<Int64>(0)
    let bytesDec = Atomic<Int64>(0)
    let nanosEnc = Atomic<Int64>(0)
    let nanosDec = Atomic<Int64>(0)

    var failed = false
    var error = ""

    init(id: Int, run: RunState, cfg: Config) {
        self.id = id
        self.run = run
        plaintextLen = Int(cfg.payload)
        plaintext = UnsafeMutablePointer<UInt8>.allocate(capacity: max(plaintextLen, 1))
        payloadMode = cfg.payloadMode
        seeded = cfg.seed != 0
        rng = seedWorker(cfg.seed, id)
    }

    /// Records the worker's error text (first error wins) and requests
    /// a stop of the whole run.
    func fail(_ text: String) {
        if !failed {
            error = text
            failed = true
        }
        run.stop.store(true, ordering: .relaxed)
    }
}

/// The state every worker shares: the Pipeline handles, the retained
/// blobs, the lock that keeps iterations clear of handle mutation, the
/// stop request, the barriers, and the baselines the summary reads.
final class RunState: @unchecked Sendable {
    var cfg: Config

    var streamPipe: Pipeline?   // nil unless the shape uses it
    var msgPipe: Pipeline?      // nil unless the shape uses it
    var streamProfile = ""
    var msgProfile = ""

    /// Handle mutation. Iterations hold the read side for their whole
    /// encrypt → decrypt → compare; rekey and blob reopen take the
    /// write side, so no cipher call is in flight while a handle's
    /// keying changes or the handle itself is swapped, and no encrypt
    /// is separated from its decrypt by either.
    let pipeLock = RWLock()

    /// The blob Init handed out, replaced by every rekey; the input of
    /// the next blob reopen. Guarded by pipeLock.
    var streamBlob = Data()
    var msgBlob = Data()

    /// Rotation and reopen tallies. Both are bumped under the write
    /// lock, so no atomic is needed.
    var rekeys: Int64 = 0
    var blobCycles: Int64 = 0

    var workers = [Worker]()

    /// Warmup barrier: workers arrive at warmupDone after iteration 0
    /// and at release once main has taken the baselines.
    var warmupDone: Barrier!
    var release: Barrier!

    /// Set by the duration timer, by a signal, or by a failing worker;
    /// checked by every worker before it starts an iteration.
    let stop = Atomic<Bool>(false)

    /// Main waits on doneCondition for active to reach zero; the last
    /// returning worker stamps finishNanos so elapsed excludes the
    /// wake-up latency of the waiter.
    let doneCondition = NSCondition()
    var active = 0
    var startNanos: Int64 = 0
    var finishNanos: Int64 = 0

    /// Baselines taken after the warmup barrier and at shutdown.
    var rssWarmup: UInt64 = 0
    var rssPeak: UInt64 = 0
    var rssFinal: UInt64 = 0
    var poolWarmup = [Int64]()
    var poolSteady = [Int64]()

    init(cfg: Config) {
        self.cfg = cfg
    }
}

// MARK: - Stream pump

/// Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
/// and ITB drives the chunk loop internally; the binding's session
/// surface has no reader / writer entry, so the caller drives it: open
/// a session, feed slices of at most 1 MiB, drain whatever the session
/// has produced after every write (a read before end never blocks),
/// end, then drain until the session reports finished (after end, a
/// read on an empty spool blocks until the terminal bytes arrive). The
/// whole produced output lands in the worker's reusable accumulator.
/// The loop is written here rather than delegated to the binding's
/// pump convenience (`encryptStreamPump`) so it stands in the utility,
/// at the same place, in every language.
func pump(_ pipe: Pipeline, encrypt: Bool,
          source: UnsafeRawBufferPointer, into out: inout [UInt8]) throws {
    let session: StreamSession
    do {
        session = encrypt ? try pipe.encryptStream() : try pipe.decryptStream()
    } catch let e as ItbError {
        throw CallFailure(what: "StreamBegin", e)
    }
    defer { session.free() }

    out.removeAll(keepingCapacity: true)
    var off = 0
    while off < source.count {
        let slice = min(source.count - off, loopPumpSlice)
        do {
            try session.write(Data(bytes: source.baseAddress! + off, count: slice))
        } catch let e as ItbError {
            throw CallFailure(what: "StreamWrite", e)
        }
        off += slice
        while true {
            let drained: (data: Data, finished: Bool)
            do {
                drained = try session.read(max: loopPumpSlice)
            } catch let e as ItbError {
                throw CallFailure(what: "StreamRead", e)
            }
            if drained.data.isEmpty {
                break
            }
            out.append(contentsOf: drained.data)
        }
    }
    do {
        try session.end()
    } catch let e as ItbError {
        throw CallFailure(what: "StreamEnd", e)
    }
    while true {
        let drained: (data: Data, finished: Bool)
        do {
            drained = try session.read(max: loopPumpSlice)
        } catch let e as ItbError {
            throw CallFailure(what: "StreamRead", e)
        }
        out.append(contentsOf: drained.data)
        if drained.finished {
            break
        }
    }
}

// MARK: - One iteration

/// First offset at which a and b differ; the shorter length when one
/// is a prefix of the other.
func firstDifference(_ a: UnsafeRawBufferPointer, _ b: UnsafeRawBufferPointer) -> Int {
    let n = min(a.count, b.count)
    for i in 0..<n where a[i] != b[i] {
        return i
    }
    return n
}

/// Up to 16 bytes of buf from off as lowercase hex, or "-" when buf
/// has no bytes there.
func hexWindow(_ buf: UnsafeRawBufferPointer, from off: Int) -> String {
    if off >= buf.count {
        return "-"
    }
    let end = min(off + 16, buf.count)
    var out = ""
    out.reserveCapacity((end - off) * 2)
    for i in off..<end {
        out += String(format: "%02x", buf[i])
    }
    return out
}

extension Worker {
    /// Records a worker error for a failed cipher call.
    func cipherFail(_ iter: Int64, _ shape: Shape, _ direction: String, _ f: CallFailure) {
        if f.what == direction {
            fail("g\(id) iter \(iter) shape=\(shape.name): \(direction): \(f.detail)")
        } else {
            fail("g\(id) iter \(iter) shape=\(shape.name): \(direction): \(f.what): \(f.detail)")
        }
    }

    /// One iteration. In order: refill the plaintext under rotating
    /// mode; take the read lock; pick the surface; encrypt (timed);
    /// decrypt (timed); compare the round-trip with the plaintext;
    /// bump the counters; release the lock. The whole round-trip runs
    /// under the read lock so handle-mutating maintenance (rekey, blob
    /// reopen) never lands between an encrypt and its matching decrypt
    /// — maintenance runs after this returns, from the worker loop.
    /// Returns false after recording the worker error.
    func iterate(_ iter: Int64) -> Bool {
        if payloadMode == .rotating {
            if !fillPayload(.rotating, seeded: seeded, rng: &rng,
                            buf: plaintext, count: plaintextLen) {
                fail("g\(id) iter \(iter): payload refill: csprng")
                return false
            }
        }

        run.pipeLock.readLock()
        defer { run.pipeLock.unlock() }

        // Shape dispatch. message is one whole-buffer call on the
        // Single Message Pipeline; stream_one_shot is one whole-buffer
        // call on the streaming Pipeline (the C ABI's
        // ITB_Triple_EncryptStream, which routes to the same one-shot
        // stream entry the Go harness calls by name); stream opens a
        // session on the same streaming Pipeline and drives the chunk
        // loop from here. Under both the three rotate by iteration
        // number so the session path and the whole-buffer path
        // alternate on one handle inside every worker — the cross-path
        // state-reuse hazard this harness exists to catch.
        var shape = run.cfg.shape
        if shape == .both {
            switch iter % 3 {
            case 0: shape = .stream
            case 1: shape = .message
            default: shape = .streamOneShot
            }
        }

        // Swift-specific. The message and one-shot entries hand back
        // a fresh Data per call, which ARC reclaims at the end of the
        // iteration; the pump accumulators are the worker's own and
        // are reused across iterations.
        let plainBuf = UnsafeRawBufferPointer(start: plaintext, count: plaintextLen)
        var roundTrip: Data?

        do {
            switch shape {
            case .stream:
                var t0 = nowNanos()
                do {
                    try pump(run.streamPipe!, encrypt: true, source: plainBuf, into: &wire)
                } catch let f as CallFailure {
                    cipherFail(iter, shape, "encrypt", f)
                    return false
                } catch {
                    fail("g\(id) iter \(iter) shape=\(shape.name): encrypt: \(error)")
                    return false
                }
                nanosEnc.add(nowNanos() - t0, ordering: .relaxed)
                t0 = nowNanos()
                do {
                    try wire.withUnsafeBytes { src in
                        try pump(run.streamPipe!, encrypt: false, source: src, into: &plain)
                    }
                } catch let f as CallFailure {
                    cipherFail(iter, shape, "decrypt", f)
                    return false
                } catch {
                    fail("g\(id) iter \(iter) shape=\(shape.name): decrypt: \(error)")
                    return false
                }
                nanosDec.add(nowNanos() - t0, ordering: .relaxed)
            case .streamOneShot, .message:
                let pipe = shape == .message ? run.msgPipe! : run.streamPipe!
                let source = Data(bytes: plaintext, count: plaintextLen)
                var t0 = nowNanos()
                let wireData: Data
                do {
                    wireData = shape == .message
                        ? try pipe.encryptMessage(source)
                        : try pipe.encryptStreamOneShot(source)
                } catch let e as ItbError {
                    cipherFail(iter, shape, "encrypt", CallFailure(what: "encrypt", e))
                    return false
                } catch {
                    fail("g\(id) iter \(iter) shape=\(shape.name): encrypt: \(error)")
                    return false
                }
                nanosEnc.add(nowNanos() - t0, ordering: .relaxed)
                t0 = nowNanos()
                do {
                    roundTrip = shape == .message
                        ? try pipe.decryptMessage(wireData)
                        : try pipe.decryptStreamOneShot(wireData)
                } catch let e as ItbError {
                    cipherFail(iter, shape, "decrypt", CallFailure(what: "decrypt", e))
                    return false
                } catch {
                    fail("g\(id) iter \(iter) shape=\(shape.name): decrypt: \(error)")
                    return false
                }
                nanosDec.add(nowNanos() - t0, ordering: .relaxed)
            case .both:
                break // resolved above
            }
        }

        // Failure model. A cipher call that returns a non-OK status is
        // a worker error: it is recorded, the run is asked to stop,
        // the other workers finish their in-flight iteration, and the
        // error is listed in the summary with the FAIL verdict. A
        // round-trip that returns OK with different bytes is a data
        // mismatch: the process terminates here, without summary or
        // cleanup, because the Pipeline state that produced the wrong
        // bytes is the evidence and nothing that runs afterwards may
        // touch it.
        let check: (UnsafeRawBufferPointer) -> Bool = { got in
            let same = got.count == self.plaintextLen
                && (self.plaintextLen == 0
                    || memcmp(self.plaintext, got.baseAddress!, self.plaintextLen) == 0)
            if !same {
                let off = firstDifference(plainBuf, got)
                Log.err("DATA MISMATCH g\(self.id) iter \(iter) shape=\(shape.name): "
                    + "want \(self.plaintextLen) bytes, got \(got.count) bytes, "
                    + "first difference at offset \(off): "
                    + "want \(hexWindow(plainBuf, from: off)) got \(hexWindow(got, from: off))")
                _exit(3)
            }
            return true
        }
        var gotLen = 0
        if let roundTrip {
            gotLen = roundTrip.count
            roundTrip.withUnsafeBytes { _ = check($0) }
        } else {
            gotLen = plain.count
            plain.withUnsafeBytes { _ = check($0) }
        }

        iters.add(1, ordering: .relaxed)
        bytesEnc.add(Int64(plaintextLen), ordering: .relaxed)
        bytesDec.add(Int64(gotLen), ordering: .relaxed)
        return true
    }

    /// Marks this worker returned; the last one to return stamps the
    /// finish instant and wakes main.
    private func done() {
        run.doneCondition.lock()
        run.active -= 1
        if run.active == 0 {
            run.finishNanos = nowNanos()
            run.doneCondition.signal()
        }
        run.doneCondition.unlock()
    }

    /// The worker thread body: one warmup iteration, the warmup
    /// barrier, then the main loop until a stop is requested or the
    /// fixed per-worker iteration budget (warmup included) is spent. A
    /// failing warmup still passes both barriers so the launcher never
    /// waits on a worker that has already given up.
    func main() {
        // Warmup iteration — counted in the totals; its completion
        // feeds the post-warmup baselines.
        let ok = iterate(0)
        run.warmupDone.wait()
        run.release.wait()
        if !ok {
            done()
            return
        }

        var iter: Int64 = 1
        while true {
            if run.cfg.iterations > 0 && iter >= run.cfg.iterations {
                break
            }
            if run.stop.load(ordering: .relaxed) {
                break
            }
            if !iterate(iter) {
                break
            }
            if !workerMaintenance(self, iter) {
                break
            }
            iter += 1
        }
        done()
    }
}
