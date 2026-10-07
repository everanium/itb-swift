/*
 * The maintenance operations that mutate a live Pipeline handle
 * between iterations: master rotation (--rekey-every) and blob
 * reopen (--blob-cycle-every).
 */

import Foundation
import Itb3

/// Byte length of each fresh master drawn for a rotation. Matches the
/// size Init auto-generates for both the parallax and the wrapper
/// master.
private let rekeyMasterSize = 32

/// Master rotation. Rotates the parallax + wrapper masters on every
/// active Pipeline under the write lock and retains the refreshed blob
/// for subsequent blob reopens. Masters are drawn fresh from the OS
/// CSPRNG on every rotation regardless of --seed (master rotation is
/// pipeline keying, not plaintext content); a disabled layer passes no
/// bytes, which Rekey ignores. The eight inner seeds and the MAC key
/// are untouched by design — Rekey targets only the two outer-layer
/// master secrets.
private func rekeyPipes(_ w: Worker, _ iter: Int64) -> Bool {
    let r = w.run
    var perm = Data()
    var wrap = Data()

    if r.cfg.parallax {
        perm = Data(count: rekeyMasterSize)
        var ok = false
        perm.withUnsafeMutableBytes { ok = fillRandom($0.baseAddress!, rekeyMasterSize) }
        if !ok {
            w.fail("g\(w.id) iter \(iter): csprng: parallax master")
            return false
        }
    }
    if r.cfg.wrapper {
        wrap = Data(count: rekeyMasterSize)
        var ok = false
        wrap.withUnsafeMutableBytes { ok = fillRandom($0.baseAddress!, rekeyMasterSize) }
        if !ok {
            w.fail("g\(w.id) iter \(iter): csprng: wrapper master")
            return false
        }
    }

    r.pipeLock.writeLock()
    defer { r.pipeLock.unlock() }
    if let pipe = r.streamPipe {
        do {
            r.streamBlob = try pipe.rekey(permMaster: perm, wrapMaster: wrap)
        } catch let e as ItbError {
            w.fail("g\(w.id) iter \(iter): Rekey(\(r.streamProfile)): status \(e.code): \(e.message)")
            return false
        } catch {
            w.fail("g\(w.id) iter \(iter): Rekey(\(r.streamProfile)): \(error)")
            return false
        }
    }
    if let pipe = r.msgPipe {
        do {
            r.msgBlob = try pipe.rekey(permMaster: perm, wrapMaster: wrap)
        } catch let e as ItbError {
            w.fail("g\(w.id) iter \(iter): Rekey(\(r.msgProfile)): status \(e.code): \(e.message)")
            return false
        } catch {
            w.fail("g\(w.id) iter \(iter): Rekey(\(r.msgProfile)): \(error)")
            return false
        }
    }
    r.rekeys += 1
    Log.line("rekey: g\(w.id) iter \(iter) rotated parallax + wrapper masters (rekey #\(r.rekeys))")
    return true
}

/// Blob reopen. Reopens every active Pipeline from its retained blob
/// under the write lock: a fresh handle is loaded from the blob, the
/// running handle is released, and the fresh one is swapped in, so
/// every later iteration round-trips through seeds and masters that
/// survived a blob crossing. The input is the blob Init or the latest
/// Rekey handed out, not a fresh Save: that is what a receiver holds,
/// and reopening from it proves the handed-out bytes rather than the
/// live state. The blob carries the Pipeline's full shape, so no
/// override reaches the reopen. On a Load failure the running handle
/// stays and the failure aborts the run.
private func blobCyclePipes(_ w: Worker, _ iter: Int64) -> Bool {
    let r = w.run
    r.pipeLock.writeLock()
    defer { r.pipeLock.unlock() }
    if r.streamPipe != nil {
        do {
            // Swift-specific. Assigning the fresh handle drops the
            // last reference to the running one, and ARC runs its
            // deinit, which is itb_pipeline_free.
            r.streamPipe = try Pipeline(load: r.streamBlob)
        } catch let e as ItbError {
            w.fail("g\(w.id) iter \(iter): Load(\(r.streamProfile)): status \(e.code): \(e.message)")
            return false
        } catch {
            w.fail("g\(w.id) iter \(iter): Load(\(r.streamProfile)): \(error)")
            return false
        }
    }
    if r.msgPipe != nil {
        do {
            r.msgPipe = try Pipeline(load: r.msgBlob)
        } catch let e as ItbError {
            w.fail("g\(w.id) iter \(iter): Load(\(r.msgProfile)): status \(e.code): \(e.message)")
            return false
        } catch {
            w.fail("g\(w.id) iter \(iter): Load(\(r.msgProfile)): \(error)")
            return false
        }
    }
    r.blobCycles += 1
    Log.line("blob-cycle: g\(w.id) iter \(iter) reopened from session blob (cycle #\(r.blobCycles))")
    return true
}

/// Handle mutation. Runs the periodic Pipeline-mutating operations
/// after a completed iteration: master rotation (--rekey-every) and
/// blob reopen (--blob-cycle-every). Both intervals count per-worker
/// iterations; the warmup iteration (iter 0) never triggers because
/// the worker loop calls this for iter >= 1 only. Rekey rewrites the
/// outer-layer keying of a live handle and a blob reopen replaces the
/// handle outright; each takes the write lock, so in-flight cipher
/// calls on other workers drain before anything changes and no encrypt
/// is separated from its decrypt by either. Returns false after
/// recording the worker error.
func workerMaintenance(_ w: Worker, _ iter: Int64) -> Bool {
    let cfg = w.run.cfg
    if cfg.rekeyEvery > 0 && iter % cfg.rekeyEvery == 0 {
        if !rekeyPipes(w, iter) {
            return false
        }
    }
    if cfg.blobCycleEvery > 0 && iter % cfg.blobCycleEvery == 0 {
        if !blobCyclePipes(w, iter) {
            return false
        }
    }
    return true
}
