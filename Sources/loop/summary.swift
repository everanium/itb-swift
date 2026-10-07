/*
 * The final summary in both renderings, and the two measurements it
 * folds in that are not per-worker counters: the process resident set
 * and the shared library's pool counters.
 */

import Foundation
import Glibc
import Itb3

// MARK: - Resident set

/// The process's current resident set and its high-water mark in
/// bytes, from /proc/self/status (VmRSS and VmHWM, reported in kB).
/// Both are zero on a platform without that file; the figures are
/// informational and never enter the verdict.
func readRSS() -> (current: UInt64, peak: UInt64) {
    guard let text = try? String(contentsOfFile: "/proc/self/status", encoding: .utf8) else {
        return (0, 0)
    }
    var current: UInt64 = 0
    var peak: UInt64 = 0
    for line in text.split(separator: "\n") {
        guard let colon = line.firstIndex(of: ":") else {
            continue
        }
        let kb = UInt64(line[line.index(after: colon)...]
            .trimmingCharacters(in: .whitespaces)
            .prefix(while: { $0.isNumber })) ?? 0
        if line.hasPrefix("VmRSS:") {
            current = kb * 1024
        } else if line.hasPrefix("VmHWM:") {
            peak = kb * 1024
        }
    }
    return (current, peak)
}

// MARK: - Pool counters

/// Pool counters. The shared library keeps process-wide monotonic
/// totals at every pool checkout of its cipher core: per hash-array
/// tier the starter width, checkouts, constructor misses, regrow
/// replacements and bytes allocated; for the scratch byte pool and the
/// parallax chunk pool the checkouts, constructor misses, regrows and
/// regrow bytes. Two snapshots bracketing the main loop are
/// differenced into per-run hit / miss figures that tell whether a
/// pool keeps its items warm between calls or evicts them across GC
/// cycles. The slot layout is read from the library: slot 0 carries
/// the tier count T, tier i occupies the five slots at 1 + 5*i, and
/// the two byte pools occupy the eight slots at 1 + 5*T; the buffer is
/// sized from the binding's length query, never from a constant.
func poolSnapshot() -> [Int64] {
    (try? ItbRuntime.poolStats()) ?? []
}

/// The differenced pool figures of one run.
struct PoolDelta {
    struct Tier {
        var index = 0
        var starter: Int64 = 0
        var get: Int64 = 0
        var fresh: Int64 = 0
        var regrow: Int64 = 0
        var newBytes: Int64 = 0
    }

    var tiers = [Tier]()
    var bufGet: Int64 = 0
    var bufNew: Int64 = 0
    var bufRegrow: Int64 = 0
    var bufRegrowBytes: Int64 = 0
    var chunkGet: Int64 = 0
    var chunkNew: Int64 = 0
    var chunkRegrow: Int64 = 0
    var chunkRegrowBytes: Int64 = 0
}

func poolDiff(_ r: RunState) -> PoolDelta {
    var d = PoolDelta()
    let w = r.poolWarmup
    let s = r.poolSteady
    if w.count < 9 || s.count < 9 || w.count != s.count {
        return d
    }
    let tiers = Int(s[0])
    if tiers < 0 || tiers > 64 || 1 + 5 * tiers + 8 > s.count {
        return d
    }
    for i in 0..<tiers {
        let base = 1 + 5 * i
        d.tiers.append(PoolDelta.Tier(
            index: i,
            starter: s[base + 0],
            get: s[base + 1] - w[base + 1],
            fresh: s[base + 2] - w[base + 2],
            regrow: s[base + 3] - w[base + 3],
            newBytes: s[base + 4] - w[base + 4]))
    }
    let tail = 1 + 5 * tiers
    d.bufGet = s[tail + 0] - w[tail + 0]
    d.bufNew = s[tail + 1] - w[tail + 1]
    d.bufRegrow = s[tail + 2] - w[tail + 2]
    d.bufRegrowBytes = s[tail + 3] - w[tail + 3]
    d.chunkGet = s[tail + 4] - w[tail + 4]
    d.chunkNew = s[tail + 5] - w[tail + 5]
    d.chunkRegrow = s[tail + 6] - w[tail + 6]
    d.chunkRegrowBytes = s[tail + 7] - w[tail + 7]
    return d
}

/// Misses over checkouts as a percentage; zero when nothing was
/// checked out.
func missPercent(_ miss: Int64, _ get: Int64) -> Double {
    get <= 0 ? 0.0 : 100.0 * Double(miss) / Double(get)
}

/// Writes s as a JSON string literal with the escapes JSON requires.
func jsonString(_ s: String) -> String {
    var out = "\""
    for scalar in s.unicodeScalars {
        switch scalar {
        case "\"": out += "\\\""
        case "\\": out += "\\\\"
        case "\n": out += "\\n"
        case "\r": out += "\\r"
        case "\t": out += "\\t"
        default:
            if scalar.value < 0x20 {
                out += String(format: "\\u%04x", scalar.value)
            } else {
                out.unicodeScalars.append(scalar)
            }
        }
    }
    return out + "\""
}

/// The effective GC percentage as the runtime reports it: the query
/// form of the setter (a set-and-restore round trip inside the
/// library) so the field is the same whether the value came from the
/// flag, the environment, or the runtime default.
private func effectiveGogc(_ flag: Int32) -> Int32 {
    flag > 0 ? flag : ItbRuntime.setGCPercent(-1)
}

/// Output contract. Both renderings are shared with the Go harness and
/// every other binding's loop utility field for field: the same lines
/// in the same order, the same keys in the same order, floats with a
/// fixed number of decimals so the JSON is byte-identical across
/// implementations. The Go harness alone adds its runtime-internal
/// lines after rss: and its runtime-internal keys after
/// parallax_chunk_pool; nothing here reproduces them because nothing
/// they read is reachable through this binding.
func finalSummary(_ r: RunState, _ elapsedNanos: Int64) -> Int32 {
    let cfg = r.cfg
    var totalIters: Int64 = 0
    var totalEnc: Int64 = 0
    var totalDec: Int64 = 0
    var nanosEnc: Int64 = 0
    var nanosDec: Int64 = 0
    var errors = 0
    for w in r.workers {
        totalIters += w.iters.load(ordering: .relaxed)
        totalEnc += w.bytesEnc.load(ordering: .relaxed)
        totalDec += w.bytesDec.load(ordering: .relaxed)
        nanosEnc += w.nanosEnc.load(ordering: .relaxed)
        nanosDec += w.nanosDec.load(ordering: .relaxed)
        if w.failed {
            errors += 1
        }
    }

    // Throughput. Per-direction throughput divides the sum of every
    // worker's wall time in that direction by the worker count — the
    // equivalent single-stream wall time under N-way concurrency — so
    // each direction reports the aggregate rate it sustained rather
    // than collapsing to combined/2 (every iteration moves equal
    // encrypt and decrypt bytes, so a total-elapsed denominator would
    // give both directions the same figure). The combined rate keeps
    // total elapsed as the one-glance overall figure.
    let workers = Int64(cfg.workers)
    let avgEnc = nanosEnc > 0 ? nanosEnc / workers : 0
    let avgDec = nanosDec > 0 ? nanosDec / workers : 0

    let rssDelta = Int64(r.rssFinal) - Int64(r.rssWarmup)
    var rssGrowth = 0.0
    if r.rssWarmup > 0 {
        rssGrowth = 100.0 * Double(rssDelta) / Double(r.rssWarmup)
    }

    let pd = poolDiff(r)
    let pass = errors == 0
    let gomaxprocs = ItbRuntime.setGOMAXPROCS(0)
    let streamProfile = r.streamPipe != nil ? r.streamProfile : ""
    let msgProfile = r.msgPipe != nil ? r.msgProfile : ""
    let microbatch = policyLabel(ProcessInfo.processInfo.environment["ITB_MICROBATCH_TIERS"])
    let hashpool = policyLabel(ProcessInfo.processInfo.environment["ITB_HASHPOOL_STARTERS"])

    if cfg.jsonOutput {
        var o = "{"
        o += "\"duration_seconds\":" + String(format: "%.3f", Double(elapsedNanos) / 1e9)
        o += ",\"iterations\":\(totalIters)"
        o += ",\"per_worker_iterations\":["
        o += r.workers.map { "\($0.iters.load(ordering: .relaxed))" }.joined(separator: ",")
        o += "]"
        o += ",\"bytes_encrypted\":\(totalEnc)"
        o += ",\"bytes_decrypted\":\(totalDec)"
        o += ",\"encrypt_mb_per_sec\":" + String(format: "%.1f", mbPerSec(totalEnc, avgEnc))
        o += ",\"decrypt_mb_per_sec\":" + String(format: "%.1f", mbPerSec(totalDec, avgDec))
        o += ",\"combined_mb_per_sec\":" + String(format: "%.1f", mbPerSec(totalEnc + totalDec, elapsedNanos))
        o += ",\"rekeys\":\(r.rekeys)"
        o += ",\"blob_cycles\":\(r.blobCycles)"
        o += ",\"worker_errors\":["
        o += r.workers.filter { $0.failed }.map { jsonString($0.error) }.joined(separator: ",")
        o += "]"
        o += ",\"verdict\":\"" + (pass ? "PASS" : "FAIL") + "\""
        o += ",\"shape\":\"\(cfg.shape.name)\""
        o += ",\"stream_profile\":" + jsonString(streamProfile)
        o += ",\"message_profile\":" + jsonString(msgProfile)
        o += ",\"hash\":" + jsonString(cfg.hash)
        o += ",\"mac\":" + jsonString(cfg.mac)
        o += ",\"payload_bytes\":\(cfg.payload)"
        o += ",\"payload_mode\":\"\(cfg.payloadMode.name)\""
        o += ",\"seed\":\(cfg.seed)"
        o += ",\"key_bits\":\(cfg.keyBits)"
        o += ",\"nonce_bits\":\(cfg.nonceBits)"
        o += ",\"blob_mode\":\(cfg.blobMode)"
        o += ",\"drbg\":" + jsonString(cfg.drbg)
        o += ",\"drbg_auto_tier\":" + jsonString(ItbRuntime.drbgAutoTier)
        o += ",\"chunk_size_bytes\":\(cfg.chunkSize)"
        o += ",\"barrier_fill\":\(cfg.barrierFill)"
        o += ",\"parallax\":\"\(onOff(cfg.parallax))\""
        o += ",\"wrapper\":\"\(onOff(cfg.wrapper))\""
        o += ",\"goroutines_requested\":\(cfg.workersRequested)"
        o += ",\"goroutines\":\(cfg.workers)"
        o += ",\"concurrency\":\"\(loopConcurrency)\""
        o += ",\"gogc\":\"\(effectiveGogc(cfg.gogc))\""
        o += ",\"memlimit_bytes\":\(cfg.memlimit)"
        o += ",\"gomaxprocs\":\(gomaxprocs)"
        o += ",\"microbatch_tiers\":" + jsonString(microbatch)
        o += ",\"hashpool_starters\":" + jsonString(hashpool)
        o += ",\"rss_warmup_bytes\":\(r.rssWarmup)"
        o += ",\"rss_peak_bytes\":\(r.rssPeak)"
        o += ",\"rss_final_bytes\":\(r.rssFinal)"
        o += ",\"rss_growth_percent\":" + String(format: "%.2f", rssGrowth)
        o += ",\"hash_pool_tiers\":["
        o += pd.tiers.filter { $0.starter != 0 }.map { t in
            "{\"tier\":\(t.index),\"starter\":\(t.starter),\"get\":\(t.get),\"new\":\(t.fresh),"
                + "\"regrow\":\(t.regrow),\"new_bytes\":\(t.newBytes),\"miss_percent\":"
                + String(format: "%.2f", missPercent(t.fresh + t.regrow, t.get)) + "}"
        }.joined(separator: ",")
        o += "]"
        o += ",\"buf_pool\":{\"get\":\(pd.bufGet),\"new\":\(pd.bufNew),\"regrow\":\(pd.bufRegrow),"
        o += "\"regrow_bytes\":\(pd.bufRegrowBytes),\"miss_percent\":"
        o += String(format: "%.2f", missPercent(pd.bufRegrow, pd.bufGet)) + "}"
        o += ",\"parallax_chunk_pool\":{\"get\":\(pd.chunkGet),\"new\":\(pd.chunkNew),"
        o += "\"regrow\":\(pd.chunkRegrow),\"regrow_bytes\":\(pd.chunkRegrowBytes),\"miss_percent\":"
        o += String(format: "%.2f", missPercent(pd.chunkRegrow, pd.chunkGet)) + "}"
        o += "}"
        Log.raw(o + "\n")
        return pass ? 0 : 1
    }

    Log.line("=== FINAL ===")
    Log.line("  duration: " + humanDuration((elapsedNanos + 500_000) / 1_000_000 * 1_000_000))
    let parts = r.workers.map { "\($0.iters.load(ordering: .relaxed))" }.joined(separator: " + ")
    Log.line("  iterations: \(parts) = \(totalIters) total")
    Log.line("  throughput: encrypt \(humanRate(totalEnc, avgEnc)), "
        + "decrypt \(humanRate(totalDec, avgDec)), "
        + "combined \(humanRate(totalEnc + totalDec, elapsedNanos))")
    Log.line("  bytes: \(humanBytes(totalEnc)) encrypted, \(humanBytes(totalDec)) decrypted")
    Log.line("  data integrity: \(totalIters)/\(totalIters) PASS")
    Log.line("  concurrency: \(loopConcurrency), workers \(cfg.workers) (requested \(cfg.workersRequested))")
    Log.line("  rss: warmup \(humanBytes(Int64(r.rssWarmup))), peak \(humanBytes(Int64(r.rssPeak))), "
        + "final \(humanBytes(Int64(r.rssFinal))) (delta \(humanBytesSigned(rssDelta)), "
        + String(format: "%.1f", rssGrowth) + "% growth)")
    for t in pd.tiers where t.starter != 0 {
        Log.line("  hash pool tier \(t.index) (starter \(t.starter)): get \(t.get), "
            + "miss \(t.fresh + t.regrow) (new \(t.fresh) + regrow \(t.regrow)), "
            + "miss " + String(format: "%.2f", missPercent(t.fresh + t.regrow, t.get)) + "%, "
            + "\(humanBytes(t.newBytes)) allocated")
    }
    Log.line("  buf pool: get \(pd.bufGet), regrow \(pd.bufRegrow) (of which fresh \(pd.bufNew)), "
        + "miss " + String(format: "%.2f", missPercent(pd.bufRegrow, pd.bufGet)) + "%, "
        + "\(humanBytes(pd.bufRegrowBytes)) regrown")
    Log.line("  parallax chunk pool: get \(pd.chunkGet), regrow \(pd.chunkRegrow) "
        + "(of which fresh \(pd.chunkNew)), "
        + "miss " + String(format: "%.2f", missPercent(pd.chunkRegrow, pd.chunkGet)) + "%, "
        + "\(humanBytes(pd.chunkRegrowBytes)) regrown")
    if r.rekeys > 0 {
        Log.line("  rekeys: \(r.rekeys)")
    }
    if r.blobCycles > 0 {
        Log.line("  blob cycles: \(r.blobCycles)")
    }
    for w in r.workers where w.failed {
        Log.line("  ERROR: \(w.error)")
    }
    if pass {
        Log.line("  verdict: PASS")
        return 0
    }
    Log.line("  verdict: FAIL (errors=\(errors))")
    return 1
}
