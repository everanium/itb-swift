/*
 * Plaintext content: the payload modes, the seeded per-worker
 * generator, and the buffer fill from the operating-system CSPRNG.
 */

import Foundation
import Glibc

// Swift-specific. The Glibc module does not re-export <sys/random.h>,
// so the libc entry is declared here by its symbol. It is the libc
// call, not the raw syscall: everything counting CSPRNG draws from
// outside the process sees it.
@_silgen_name("getrandom")
private func c_getrandom(_ buf: UnsafeMutableRawPointer?, _ buflen: Int, _ flags: UInt32) -> Int

/// Payload mode selector values for the --payload-mode flag.
///
///   - fixed: one CSPRNG-generated buffer per worker, held unchanged
///     for the whole run (the default).
///   - rotating: the buffer is regenerated before every iteration, so
///     no two encrypt calls see the same plaintext.
///   - patternZero / patternFF: degenerate constant fills (all 0x00 /
///     all 0xFF) probing minimum-entropy plaintext handling.
///   - patternASCII: a repeating 'A'..'Z' ramp probing low-entropy
///     structured text.
enum PayloadMode: Int, CaseIterable {
    case fixed
    case rotating
    case patternZero
    case patternFF
    case patternASCII

    static let names = [
        "fixed", "rotating", "pattern-zero", "pattern-ff", "pattern-ascii",
    ]

    var name: String {
        PayloadMode.names[rawValue]
    }

    static func parse(_ s: String) -> PayloadMode? {
        guard let i = names.firstIndex(of: s) else {
            return nil
        }
        return PayloadMode(rawValue: i)
    }
}

/// Seeded plaintext. The seed makes plaintext content reproducible so
/// a failing iteration can be replayed with the same bytes; it governs
/// nothing else — pipeline keys, nonces and masters stay CSPRNG-drawn,
/// so a seeded run is a reproduction aid and never a security test.
/// Each worker's stream is domain-separated by its id so seeded
/// workers still hold pairwise-distinct buffers under the fixed and
/// rotating modes. The generator is splitmix64: a few lines in any
/// language, which is why it is the one every binding uses.
func seedWorker(_ seed: UInt64, _ workerID: Int) -> UInt64 {
    seed &+ UInt64(workerID) &+ 1
}

private func splitmix64(_ state: inout UInt64) -> UInt64 {
    state &+= 0x9E37_79B9_7F4A_7C15
    var z = state
    z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
    z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
    return z ^ (z >> 31)
}

/// Fills `buf` from the operating-system CSPRNG. Swift-specific: the
/// libc entry returns at most ~33 MiB per call and may return short
/// on a signal, so the fill loops until every byte is in place.
/// Returns false on failure.
@discardableResult
func fillRandom(_ buf: UnsafeMutableRawPointer, _ n: Int) -> Bool {
    var off = 0
    while off < n {
        let r = c_getrandom(buf + off, n - off, 0)
        if r <= 0 {
            return false
        }
        off += r
    }
    return true
}

/// Writes one plaintext buffer according to the payload mode. The
/// fixed and rotating modes draw from the seeded generator when the
/// run is seeded and from the OS CSPRNG otherwise; the pattern modes
/// are deterministic regardless of the seed. Returns false when the
/// CSPRNG fails.
func fillPayload(_ mode: PayloadMode, seeded: Bool, rng: inout UInt64,
                 buf: UnsafeMutablePointer<UInt8>, count n: Int) -> Bool {
    switch mode {
    case .fixed, .rotating:
        if !seeded {
            return fillRandom(UnsafeMutableRawPointer(buf), n)
        }
        var i = 0
        while i < n {
            var v = splitmix64(&rng)
            let take = min(n - i, 8)
            withUnsafeBytes(of: &v) { src in
                (UnsafeMutableRawPointer(buf) + i).copyMemory(from: src.baseAddress!, byteCount: take)
            }
            i += 8
        }
        return true
    case .patternZero:
        memset(buf, 0x00, n)
        return true
    case .patternFF:
        memset(buf, 0xFF, n)
        return true
    case .patternASCII:
        for i in 0..<n {
            buf[i] = UInt8(65 + (i % 26))
        }
        return true
    }
}
