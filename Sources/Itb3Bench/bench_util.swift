/*
 * bench_util.swift — shared timing + reporting helpers for the Swift
 * binding micro-benchmarks. Wall-clock via DispatchTime; output is a
 * fixed-width table:
 *
 *   bench             size     mb_per_sec
 *   message           1 MiB    <n>
 *   ...
 */

import Foundation
import Itb3

let benchMinIters = 3

func benchMinSeconds() -> Double {
    if let raw = ProcessInfo.processInfo.environment["ITB_BENCH_MIN_SEC"],
       let v = Double(raw), v > 0 {
        return v
    }
    return 5.0
}

func env(_ key: String, _ fallback: String) -> String {
    let raw = ProcessInfo.processInfo.environment[key]
    return (raw?.isEmpty == false) ? raw! : fallback
}

func envBool(_ key: String) -> String {
    let raw = ProcessInfo.processInfo.environment[key]
    return (raw == "true" || raw == "1") ? "true" : "false"
}

/// Reads the bench-shape env vars and builds an Opts. Defaults match
/// root Go BENCH3.md so numbers are directly comparable.
func benchBuildOpts() throws -> Opts {
    let opts = try Opts()
    try opts.set("nonceBits", env("ITB_NONCE_BITS", "512"))
    try opts.set("keyBits", env("ITB_KEY_BITS", "1024"))
    try opts.set("withParallax", envBool("ITB_WITH_PARALLAX"))
    try opts.set("withWrapper", envBool("ITB_WITH_WRAPPER"))
    let innerHash = env("ITB_INNER_HASH", "areion512")
    if !innerHash.isEmpty {
        try opts.set("innerHash", innerHash)
    }
    let macName = env("ITB_MAC_NAME", "")
    if !macName.isEmpty {
        try opts.set("macName", macName)
    }
    return opts
}

func benchProfileName(_ fallback: String) -> String {
    env("ITB_PROFILE", fallback)
}

/// CSPRNG-filled plaintext so byte content matches the root Go bench
/// (crypto/rand): bulk-read from /dev/urandom, falling back to the
/// stdlib system generator.
func benchPayload(_ size: Int) -> Data {
    if let urandom = FileHandle(forReadingAtPath: "/dev/urandom") {
        defer { try? urandom.close() }
        var buf = Data(capacity: size)
        while buf.count < size {
            guard let chunk = try? urandom.read(upToCount: size - buf.count),
                  !chunk.isEmpty else {
                break
            }
            buf.append(chunk)
        }
        if buf.count == size {
            return buf
        }
    }
    var rng = SystemRandomNumberGenerator()
    var buf = Data(count: size)
    buf.withUnsafeMutableBytes { raw in
        let words = raw.bindMemory(to: UInt64.self)
        for i in 0..<words.count {
            words[i] = rng.next()
        }
        for i in (words.count * 8)..<raw.count {
            raw[i] = UInt8(truncatingIfNeeded: rng.next())
        }
    }
    return buf
}

func benchNow() -> Double {
    Double(DispatchTime.now().uptimeNanoseconds) / 1e9
}

func benchHeader() {
    print("bench".padding(toLength: 17, withPad: " ", startingAt: 0) + " "
        + "size".padding(toLength: 8, withPad: " ", startingAt: 0) + " "
        + "mb_per_sec")
}

func benchSizeLabel(_ size: Int) -> String {
    size >= (1 << 20) ? "\(size >> 20) MiB" : "\(size >> 10) KiB"
}

/// Runs body() until the wall-clock budget is spent (with an
/// iteration floor + one untimed warm-up), then prints one table row.
func benchCase(_ name: String, _ size: Int, _ body: () throws -> Void) {
    do {
        try body() // warm-up
        let start = benchNow()
        var elapsed = 0.0
        var iters = 0
        let budget = benchMinSeconds()
        while elapsed < budget || iters < benchMinIters {
            try body()
            iters += 1
            elapsed = benchNow() - start
        }
        let mb = Double(size) * Double(iters) / (1024.0 * 1024.0)
        let row = String(format: "%.1f", mb / elapsed)
        print("\(name.padding(toLength: 17, withPad: " ", startingAt: 0)) "
            + "\(benchSizeLabel(size).padding(toLength: 8, withPad: " ", startingAt: 0)) "
            + row)
    } catch {
        FileHandle.standardError.write(
            Data("bench \(name) @\(size): failed: \(error)\n".utf8))
        exit(1)
    }
}
