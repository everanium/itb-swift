/*
 * Size and duration parsing, the monotonic clock, and the human
 * renderings of sizes, rates and durations. Every rendering here is
 * part of the output contract shared with the Go harness and the
 * other bindings' loop utilities, so the formats are fixed to the
 * character, not to taste.
 */

import Foundation
import Glibc

/// Parses a human byte-size string ("16MB", "1MiB", "512K",
/// "1073741824") into a byte count. Every suffix is a binary
/// multiple: K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3,
/// B or none = bytes; matching is case-insensitive and surrounding
/// whitespace is trimmed. Returns nil on a malformed or negative
/// value.
func parseSize(_ s: String) -> Int64? {
    let trimmed = s.trimmingCharacters(in: .whitespaces)
    if trimmed.isEmpty || trimmed.count >= 64 {
        return nil
    }
    let upper = Array(trimmed.uppercased().utf8)
    let suffixes: [(String, Int64)] = [
        ("KIB", 1 << 10), ("KB", 1 << 10), ("K", 1 << 10),
        ("MIB", 1 << 20), ("MB", 1 << 20), ("M", 1 << 20),
        ("GIB", 1 << 30), ("GB", 1 << 30), ("G", 1 << 30),
        ("B", 1),
    ]
    var mult: Int64 = 1
    var digits = upper.count
    for (suffix, m) in suffixes {
        let sl = Array(suffix.utf8)
        if upper.count >= sl.count && Array(upper[(upper.count - sl.count)...]) == sl {
            mult = m
            digits = upper.count - sl.count
            break
        }
    }
    while digits > 0 && (upper[digits - 1] == 0x20 || upper[digits - 1] == 0x09) {
        digits -= 1
    }
    if digits == 0 {
        return nil
    }
    var value: Int64 = 0
    for i in 0..<digits {
        let c = upper[i]
        if c < 0x30 || c > 0x39 {
            return nil
        }
        let (mul, o1) = value.multipliedReportingOverflow(by: 10)
        if o1 {
            return nil
        }
        let (add, o2) = mul.addingReportingOverflow(Int64(c - 0x30))
        if o2 {
            return nil
        }
        value = add
    }
    if mult > 1 && value > Int64.max / mult {
        return nil
    }
    return value * mult
}

/// Parses the Go duration grammar — a sequence of decimal numbers
/// each followed by a unit (h, m, s, ms, us, ns), such as "30s",
/// "5m", "1h30m", "1.5s" — into nanoseconds. Returns nil on a
/// malformed string.
func parseDuration(_ s: String) -> Int64? {
    let units: [(String, Double)] = [
        ("ns", 1.0), ("us", 1e3), ("ms", 1e6),
        ("s", 1e9), ("m", 60e9), ("h", 3600e9),
    ]
    return s.withCString { base -> Int64? in
        var cursor = UnsafePointer<CChar>(base)
        if cursor.pointee == 0 {
            return nil
        }
        var total = 0.0
        while cursor.pointee != 0 {
            let c = UInt8(bitPattern: cursor.pointee)
            let isDigit = c >= 0x30 && c <= 0x39
            if !isDigit && c != 0x2E {
                return nil
            }
            var endPtr: UnsafeMutablePointer<CChar>?
            let v = strtod(cursor, &endPtr)
            guard let end = endPtr, end != cursor, v >= 0.0 else {
                return nil
            }
            cursor = UnsafePointer(end)
            var mult = 0.0
            for (unit, ns) in units {
                let ul = unit.utf8.count
                if strncmp(cursor, unit, ul) != 0 {
                    continue
                }
                // A longer alphabetic run is a different unit, not
                // this one with trailing text.
                let next = UInt8(bitPattern: cursor[ul])
                if (next >= 0x41 && next <= 0x5A) || (next >= 0x61 && next <= 0x7A) {
                    continue
                }
                mult = ns
                cursor += ul
                break
            }
            if mult == 0.0 {
                return nil
            }
            total += v * mult
        }
        if total > 9.2e18 {
            return nil
        }
        return Int64(total)
    }
}

/// Monotonic wall clock in nanoseconds.
func nowNanos() -> Int64 {
    var ts = timespec()
    clock_gettime(CLOCK_MONOTONIC, &ts)
    return Int64(ts.tv_sec) * 1_000_000_000 + Int64(ts.tv_nsec)
}

/// Renders a byte count with a binary-unit suffix: "1.0GiB",
/// "16.0MiB", "4.0KiB", "512B".
func humanBytes(_ n: Int64) -> String {
    if n >= (1 << 30) {
        return String(format: "%.1fGiB", Double(n) / Double(1 << 30))
    }
    if n >= (1 << 20) {
        return String(format: "%.1fMiB", Double(n) / Double(1 << 20))
    }
    if n >= (1 << 10) {
        return String(format: "%.1fKiB", Double(n) / Double(1 << 10))
    }
    return "\(n)B"
}

/// Renders a possibly-negative byte delta with an explicit sign.
func humanBytesSigned(_ n: Int64) -> String {
    n < 0 ? "-" + humanBytes(-n) : "+" + humanBytes(n)
}

/// Binary MiB per second over a nanosecond window; 0 when the window
/// is unmeasured.
func mbPerSec(_ bytes: Int64, _ ns: Int64) -> Double {
    if ns <= 0 {
        return 0.0
    }
    return Double(bytes) / Double(1 << 20) / (Double(ns) / 1e9)
}

/// Renders a throughput as "123.4MB/s" (binary MiB per second) or
/// "n/a" for an unmeasured window.
func humanRate(_ bytes: Int64, _ ns: Int64) -> String {
    if ns <= 0 {
        return "n/a"
    }
    return String(format: "%.1fMB/s", mbPerSec(bytes, ns))
}

/// The fractional part of a nanosecond remainder (0 ..< 1e9) as
/// ".ddd" with trailing zeros removed; empty for zero.
private func fractionSuffix(_ fracNanos: Int64) -> String {
    if fracNanos == 0 {
        return ""
    }
    var digits = String(format: "%09lld", fracNanos)
    while digits.hasSuffix("0") {
        digits.removeLast()
    }
    return "." + digits
}

/// Renders a duration the way Go's time.Duration prints: below one
/// second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
/// where the hour part appears when non-zero, the minute part when
/// the hour part appears or the minutes are non-zero, and the seconds
/// carry their fraction with trailing zeros removed ("5s", "5.003s",
/// "1m0s", "1m5.25s", "1h0m0s"). The caller rounds first.
func humanDuration(_ nanos: Int64) -> String {
    var ns = nanos
    if ns < 0 {
        ns = -ns
    }
    if ns == 0 {
        return "0s"
    }
    if ns < 1_000_000_000 {
        let ms = ns / 1_000_000
        let frac = (ns % 1_000_000) * 1000 // scale to 9 digits
        return "\(ms)" + fractionSuffix(frac) + "ms"
    }
    let hours = ns / 3_600_000_000_000
    var rem = ns % 3_600_000_000_000
    let minutes = rem / 60_000_000_000
    rem %= 60_000_000_000
    let seconds = rem / 1_000_000_000
    let frac = rem % 1_000_000_000
    var out = ""
    if hours > 0 {
        out += "\(hours)h"
    }
    if hours > 0 || minutes > 0 {
        out += "\(minutes)m"
    }
    out += "\(seconds)" + fractionSuffix(frac) + "s"
    return out
}
