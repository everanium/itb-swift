/*
 * Profile records (inspect / register / lookup / profiles), Go
 * runtime knobs, and the diagnostic registry surface.
 */

import CItb
import Foundation

/// Binding version. Tracks the Swift wrapper; `ItbRuntime.version`
/// reports the underlying libitb3 library version.
public let itbSwiftVersion = "0.5.5"

/// Runs a `char **json_out` C entry and hands back the JSON string,
/// releasing the C buffer via itb_string_free.
func takeJSON(_ call: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> itb_status) throws -> String {
    var out: UnsafeMutablePointer<CChar>?
    try check(call(&out))
    defer { itb_string_free(out) }
    guard let out else {
        return ""
    }
    return String(cString: out)
}

/// Decodes the profile record embedded in `blob` without constructing
/// a Pipeline. No registry read, no primitive probe — a primitive
/// name the local build lacks is returned unchanged.
public func inspect(_ blob: Data) throws -> Profile {
    let json = try blob.withItbBytes { ptr, len in
        try takeJSON { out in itb_inspect(ptr, len, out) }
    }
    return try Profile.fromJSON(json)
}

/// Registers a user-defined Triple profile under `name` so subsequent
/// `Pipeline(profile:)` calls resolve it. The record's field rules
/// are validated by libitb3; a duplicate name throws `.profileExists`.
/// A non-empty `profile.name` must equal `name`.
public func register(name: String, profile: Profile) throws {
    try check(itb_register(name, try profile.toJSON()))
}

/// Returns the profile registered under `name` — a shipped catalogue
/// entry or a prior `register` call. An unregistered name throws
/// `.unknownProfile`.
public func lookup(name: String) throws -> Profile {
    try Profile.fromJSON(try takeJSON { out in itb_lookup(name, out) })
}

/// Returns the sorted list of every registered profile name.
public func profiles() throws -> [String] {
    let json = try takeJSON { out in itb_profiles(out) }
    return try JSONDecoder().decode([String].self, from: Data(json.utf8))
}

/// Returns the shipped hash-primitive registry in canonical order.
/// The list is the one a profile's `innerHash` / `hashes` names are
/// resolved against, so a caller can validate a primitive name
/// without constructing a Pipeline.
public func hashNames() throws -> [String] {
    let json = try takeJSON { out in itb_hash_names(out) }
    return try JSONDecoder().decode([String].self, from: Data(json.utf8))
}

public enum ItbRuntime {
    /// The libitb3 library version string (e.g. "0.5.5").
    public static var version: String {
        guard let v = itb_version() else {
            return ""
        }
        return String(cString: v)
    }

    /// The fill cipher the auto DRBG tier selected on this host
    /// ("aes-256-ctr" or "chacha20"): the tier a Pipeline uses when its
    /// drbg option is empty, resolved per host and recorded in no blob.
    public static var drbgAutoTier: String {
        guard let v = itb_drbg_auto_tier() else {
            return ""
        }
        return String(cString: v)
    }

    /// The Go-side diagnostic recorded by the most recent failing
    /// libitb3 call (process-global last-write-wins; empty when none).
    public static var lastError: String {
        String(cString: itb_last_error())
    }

    /// Sets the Go runtime's soft heap limit in bytes; returns the
    /// previous limit. A negative value queries without changing.
    @discardableResult
    public static func setMemoryLimit(_ bytes: Int64) -> Int64 {
        itb_set_memory_limit(bytes)
    }

    /// Sets the Go GC trigger percentage; returns the previous value.
    /// A negative value queries without changing.
    @discardableResult
    public static func setGCPercent(_ percent: Int32) -> Int32 {
        itb_set_gc_percent(percent)
    }

    /// Sets the Go runtime's GOMAXPROCS; returns the previous value.
    /// Zero or a negative value queries without changing.
    @discardableResult
    public static func setGOMAXPROCS(_ n: Int32) -> Int32 {
        itb_set_gomaxprocs(n)
    }

    /// Writes the Go runtime's heap profile (pprof format) to `path`
    /// after one forced garbage collection. An empty path falls back
    /// to the ITB_MEMPROFILE environment variable; a path that is
    /// still empty, or a file-system failure, throws `.badInput` with
    /// the diagnostic attached.
    public static func writeHeapProfile(_ path: String) throws {
        try check(itb_write_heap_profile(path))
    }

    /// The number of Int64 slots `poolStats` fills. Size a buffer
    /// from this call, never from a constant.
    public static var poolStatsLen: Int {
        itb_pool_stats_len()
    }

    /// The library's pool hit / miss counters. Every counter is a
    /// monotonically increasing total since library load — difference
    /// two snapshots. Slot layout, with T the tier count in slot 0:
    /// tier i holds starter width, checkouts, constructor misses,
    /// regrow replacements and bytes allocated at slots
    /// 1 + 5*i .. 1 + 5*i + 4; the scratch byte pool's
    /// get / new / regrow / regrow-bytes follow at 1 + 5*T, and the
    /// parallax chunk pool's at 1 + 5*T + 4.
    public static func poolStats() throws -> [Int64] {
        let cap = itb_pool_stats_len()
        if cap == 0 {
            return []
        }
        var slots = [Int64](repeating: 0, count: cap)
        var written = 0
        try slots.withUnsafeMutableBufferPointer { buf in
            try check(itb_pool_stats(buf.baseAddress, cap, &written))
        }
        if written < cap {
            slots.removeSubrange(written..<cap)
        }
        return slots
    }
}
