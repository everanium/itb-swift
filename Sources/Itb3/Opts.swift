/*
 * Opts.swift — URL-query opts builder over itb_opts.
 *
 * Accumulates key=value pairs into the query string consumed by
 * Pipeline(profile:opts:). Profile registration takes a Profile
 * record instead (see register). The builder performs no validation
 * — Go rejects unknown keys and bad values with a diagnostic relayed
 * through the thrown ItbError.
 */

import CItb

public final class Opts: @unchecked Sendable {
    let raw: OpaquePointer

    /// Allocates an empty builder.
    public init() throws {
        guard let raw = itb_opts_new() else {
            throw ItbError(c: ITB_STATUS_INTERNAL)
        }
        self.raw = raw
    }

    /// Convenience: builds from a dictionary in sorted-key order.
    public convenience init(_ pairs: [String: String]) throws {
        try self.init()
        for key in pairs.keys.sorted() {
            try set(key, pairs[key]!)
        }
    }

    deinit {
        itb_opts_free(raw)
    }

    /// Appends one key=value pair (both percent-encoded as needed).
    @discardableResult
    public func set(_ key: String, _ value: String) throws -> Opts {
        try check(itb_opts_set(raw, key, value))
        return self
    }

    /// The built query string ("" for an empty builder).
    public var query: String {
        guard let q = itb_opts_query(raw) else {
            return ""
        }
        return String(cString: q)
    }
}
