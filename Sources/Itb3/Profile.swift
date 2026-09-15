/*
 * Profile.swift — the profile record: the JSON object libitb3 accepts
 * in `register`, returns from `lookup` and `inspect`, and embeds in
 * every blob.
 *
 * The record is a plain data carrier: no field is validated on the
 * Swift side. Field rules (mode / width / hash-width agreement, MAC
 * name, palette contents, …) are enforced by libitb3 at `register`
 * and `load`; a rejected record surfaces as ItbError carrying the
 * status code plus the ITB_LastError diagnostic.
 */

import Foundation

/// Resolved shape of a Triple Pipeline. Serialises to the libitb3
/// profile JSON object; optional keys are omitted when empty / zero
/// and decode as their defaults when absent.
///
/// `nonceBits` and `barrierFill` are inspection-only: they are not
/// part of the profile recipe, stay `nil` on a record from `lookup`
/// or built by hand, and are populated only on a record from
/// `inspect`, where libitb3 reads them from the blob's runtime globals
/// snapshot. libitb3 rejects a `register` payload that carries either
/// key, so clear both before handing an inspected record to
/// `register`.
public struct Profile: Codable, Equatable, Sendable {
    /// Registry label. Empty on a record built by hand; filled by
    /// `lookup` / `inspect`. When non-empty it must equal the `name`
    /// argument of `register`.
    public var name: String = ""
    /// Pipeline mode (`singlemsg-mac`, `singlemsg-nomac`,
    /// `streaming-aead`, `streaming-noaead`, `blob-only`).
    public var mode: String = ""
    /// Inner hash width in bits (128 / 256 / 512).
    public var width: Int = 0
    /// Single inner-hash primitive name; empty on a mixed profile.
    public var innerHash: String = ""
    /// Eight-slot inner-hash constellation for mixed profiles; empty
    /// on a single-primitive profile.
    public var mixedHashes: [String] = []
    /// Session key width in bits.
    public var keyBits: Int = 0
    /// On-wire nonce width in bits, read from the blob's runtime
    /// globals. Inspection-only: non-nil on an `inspect` record, nil
    /// on a `lookup` record and on one built by hand.
    public var nonceBits: Int?
    /// DRBG barrier fill margin, read from the blob's runtime
    /// globals. Same inspection-only lifecycle as `nonceBits`.
    public var barrierFill: Int?
    /// MAC name; empty for No MAC modes.
    public var macName: String = ""
    /// MAC tag stub size; 0 for the profile default.
    public var tagStubSize: Int = 0
    /// Streaming chunk size; 0 for the library default.
    public var chunkSize: Int = 0
    /// Whether the format-deniability wrapper layer is on.
    public var wrapper: Bool = false
    /// Outer cipher name; empty when the wrapper layer is off.
    public var outerCipher: String = ""
    /// Whether the parallax layer is on.
    public var parallax: Bool = false
    /// Parallax palette; empty when the parallax layer is off.
    public var parallaxPalette: [String] = []
    /// Parallax segment size; 0 for the library default.
    public var parallaxSegmentSize: Int = 0

    public init() {}

    enum CodingKeys: String, CodingKey {
        case name, mode, width
        case innerHash = "hash"
        case mixedHashes = "hashes"
        case keyBits = "keybits"
        case nonceBits = "nonce_bits"
        case barrierFill = "barrier_fill"
        case macName = "mac"
        case tagStubSize = "tagstub"
        case chunkSize = "chunk"
        case wrapper
        case outerCipher = "outer"
        case parallax
        case parallaxPalette = "palette"
        case parallaxSegmentSize = "segment"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decodeIfPresent(String.self, forKey: .name) ?? ""
        mode = try c.decodeIfPresent(String.self, forKey: .mode) ?? ""
        width = try c.decodeIfPresent(Int.self, forKey: .width) ?? 0
        innerHash = try c.decodeIfPresent(String.self, forKey: .innerHash) ?? ""
        mixedHashes = try c.decodeIfPresent([String].self, forKey: .mixedHashes) ?? []
        keyBits = try c.decodeIfPresent(Int.self, forKey: .keyBits) ?? 0
        nonceBits = try c.decodeIfPresent(Int.self, forKey: .nonceBits)
        barrierFill = try c.decodeIfPresent(Int.self, forKey: .barrierFill)
        macName = try c.decodeIfPresent(String.self, forKey: .macName) ?? ""
        tagStubSize = try c.decodeIfPresent(Int.self, forKey: .tagStubSize) ?? 0
        chunkSize = try c.decodeIfPresent(Int.self, forKey: .chunkSize) ?? 0
        wrapper = try c.decodeIfPresent(Bool.self, forKey: .wrapper) ?? false
        outerCipher = try c.decodeIfPresent(String.self, forKey: .outerCipher) ?? ""
        parallax = try c.decodeIfPresent(Bool.self, forKey: .parallax) ?? false
        parallaxPalette = try c.decodeIfPresent([String].self, forKey: .parallaxPalette) ?? []
        parallaxSegmentSize = try c.decodeIfPresent(Int.self, forKey: .parallaxSegmentSize) ?? 0
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        if !name.isEmpty { try c.encode(name, forKey: .name) }
        try c.encode(mode, forKey: .mode)
        try c.encode(width, forKey: .width)
        if !innerHash.isEmpty { try c.encode(innerHash, forKey: .innerHash) }
        if !mixedHashes.isEmpty { try c.encode(mixedHashes, forKey: .mixedHashes) }
        try c.encode(keyBits, forKey: .keyBits)
        try c.encodeIfPresent(nonceBits, forKey: .nonceBits)
        try c.encodeIfPresent(barrierFill, forKey: .barrierFill)
        if !macName.isEmpty { try c.encode(macName, forKey: .macName) }
        if tagStubSize != 0 { try c.encode(tagStubSize, forKey: .tagStubSize) }
        if chunkSize != 0 { try c.encode(chunkSize, forKey: .chunkSize) }
        try c.encode(wrapper, forKey: .wrapper)
        if !outerCipher.isEmpty { try c.encode(outerCipher, forKey: .outerCipher) }
        try c.encode(parallax, forKey: .parallax)
        if !parallaxPalette.isEmpty { try c.encode(parallaxPalette, forKey: .parallaxPalette) }
        if parallaxSegmentSize != 0 { try c.encode(parallaxSegmentSize, forKey: .parallaxSegmentSize) }
    }

    /// Decodes a profile JSON object as returned by libitb3.
    public static func fromJSON(_ json: String) throws -> Profile {
        try JSONDecoder().decode(Profile.self, from: Data(json.utf8))
    }

    /// Encodes the record as the profile JSON object libitb3 accepts.
    public func toJSON() throws -> String {
        String(decoding: try JSONEncoder().encode(self), as: UTF8.self)
    }
}
