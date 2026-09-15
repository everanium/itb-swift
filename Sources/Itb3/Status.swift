/*
 * Status.swift — Swift mirror of the C binding's itb_status table.
 *
 * The numeric values track cmd/cshared/internal/capi/errors.go via
 * bindings/c/include/itb3.h. Codes 11..13 are the Triple blob-record
 * / registry sentinels, 14..17 a reserved block; 19..22 belong to the
 * native Blob surface (not wrapped here
 * but relayed verbatim if libitb3 ever returns them).
 */

import CItb

/// Status code relayed from the C binding / libitb3.
public enum Status: Int32, Sendable, Equatable, Hashable {
    case ok = 0
    case badHash = 1
    case badKeyBits = 2
    case badHandle = 3
    case badInput = 4
    case bufferTooSmall = 5
    case encryptFailed = 6
    case decryptFailed = 7
    case seedWidthMix = 8
    case badMAC = 9
    case macFailure = 10
    case blobMalformedRecipe = 11
    case recipePrimitiveUnknown = 12
    case unknownProfile = 13
    case reserved14 = 14
    case reserved15 = 15
    case reserved16 = 16
    case reserved17 = 17
    case blobModeMismatch = 19
    case blobMalformed = 20
    case blobVersionTooNew = 21
    case blobTooManyOpts = 22
    case streamTruncated = 23
    case streamAfterFinal = 24
    case tripleClosed = 25
    case profileExists = 26
    case internalError = 99

    /// Maps a raw C status; an out-of-table code degrades to
    /// `.internalError` (the raw value stays attributable through
    /// `ItbError.code`).
    init(c raw: itb_status) {
        self = Status(rawValue: Int32(bitPattern: raw.rawValue)) ?? .internalError
    }

    /// Short static label for the status code (via `itb_status_str`).
    public var label: String {
        String(cString: itb_status_str(itb_status(rawValue: UInt32(bitPattern: rawValue))))
    }
}
