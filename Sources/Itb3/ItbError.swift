/*
 * ItbError.swift — the error type thrown by every fallible entry.
 *
 * Carries the mapped Status, the raw numeric code (attributable even
 * for codes outside the Status table), and the Go-side diagnostic
 * snapshot fetched from itb_last_error() immediately after the
 * failing call. The diagnostic store is process-global
 * last-write-wins — under concurrent FFI use the text may belong to
 * a different call; the status code is always attributable.
 */

import CItb

public struct ItbError: Error, Sendable, CustomStringConvertible {
    /// Mapped status code.
    public let status: Status
    /// Raw numeric code as returned by the C binding.
    public let code: Int32
    /// Go-side diagnostic text (may be empty).
    public let message: String

    init(c raw: itb_status) {
        status = Status(c: raw)
        code = Int32(bitPattern: raw.rawValue)
        message = String(cString: itb_last_error())
    }

    public var description: String {
        let base = "ITB status \(code) (\(status.label))"
        return message.isEmpty ? base : "\(base): \(message)"
    }
}

/// Relays a C status: returns on OK, throws ItbError otherwise.
@inline(__always)
func check(_ raw: itb_status, _ ok: itb_status = ITB_STATUS_OK) throws {
    if raw != ok {
        throw ItbError(c: raw)
    }
}
