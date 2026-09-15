/*
 * DecryptStream.swift — receive-side incremental stream session.
 *
 * Wire goes in through write, plaintext comes out through read. The
 * shared pump machinery lives in StreamSession (EncryptStream.swift);
 * the direction split exists so the type system distinguishes the
 * two session kinds at the call site.
 */

/// Incremental decrypt session: wire in, plaintext out.
public final class DecryptStream: StreamSession, @unchecked Sendable {}
