/*
 * TestUtil.swift — shared payload helper for the binding's
 * integration tests (deterministic xorshift fill, mirroring the C
 * suite's test_payload).
 */

import Foundation

func testPayload(_ n: Int, seed: UInt64) -> Data {
    var buf = Data(count: n)
    var x = seed | 1
    buf.withUnsafeMutableBytes { raw in
        for i in 0..<raw.count {
            x ^= x << 13
            x ^= x >> 7
            x ^= x << 17
            raw[i] = UInt8(truncatingIfNeeded: x)
        }
    }
    return buf
}
