/*
 * bench_stream_one_shot.swift — encryptStreamOneShot throughput vs
 * plaintext size (streaming Non-AEAD profile) at 1 MiB / 16 MiB /
 * 64 MiB. Times the whole-buffer path (a single FFI round trip
 * through the Pipeline's stream chain).
 */

import Foundation
import Itb3

func runStreamOneShotBench() {
    do {
        let opts = try benchBuildOpts()
        let pipe = try Pipeline(profile: benchProfileName("streaming-noaead-triple-v1"),
                                opts: opts)
        for size in [1 << 20, 16 << 20, 64 << 20] {
            let plain = benchPayload(size)
            benchCase("stream_one_shot", size) {
                _ = try pipe.encryptStreamOneShot(plain)
            }
            // Pre-encrypt one wire outside the decrypt timing loop.
            let decWire = try pipe.encryptStreamOneShot(plain)
            benchCase("stream_one_shot-dec", size) {
                _ = try pipe.decryptStreamOneShot(decWire)
            }
        }
    } catch {
        FileHandle.standardError.write(
            Data("bench_stream_one_shot: init failed: \(error)\n".utf8))
        exit(1)
    }
}
