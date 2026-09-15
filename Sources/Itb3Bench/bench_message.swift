/*
 * bench_message.swift — encryptMessage throughput vs plaintext size
 * (Single Message profile) at 1 MiB / 16 MiB / 64 MiB.
 */

import Foundation
import Itb3

func runMessageBench() {
    do {
        let opts = try benchBuildOpts()
        let pipe = try Pipeline(profile: benchProfileName("singlemsg-triple-nomac-v1"),
                                opts: opts)
        for size in [1 << 20, 16 << 20, 64 << 20] {
            let plain = benchPayload(size)
            benchCase("message", size) {
                _ = try pipe.encryptMessage(plain)
            }
            // Pre-encrypt one wire outside the decrypt timing loop.
            let decWire = try pipe.encryptMessage(plain)
            benchCase("message-dec", size) {
                _ = try pipe.decryptMessage(decWire)
            }
        }
    } catch {
        FileHandle.standardError.write(
            Data("bench_message: init failed: \(error)\n".utf8))
        exit(1)
    }
}
