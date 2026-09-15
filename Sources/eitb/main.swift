/*
 * eitb — command-line demonstrator for the ITB Swift binding.
 *
 * Subcommands:
 *
 *   eitb version                                   library + binding versions
 *   eitb profiles                                  registered profile catalogue
 *   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
 *   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
 *
 * `encrypt` prints the session blob to stderr as hex; feed that hex
 * back to `decrypt` on the receiving side. `profiles` lists the
 * registered profile catalogue one name per line; the profiles that
 * carry a cipher surface are the ones `encrypt` / `decrypt` accept.
 */

import Foundation
import Itb3

func errPrint(_ text: String) {
    FileHandle.standardError.write(Data((text + "\n").utf8))
}

func usage() -> Int32 {
    errPrint("""
    usage: eitb version
           eitb profiles
           eitb encrypt <profile> <in-file> <out-file>
           eitb decrypt <profile> <blob-hex> <in-file> <out-file>
    """)
    return 2
}

/// Defensive Go-runtime pacing for cipher workloads on large files:
/// a soft memory cap + aggressive GC keep the scratch heap bounded.
func capGoRuntime() {
    ItbRuntime.setMemoryLimit(4 << 30) // 4 GiB soft cap
    ItbRuntime.setGCPercent(100)        // balanced GC
}

func readFile(_ path: String) -> Data? {
    guard let data = FileManager.default.contents(atPath: path) else {
        errPrint("eitb: cannot open \(path)")
        return nil
    }
    return data
}

// Profiles whose canonical name begins with "streaming-" route
// through the one-shot streaming buffered pair instead of the Single
// Message pair.
func isStreamingProfile(_ profile: String) -> Bool {
    profile.hasPrefix("streaming-")
}

// Recursively create the parent directory of `path` (mkdir -p).
func ensureParentDir(_ path: String) throws {
    let parent = (path as NSString).deletingLastPathComponent
    if !parent.isEmpty && parent != "." {
        try FileManager.default.createDirectory(atPath: parent,
                                                withIntermediateDirectories: true)
    }
}

func writeFile(_ path: String, _ data: Data) -> Bool {
    do {
        try ensureParentDir(path)
        try data.write(to: URL(fileURLWithPath: path))
        return true
    } catch {
        errPrint("eitb: write error on \(path): \(error)")
        return false
    }
}

func hexEncode(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

func hexDecode(_ hex: String) -> Data? {
    let chars = Array(hex.utf8)
    guard !chars.isEmpty, chars.count % 2 == 0 else {
        return nil
    }
    var out = Data(capacity: chars.count / 2)
    func nibble(_ c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x61...0x66: return c - 0x61 + 10
        case 0x41...0x46: return c - 0x41 + 10
        default: return nil
        }
    }
    for i in stride(from: 0, to: chars.count, by: 2) {
        guard let hi = nibble(chars[i]), let lo = nibble(chars[i + 1]) else {
            return nil
        }
        out.append(hi << 4 | lo)
    }
    return out
}

func cmdVersion() -> Int32 {
    print("libitb3 \(ItbRuntime.version)")
    print("itb-swift \(itbSwiftVersion)")
    return 0
}

/// Prints the registered profile catalogue one name per line in the
/// sorted order `profiles()` returns.
func cmdProfiles() -> Int32 {
    do {
        for name in try profiles() {
            print(name)
        }
        return 0
    } catch {
        errPrint("eitb: profiles: \(error)")
        return 1
    }
}

func cmdEncrypt(_ profile: String, _ inFile: String, _ outFile: String) -> Int32 {
    capGoRuntime()
    guard let plain = readFile(inFile) else {
        return 1
    }
    do {
        let pipe = try Pipeline(profile: profile)
        let wire = isStreamingProfile(profile)
            ? try pipe.encryptStreamPump(plain)
            : try pipe.encryptMessage(plain)
        guard writeFile(outFile, wire) else {
            return 1
        }
        errPrint(hexEncode(try pipe.save()))
        print("encrypted \(inFile) -> \(outFile) (\(plain.count) -> \(wire.count) bytes)")
        return 0
    } catch {
        errPrint("eitb: encrypt: \(error)")
        return 1
    }
}

func cmdDecrypt(_ profile: String, _ blobHex: String,
                _ inFile: String, _ outFile: String) -> Int32 {
    capGoRuntime()
    guard let blob = hexDecode(blobHex) else {
        errPrint("eitb: invalid blob hex")
        return 1
    }
    guard let wire = readFile(inFile) else {
        return 1
    }
    do {
        // The profile shape travels inside the blob; the profile
        // argument only selects the Single Message or streaming pair.
        let pipe = try Pipeline(load: blob)
        let plain = isStreamingProfile(profile)
            ? try pipe.decryptStreamPump(wire)
            : try pipe.decryptMessage(wire)
        guard writeFile(outFile, plain) else {
            return 1
        }
        print("decrypted \(inFile) -> \(outFile) (\(wire.count) -> \(plain.count) bytes)")
        return 0
    } catch {
        errPrint("eitb: decrypt: \(error)")
        return 1
    }
}

let args = CommandLine.arguments
switch (args.count, args.count > 1 ? args[1] : "") {
case (2, "version"):
    exit(cmdVersion())
case (2, "profiles"):
    exit(cmdProfiles())
case (5, "encrypt"):
    exit(cmdEncrypt(args[2], args[3], args[4]))
case (6, "decrypt"):
    exit(cmdDecrypt(args[2], args[3], args[4], args[5]))
default:
    exit(usage())
}
