/*
 * Long-run stress harness. The loop utility holds one Pipeline handle
 * per exercised cipher surface for minutes, hammers it with
 * concurrent encrypt → decrypt → compare round-trips from N worker
 * threads, rotates the outer masters and reopens the handle from its
 * session blob on a schedule, and reports whether the process
 * survived with every byte intact. It is the Swift binding's
 * counterpart of the Go harness under tools/loop: the same flags, the
 * same round structure, the same summary in both renderings.
 *
 * The default shape is full production: the Streaming AEAD profile
 * with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512
 * inner hash, 1024-bit keys, and the compile-in 512-bit nonce width,
 * driven through a stream session by three workers for five minutes
 * on 16 MiB plaintexts. Every worker owns a distinct CSPRNG-generated
 * plaintext held for the whole run, so any cross-call state leakage
 * inside the Pipeline surfaces as a data mismatch between workers
 * rather than cancelling out.
 *
 * A failure is one of two things. A cipher, rekey or load call that
 * returns a non-OK status is a worker error: the run stops, the
 * summary lists it, the verdict is FAIL and the exit code 1. A
 * round-trip that returns without error but with different bytes is
 * a data mismatch: the process terminates on the spot with exit
 * code 3, printing the worker, the iteration and the first differing
 * offset, and no summary — the state that produced the wrong bytes
 * is the evidence. A crash inside the shared library or the host
 * runtime has no exit code of its own here; surfacing it is what the
 * utility is for.
 *
 * Usage:
 *
 *   ./run_loop.sh --duration 5m --goroutines 3 --shape stream \
 *                 --hash areion512 --mac hmac-blake3 \
 *                 --payload-size 16MB --memlimit auto \
 *                 --parallax on --wrapper on
 *
 * Ctrl-C triggers a graceful shutdown: in-flight iterations complete,
 * then the partial summary prints.
 */

import Foundation
import Glibc
import Itb3
import Synchronization

/// Profiles the shape-based pair is built against when --profile is
/// empty.
let defaultStreamProfile = "streaming-aead-triple-mac-v1"
let defaultMessageProfile = "singlemsg-triple-mac-v1"

/// The primitive supplied for the parallax palette and the outer
/// cipher when a profile leaves them unnamed. AES-CMAC is PRF-grade,
/// so it is sound outside the Interlocked Barrier, and it is the
/// closest relative of the AES-based inner primitive whose profiles
/// need this fill.
let keystreamFillCipher = "aescmac"

// MARK: - Logging

/// A line and its newline leave the process in one write: workers log
/// concurrently during maintenance, and a print that emitted the text
/// and the newline separately would let another worker's line land
/// between them.
enum Log {
    static func raw(_ s: String) {
        writeAll(1, s)
    }

    /// Prints one prefixed status line to stdout.
    static func line(_ s: String) {
        writeAll(1, "[loop] " + s + "\n")
    }

    /// Prints one prefixed error line to stderr.
    static func err(_ s: String) {
        writeAll(2, "loop: " + s + "\n")
    }

    static func stderrRaw(_ s: String) {
        writeAll(2, s)
    }

    private static func writeAll(_ fd: Int32, _ s: String) {
        let bytes = Array(s.utf8)
        bytes.withUnsafeBufferPointer { buf in
            var off = 0
            while off < buf.count {
                let n = write(fd, buf.baseAddress! + off, buf.count - off)
                if n <= 0 {
                    return
                }
                off += n
            }
        }
    }
}

func onOff(_ b: Bool) -> String {
    b ? "on" : "off"
}

/// Renders an encoder policy env value for the summary: the raw
/// string when set, "default" when the shipped ladder applies.
func policyLabel(_ env: String?) -> String {
    guard let env else {
        return "default"
    }
    let trimmed = env.drop(while: { $0 == " " || $0 == "\t" })
    return trimmed.isEmpty ? "default" : String(trimmed)
}

// MARK: - Configuration

/// The resolved command line.
struct Config {
    var durationNanos: Int64 = 0  // run duration; ignored when iterations > 0
    var iterations: Int64 = 0     // per-worker count incl. warmup; 0 = duration-based
    var workersRequested = 0      // the --goroutines value as given
    var workers = 0               // the effective worker count
    var shape = Shape.stream
    var hash = ""
    var mac = ""
    var payload: Int64 = 0        // bytes per iteration
    var memlimit: Int64 = 0       // resolved bytes; the effective limit once shaped
    var memlimitAuto = false      // --memlimit auto: cap only when the runtime has no limit
    var gogc: Int32 = 0           // 0 = leave the runtime default
    var parallax = true
    var wrapper = true

    var profile = ""              // empty = shape-based profile pair
    var keyBits: Int32 = 0        // 0 = profile default
    var nonceBits: Int32 = 0      // 0 = profile default
    var blobMode: Int32 = 1       // container floor sizing mode: 1 (per-region, default) | 2 (per-container)
    var chunkSize: Int64 = 0      // 0 = profile default
    var barrierFill: Int32 = 0    // 0 = profile default
    var drbg = ""                 // DRBG fill primitive; "" = profile default (auto tier)
    var gomaxprocs: Int32 = 0     // 0 = inherit from the environment
    var rekeyEvery: Int64 = 0     // per-worker iterations between rotations; 0 = never
    var blobCycleEvery: Int64 = 0 // per-worker iterations between reopens; 0 = never
    var payloadMode = PayloadMode.fixed
    var seed: UInt64 = 0          // 0 = OS CSPRNG plaintexts
    var jsonOutput = false
    var memprofile = ""           // empty = none
}

// MARK: - Flags

enum FlagKind {
    case int, int64, uint64, string, bool
}

/// One command-line flag: its name, its help text, and where the raw
/// value lands. Values are validated after the whole line is parsed.
struct Flag {
    let name: String
    let typeLabel: String
    let kind: FlagKind
    let help: String
}

/// The raw flag values before validation.
final class RawFlags {
    var barrierFill: Int32 = 0
    var blobCycleEvery: Int64 = 0
    var blobMode: Int32 = 1
    var chunkSize = "0"
    var drbg = ""
    var duration = "5m"
    var gogc: Int32 = 0
    var gomaxprocs: Int32 = 0
    var goroutines: Int32 = 3
    var hash = "areion512"
    var iterations: Int64 = 0
    var jsonOutput = false
    var keyBits: Int32 = 0
    var mac = "hmac-blake3"
    var memlimit = "auto"
    var memprofile = ""
    var nonceBits: Int32 = 0
    var parallax = "on"
    var payloadMode = "fixed"
    var payloadSize = "16MB"
    var profile = ""
    var rekeyEvery: Int64 = 0
    var seed: UInt64 = 0
    var shape = "stream"
    var wrapper = "on"

    /// The default-value suffix the usage prints for this flag: an
    /// integer when non-zero, a string when non-empty, nothing
    /// otherwise.
    func defaultSuffix(_ f: Flag) -> String {
        switch f.kind {
        case .int:
            let v = intValue(f.name)
            return v != 0 ? " (default \(v))" : ""
        case .string:
            let v = stringValue(f.name)
            return v.isEmpty ? "" : " (default \"\(v)\")"
        default:
            return ""
        }
    }

    func intValue(_ name: String) -> Int32 {
        switch name {
        case "barrier-fill": return barrierFill
        case "blob-mode": return blobMode
        case "gogc": return gogc
        case "gomaxprocs": return gomaxprocs
        case "goroutines": return goroutines
        case "key-bits": return keyBits
        case "nonce-bits": return nonceBits
        default: return 0
        }
    }

    func stringValue(_ name: String) -> String {
        switch name {
        case "chunk-size": return chunkSize
        case "drbg": return drbg
        case "duration": return duration
        case "hash": return hash
        case "mac": return mac
        case "memlimit": return memlimit
        case "memprofile": return memprofile
        case "parallax": return parallax
        case "payload-mode": return payloadMode
        case "payload-size": return payloadSize
        case "profile": return profile
        case "shape": return shape
        case "wrapper": return wrapper
        default: return ""
        }
    }

    /// Parses one value into its flag slot; false on a malformed
    /// value.
    func assign(_ f: Flag, _ value: String) -> Bool {
        switch f.kind {
        case .int:
            guard let v = Int32(value) else {
                return false
            }
            switch f.name {
            case "barrier-fill": barrierFill = v
            case "blob-mode": blobMode = v
            case "gogc": gogc = v
            case "gomaxprocs": gomaxprocs = v
            case "goroutines": goroutines = v
            case "key-bits": keyBits = v
            case "nonce-bits": nonceBits = v
            default: return false
            }
            return true
        case .int64:
            guard let v = Int64(value) else {
                return false
            }
            switch f.name {
            case "blob-cycle-every": blobCycleEvery = v
            case "iterations": iterations = v
            case "rekey-every": rekeyEvery = v
            default: return false
            }
            return true
        case .uint64:
            guard !value.hasPrefix("-"), let v = UInt64(value) else {
                return false
            }
            seed = v
            return true
        case .string:
            switch f.name {
            case "chunk-size": chunkSize = value
            case "drbg": drbg = value
            case "duration": duration = value
            case "hash": hash = value
            case "mac": mac = value
            case "memlimit": memlimit = value
            case "memprofile": memprofile = value
            case "parallax": parallax = value
            case "payload-mode": payloadMode = value
            case "payload-size": payloadSize = value
            case "profile": profile = value
            case "shape": shape = value
            case "wrapper": wrapper = value
            default: return false
            }
            return true
        case .bool:
            if value == "true" {
                jsonOutput = true
            } else if value == "false" {
                jsonOutput = false
            } else {
                return false
            }
            return true
        }
    }
}

/// The flag table, in alphabetical order (the order the usage
/// prints).
let flagTable: [Flag] = [
    Flag(name: "barrier-fill", typeLabel: "int", kind: .int,
         help: "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)"),
    Flag(name: "blob-cycle-every", typeLabel: "int", kind: .int64,
         help: "reopen each pipeline from its session blob every N iterations per worker; 0 = never"),
    Flag(name: "blob-mode", typeLabel: "int", kind: .int,
         help: "container floor sizing mode: 1 (per-region, default) | 2 (per-container)"),
    Flag(name: "chunk-size", typeLabel: "string", kind: .string,
         help: "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape"),
    Flag(name: "drbg", typeLabel: "string", kind: .string,
         help: "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)"),
    Flag(name: "duration", typeLabel: "duration", kind: .string,
         help: "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0"),
    Flag(name: "gogc", typeLabel: "int", kind: .int,
         help: "GC trigger percentage; 0 = leave the runtime default"),
    Flag(name: "gomaxprocs", typeLabel: "int", kind: .int,
         help: "Go runtime GOMAXPROCS override; 0 = inherit from the environment"),
    Flag(name: "goroutines", typeLabel: "int", kind: .int,
         help: "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1"),
    Flag(name: "hash", typeLabel: "string", kind: .string,
         help: "inner ITB hash primitive name"),
    Flag(name: "iterations", typeLabel: "int", kind: .int64,
         help: "fixed per-worker iteration count; 0 = duration-based"),
    Flag(name: "json-output", typeLabel: "", kind: .bool,
         help: "print the final summary as one compact JSON object instead of log lines"),
    Flag(name: "key-bits", typeLabel: "int", kind: .int,
         help: "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)"),
    Flag(name: "mac", typeLabel: "string", kind: .string,
         help: "MAC primitive name"),
    Flag(name: "memlimit", typeLabel: "string", kind: .string,
         help: "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)"),
    Flag(name: "memprofile", typeLabel: "string", kind: .string,
         help: "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none"),
    Flag(name: "nonce-bits", typeLabel: "int", kind: .int,
         help: "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)"),
    Flag(name: "parallax", typeLabel: "string", kind: .string,
         help: "parallax layer: on | off"),
    Flag(name: "payload-mode", typeLabel: "string", kind: .string,
         help: "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii"),
    Flag(name: "payload-size", typeLabel: "string", kind: .string,
         help: "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)"),
    Flag(name: "profile", typeLabel: "string", kind: .string,
         help: "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair"),
    Flag(name: "rekey-every", typeLabel: "int", kind: .int64,
         help: "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never"),
    Flag(name: "seed", typeLabel: "uint", kind: .uint64,
         help: "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts"),
    Flag(name: "shape", typeLabel: "string", kind: .string,
         help: "cipher surface to exercise: stream | message | stream_one_shot | both"),
    Flag(name: "wrapper", typeLabel: "string", kind: .string,
         help: "wrapper layer: on | off"),
]

// MARK: - Signals

/// Graceful stop. SIGINT / SIGTERM set a flag the main thread polls
/// while it waits for the workers; it turns the flag into the stop
/// request every worker checks before starting an iteration, so a
/// signal interrupts nothing mid-call — the in-flight encrypt /
/// decrypt / compare completes, the worker returns, and the partial
/// summary prints with the verdict the completed iterations earned.
enum SignalState {
    nonisolated(unsafe) static var seen: sig_atomic_t = 0
}

func onSignal(_ sig: Int32) {
    SignalState.seen = 1
}

// MARK: - Worker launch

/// Swift-specific. pthread_create takes a C-convention entry point,
/// so the Worker reference crosses as an opaque pointer; the worker
/// objects outlive every thread because the run state owns them.
private func workerTrampoline(_ arg: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
    guard let arg else {
        return nil
    }
    Unmanaged<Worker>.fromOpaque(arg).takeUnretainedValue().main()
    return nil
}

// MARK: - The run

enum LoopMain {
    static func usage(_ defaults: RawFlags) {
        var out = "Usage of loop:\n"
        for f in flagTable {
            out += "  -\(f.name)" + (f.typeLabel.isEmpty ? "" : " " + f.typeLabel) + "\n"
            out += "    \t\(f.help)\(defaults.defaultSuffix(f))\n"
        }
        Log.stderrRaw(out)
    }

    /// Parses argv into the raw flag values. Accepts -name value,
    /// --name value, -name=value and --name=value; a boolean flag
    /// takes no value unless given as -name=true / -name=false.
    /// Returns 0, 1 for -h / --help (usage printed), or -1 after
    /// printing the error.
    static func parseArgv(_ argv: [String], _ f: RawFlags, _ defaults: RawFlags) -> Int {
        var i = 1
        while i < argv.count {
            let arg = argv[i]
            if !arg.hasPrefix("-") || arg == "-" {
                Log.err("unexpected positional arguments: [\(arg)]")
                return -1
            }
            var name = String(arg.dropFirst(arg.hasPrefix("--") ? 2 : 1))
            if name == "h" || name == "help" {
                usage(defaults)
                return 1
            }
            var value: String?
            if let eq = name.firstIndex(of: "=") {
                value = String(name[name.index(after: eq)...])
                name = String(name[name.startIndex..<eq])
            }
            guard let flag = flagTable.first(where: { $0.name == name }) else {
                Log.err("flag provided but not defined: -\(name)")
                usage(defaults)
                return -1
            }
            if value == nil {
                if flag.kind == .bool {
                    value = "true"
                } else if i + 1 < argv.count {
                    i += 1
                    value = argv[i]
                } else {
                    Log.err("flag needs an argument: -\(flag.name)")
                    return -1
                }
            }
            if !f.assign(flag, value!) {
                Log.err("invalid value \"\(value!)\" for flag -\(flag.name)")
                return -1
            }
            i += 1
        }
        return 0
    }

    /// Maps "on" / "off" to a bool; nil otherwise.
    static func parseOnOff(_ v: String) -> Bool? {
        v == "on" ? true : (v == "off" ? false : nil)
    }

    /// Whether name is in the shipped hash registry the binding
    /// enumerates.
    static func hashRegistered(_ name: String) -> Bool {
        guard let names = try? hashNames() else {
            return false
        }
        return names.contains(name)
    }

    /// Resolves a registered profile to the shape family its record's
    /// mode exposes by reading the record through the binding's
    /// lookup: a mode beginning with "streaming" exposes the stream
    /// surfaces, one beginning with "singlemsg" the message surface,
    /// "blob-only" none. Prints the validation message and returns nil
    /// on rejection.
    static func profileSurface(_ name: String) -> Shape? {
        guard let record = try? lookup(name: name) else {
            Log.err("--profile \"\(name)\" is not a registered triple profile")
            return nil
        }
        if record.mode.hasPrefix("streaming") {
            return .stream
        }
        if record.mode.hasPrefix("singlemsg") {
            return .message
        }
        Log.err("--profile \"\(name)\" carries no cipher surface (blob-only mode)")
        return nil
    }

    /// Applies a --profile's surface to the requested shape: a
    /// message-surface profile forces message; a stream-surface
    /// profile keeps stream or stream_one_shot as requested and turns
    /// message or both into stream.
    static func narrowShape(_ requested: Shape, _ surface: Shape) -> Shape {
        if surface == .message {
            return .message
        }
        return requested == .streamOneShot ? .streamOneShot : .stream
    }

    /// Builds the resolved config from argv. Returns 0, 1 for help, or
    /// -1 after printing "loop: <message>" for the first failing rule.
    static func parseFlags(_ argv: [String], _ cfg: inout Config) -> Int {
        let f = RawFlags()
        let defaults = RawFlags()
        let rc = parseArgv(argv, f, defaults)
        if rc != 0 {
            return rc
        }

        guard let durationNanos = parseDuration(f.duration), durationNanos > 0 else {
            Log.err("--duration must be positive, got \(f.duration)")
            return -1
        }
        cfg.durationNanos = durationNanos
        cfg.iterations = f.iterations
        if cfg.iterations < 0 {
            Log.err("--iterations must be >= 0, got \(cfg.iterations)")
            return -1
        }
        if f.goroutines < 1 || f.goroutines > Int32(loopMaxWorkers) {
            Log.err("--goroutines must be in 1..\(loopMaxWorkers), got \(f.goroutines)")
            return -1
        }
        // Concurrency mode. This binding runs shared-handle: POSIX
        // threads call into one Pipeline handle concurrently, which
        // the shared library permits after construction and the
        // binding's Pipeline class allows (it is Sendable and adds no
        // lock of its own), so --goroutines is the thread count
        // verbatim, never clamped.
        cfg.workersRequested = Int(f.goroutines)
        cfg.workers = Int(f.goroutines)
        guard let shape = Shape.parse(f.shape) else {
            Log.err("--shape must be stream | message | stream_one_shot | both, got \"\(f.shape)\"")
            return -1
        }
        cfg.shape = shape
        if !hashRegistered(f.hash) {
            Log.err("--hash \"\(f.hash)\" is not a registered hash primitive")
            return -1
        }
        cfg.hash = f.hash
        cfg.mac = f.mac // validated by Init: no MAC-name enumeration exists
        guard let payload = parseSize(f.payloadSize) else {
            Log.err("--payload-size: invalid size \"\(f.payloadSize)\"")
            return -1
        }
        cfg.payload = payload
        if cfg.payload < 1 {
            Log.err("--payload-size must be at least 1 byte")
            return -1
        }
        if f.memlimit == "auto" {
            cfg.memlimitAuto = true
            cfg.memlimit = cfg.workers <= 3 ? (1 << 30) : (256 << 20)
        } else {
            guard let m = parseSize(f.memlimit) else {
                Log.err("--memlimit: invalid size \"\(f.memlimit)\"")
                return -1
            }
            cfg.memlimit = m
        }
        cfg.gogc = f.gogc
        if cfg.gogc < 0 {
            Log.err("--gogc must be >= 0, got \(cfg.gogc)")
            return -1
        }
        guard let parallax = parseOnOff(f.parallax) else {
            Log.err("--parallax must be on | off, got \"\(f.parallax)\"")
            return -1
        }
        cfg.parallax = parallax
        guard let wrapper = parseOnOff(f.wrapper) else {
            Log.err("--wrapper must be on | off, got \"\(f.wrapper)\"")
            return -1
        }
        cfg.wrapper = wrapper
        cfg.profile = f.profile
        if !cfg.profile.isEmpty {
            guard let surface = profileSurface(cfg.profile) else {
                return -1
            }
            cfg.shape = narrowShape(cfg.shape, surface)
        }
        cfg.keyBits = f.keyBits
        switch cfg.keyBits {
        case 0, 512, 1024, 2048:
            break
        default:
            Log.err("--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got \(cfg.keyBits)")
            return -1
        }
        cfg.nonceBits = f.nonceBits
        switch cfg.nonceBits {
        case 0, 128, 256, 512:
            break
        default:
            Log.err("--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got \(cfg.nonceBits)")
            return -1
        }
        cfg.blobMode = f.blobMode
        switch cfg.blobMode {
        case 1, 2:
            break
        default:
            Log.err("--blob-mode must be 1 (per-region) | 2 (per-container), got \(cfg.blobMode)")
            return -1
        }
        cfg.barrierFill = f.barrierFill
        switch cfg.barrierFill {
        case 0, 1, 2, 4, 8, 16, 32:
            break
        default:
            Log.err("--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got \(cfg.barrierFill)")
            return -1
        }
        cfg.drbg = f.drbg // validated by Init: no DRBG-name enumeration exists
        guard let chunk = parseSize(f.chunkSize) else {
            Log.err("--chunk-size: invalid size \"\(f.chunkSize)\"")
            return -1
        }
        cfg.chunkSize = chunk
        cfg.gomaxprocs = f.gomaxprocs
        if cfg.gomaxprocs < 0 {
            Log.err("--gomaxprocs must be > 0 when specified, got \(cfg.gomaxprocs)")
            return -1
        }
        cfg.rekeyEvery = f.rekeyEvery
        if cfg.rekeyEvery < 0 {
            Log.err("--rekey-every must be >= 0, got \(cfg.rekeyEvery)")
            return -1
        }
        cfg.blobCycleEvery = f.blobCycleEvery
        if cfg.blobCycleEvery < 0 {
            Log.err("--blob-cycle-every must be >= 0, got \(cfg.blobCycleEvery)")
            return -1
        }
        guard let mode = PayloadMode.parse(f.payloadMode) else {
            Log.err("--payload-mode must be fixed | rotating | pattern-zero | pattern-ff | pattern-ascii, got \"\(f.payloadMode)\"")
            return -1
        }
        cfg.payloadMode = mode
        cfg.seed = f.seed
        cfg.jsonOutput = f.jsonOutput
        cfg.memprofile = f.memprofile
        return 0
    }

    // MARK: Pipelines

    /// Folds a keystream primitive into opts for any layer the named
    /// profile leaves unfilled but the operator asked for.
    ///
    /// A profile built around a primitive that is safe only inside the
    /// Interlocked Barrier ships with no parallax palette and no outer
    /// cipher: both layers run outside the barrier, where that
    /// primitive would stand bare, so the recipe leaves them unnamed
    /// rather than naming a primitive that must not key them. Engaging
    /// either layer therefore needs a keystream-capable primitive
    /// supplied from outside the recipe; without it construction fails
    /// on a palette below its minimum or an unnamed outer cipher, and
    /// the primitive that most deserves stressing becomes the one that
    /// cannot be stressed with those layers engaged.
    ///
    /// Overrides fold into the resolved record the blob carries, so
    /// the receiver rebuilds the same shape from the blob alone.
    ///
    /// Returns 1 when a layer was filled, 0 when none needed it, -1 on
    /// a lookup failure (message already printed).
    static func fillKeystreamLayers(_ name: String, _ opts: Opts,
                                    wantParallax: Bool, wantWrapper: Bool) -> Int {
        guard let record = try? lookup(name: name) else {
            Log.err("--profile \"\(name)\" is not a registered triple profile")
            return -1
        }
        var filled = 0
        if wantParallax && record.parallaxPalette.isEmpty {
            _ = try? opts.set("parallaxPalette",
                          [keystreamFillCipher, keystreamFillCipher, keystreamFillCipher]
                              .joined(separator: ","))
            if record.parallaxSegmentSize == 0 {
                // A recipe that never carried a palette never carried a
                // segment size either, and the schedule rejects zero.
                _ = try? opts.set("parallaxSegmentSize", "4093")
            }
            filled = 1
        }
        if wantWrapper && record.outerCipher.isEmpty {
            _ = try? opts.set("outerCipher", keystreamFillCipher)
            filled = 1
        }
        return filled
    }

    /// Prints the construction line with the recipe read back from the
    /// blob the Pipeline handed out, not echoed from the flags: every
    /// construction override is proven to have reached the library by
    /// the value the receiver would see. Record values that are empty
    /// (a No MAC profile's MAC, a mixed profile's single hash) print
    /// as "-".
    static func logPipelineInitialised(_ profile: String, _ blob: Data) {
        let record: Profile
        do {
            record = try inspect(blob)
        } catch let e as ItbError {
            Log.line("pipeline initialised: profile=\(profile) blob=\(blob.count) bytes (inspect: \(e.message))")
            return
        } catch {
            Log.line("pipeline initialised: profile=\(profile) blob=\(blob.count) bytes (inspect: \(error))")
            return
        }
        let hash = record.innerHash.isEmpty ? "-" : record.innerHash
        let mac = record.macName.isEmpty ? "-" : record.macName
        var line = "pipeline initialised: profile=\(profile) blob=\(blob.count) bytes hash=\(hash) "
            + "key-bits=\(record.keyBits) nonce-bits=\(record.nonceBits ?? 0) "
            + "barrier-fill=\(record.barrierFill ?? 0) chunk-size=\(record.chunkSize) mac=\(mac) "
            + "parallax=\(onOff(record.parallax)) wrapper=\(onOff(record.wrapper))"
        if record.containerMode == 2 {
            line += " container-mode=2"
        }
        if !record.drbg.isEmpty {
            line += " drbg=\(record.drbg)"
        }
        Log.line(line)
    }

    /// Sets the inner blob's "mode" field of a wrap-layer session blob
    /// to targetMode (1 = per-region, 2 = per-container) in place. The
    /// wrap layer's profile record carries its own "mode" (a string),
    /// so the search starts at the inner blob ("ib"); both shipped
    /// modes are one digit wide, so the blob length does not change.
    /// Returns false when the inner blob or its mode field is not
    /// found.
    static func editInnerBlobMode(_ blob: inout Data, _ targetMode: Int) -> Bool {
        guard let ib = blob.range(of: Data("\"ib\":{".utf8)),
              let mode = blob.range(of: Data("\"mode\":".utf8), in: ib.upperBound..<blob.endIndex) else {
            return false
        }
        let at = mode.upperBound
        guard at + 1 < blob.endIndex else {
            return false
        }
        let digit = UInt8(ascii: "0")
        let nine = UInt8(ascii: "9")
        if blob[at] < UInt8(ascii: "1") || blob[at] > UInt8(ascii: "2")
            || (blob[at + 1] >= digit && blob[at + 1] <= nine) {
            return false
        }
        blob[at] = digit + UInt8(targetMode)
        return true
    }

    /// Constructs one Pipeline against profile with every flag-carried
    /// override in the opts string (zero values included — the shared
    /// library treats zero as "profile default"), then obtains the
    /// Init blob once through save: the binding's init entry does not
    /// hand the blob back, and the bytes are the ones Init produced.
    /// Later blob reopens use the retained blob; save is never called
    /// again.
    static func buildPipeline(_ cfg: Config, _ profile: String) -> (Pipeline, Data)? {
        guard let opts = try? Opts() else {
            Log.err("out of memory")
            return nil
        }
        do {
            try opts.set("innerHash", cfg.hash)
            try opts.set("macName", cfg.mac)
            try opts.set("withParallax", cfg.parallax ? "true" : "false")
            try opts.set("withWrapper", cfg.wrapper ? "true" : "false")
            try opts.set("keyBits", "\(cfg.keyBits)")
            try opts.set("nonceBits", "\(cfg.nonceBits)")
            try opts.set("barrierFill", "\(cfg.barrierFill)")
            try opts.set("drbg", cfg.drbg)
            try opts.set("chunkSize", "\(cfg.chunkSize)")
        } catch {
            Log.err("opts: \(error)")
            return nil
        }
        if !cfg.profile.isEmpty {
            let filled = fillKeystreamLayers(cfg.profile, opts,
                                             wantParallax: cfg.parallax, wantWrapper: cfg.wrapper)
            if filled < 0 {
                return nil
            }
            if filled > 0 {
                Log.err("\(cfg.profile) leaves the requested keystream layers unnamed; "
                    + "\(keystreamFillCipher) supplied for them")
            }
        }

        var pipe: Pipeline
        do {
            pipe = try Pipeline(profile: profile, opts: opts)
        } catch let e as ItbError {
            Log.err("Init(\(profile)): status \(e.code): \(e.message)")
            return nil
        } catch {
            Log.err("Init(\(profile)): \(error)")
            return nil
        }
        var blob: Data
        do {
            blob = try pipe.save()
        } catch let e as ItbError {
            Log.err("Save(\(profile)): status \(e.code): \(e.message)")
            return nil
        } catch {
            Log.err("Save(\(profile)): \(error)")
            return nil
        }
        if cfg.blobMode == 2 {
            // The sizing mode is not an Opts knob: the Init blob is
            // edited and the pipeline reopened from it, so the retained
            // blob (the one blob-cycle reopens from) carries the edited
            // mode.
            if !editInnerBlobMode(&blob, 2) {
                Log.err("rewrite blob mode: inner blob mode field not found")
                return nil
            }
            do {
                pipe = try Pipeline(load: blob)
            } catch let e as ItbError {
                Log.err("reload Mode 2 blob: status \(e.code): \(e.message)")
                return nil
            } catch {
                Log.err("reload Mode 2 blob: \(error)")
                return nil
            }
        }
        logPipelineInitialised(profile, blob)
        return (pipe, blob)
    }

    // MARK: Run

    static func run(_ argv: [String]) -> Int32 {
        var cfg = Config()
        let rc = parseFlags(argv, &cfg)
        if rc == 1 {
            return 0
        }
        if rc != 0 {
            return 2
        }

        // Runtime shaping. A long run under allocation churn grows the
        // Go heap inside the shared library without bound unless a
        // soft limit paces the collector, so a limit is always in
        // force: an explicit --memlimit is set as given, and auto caps
        // the heap only when the runtime reports no limit at all (a
        // limit already installed from the environment is left
        // standing). The GC percentage and GOMAXPROCS are set only
        // when their flag is non-zero — a zero flag skips the setter
        // rather than calling it with zero, because zero is a real
        // value to the GC-percent setter, and a call would clobber
        // whatever the environment installed. All of it lands before
        // any Pipeline exists so the baselines are taken under the
        // shaped runtime.
        if cfg.memlimitAuto {
            if ItbRuntime.setMemoryLimit(-1) == Int64.max {
                ItbRuntime.setMemoryLimit(cfg.memlimit)
            }
        } else {
            ItbRuntime.setMemoryLimit(cfg.memlimit)
        }
        cfg.memlimit = ItbRuntime.setMemoryLimit(-1)
        if cfg.gogc > 0 {
            ItbRuntime.setGCPercent(cfg.gogc)
        }
        if cfg.gomaxprocs > 0 {
            ItbRuntime.setGOMAXPROCS(cfg.gomaxprocs)
        }

        Log.line("start: duration=\(humanDuration(cfg.durationNanos)) iterations=\(cfg.iterations) "
            + "goroutines=\(cfg.workersRequested) workers=\(cfg.workers) concurrency=\(loopConcurrency) "
            + "shape=\(cfg.shape.name) hash=\(cfg.hash) mac=\(cfg.mac) "
            + "payload=\(humanBytes(cfg.payload)) memlimit=\(humanBytes(cfg.memlimit)) "
            + "parallax=\(onOff(cfg.parallax)) wrapper=\(onOff(cfg.wrapper))")
        Log.line("overrides: profile=\"\(cfg.profile)\" key-bits=\(cfg.keyBits) "
            + "nonce-bits=\(cfg.nonceBits) chunk-size=\(humanBytes(cfg.chunkSize)) "
            + "barrier-fill=\(cfg.barrierFill) gomaxprocs=\(cfg.gomaxprocs) "
            + "rekey-every=\(cfg.rekeyEvery) blob-cycle-every=\(cfg.blobCycleEvery) "
            + "payload-mode=\(cfg.payloadMode.name) seed=\(cfg.seed) "
            + "json-output=\(cfg.jsonOutput ? "true" : "false")"
            + (cfg.blobMode != 1 ? " blob-mode=\(cfg.blobMode)" : "")
            + (cfg.drbg.isEmpty ? "" : " drbg=\(cfg.drbg)"))
        let env = ProcessInfo.processInfo.environment
        Log.line("policy: microbatch-tiers=\(policyLabel(env["ITB_MICROBATCH_TIERS"])) "
            + "hashpool-starters=\(policyLabel(env["ITB_HASHPOOL_STARTERS"]))")

        let r = RunState(cfg: cfg)

        // Pipeline construction — one shared handle per exercised
        // shape. stream and stream_one_shot share the streaming
        // handle.
        r.streamProfile = cfg.profile.isEmpty ? defaultStreamProfile : cfg.profile
        r.msgProfile = cfg.profile.isEmpty ? defaultMessageProfile : cfg.profile
        if cfg.shape == .stream || cfg.shape == .streamOneShot || cfg.shape == .both {
            guard let built = buildPipeline(cfg, r.streamProfile) else {
                return 1
            }
            r.streamPipe = built.0
            r.streamBlob = built.1
        }
        if cfg.shape == .message || cfg.shape == .both {
            guard let built = buildPipeline(cfg, r.msgProfile) else {
                return 1
            }
            r.msgPipe = built.0
            r.msgBlob = built.1
        }

        // Allocation posture. Per-worker plaintexts are allocated once
        // and held for the whole run (rotating mode refills them in
        // place per iteration); the pump accumulators live inside each
        // worker and are reused across iterations; the message and
        // one-shot outputs are handed back by the binding per call and
        // reclaimed per iteration. Under the default fixed CSPRNG mode
        // every worker's buffer is distinct, so cross-worker data
        // crossover is detectable; pattern modes trade that property
        // for content edge-case coverage.
        for i in 0..<cfg.workers {
            let w = Worker(id: i, run: r, cfg: cfg)
            if !fillPayload(cfg.payloadMode, seeded: w.seeded, rng: &w.rng,
                            buf: w.plaintext, count: w.plaintextLen) {
                Log.err("payload fill: csprng")
                return 1
            }
            r.workers.append(w)
        }

        if ItbRuntime.poolStatsLen == 0 {
            Log.err("pool snapshot alloc failed")
            return 1
        }

        signal(SIGINT, onSignal)
        signal(SIGTERM, onSignal)
        r.warmupDone = Barrier(UInt32(cfg.workers + 1))
        r.release = Barrier(UInt32(cfg.workers + 1))
        r.active = cfg.workers

        // Warmup barrier. Every worker runs one iteration and waits;
        // the clock starts only once all of them have paid their
        // first-call costs (pool warm-up, lazy kernel dispatch, page
        // faults on the payload buffers), and the RSS and pool
        // baselines taken here describe a process that has already run
        // the whole cipher path once per worker.
        let warmupStart = nowNanos()
        for w in r.workers {
            if pthread_create(&w.thread, nil, workerTrampoline,
                              Unmanaged.passUnretained(w).toOpaque()) != 0 {
                Log.err("pthread_create failed")
                return 1
            }
        }
        r.warmupDone.wait()
        (r.rssWarmup, r.rssPeak) = readRSS()
        r.poolWarmup = poolSnapshot()
        let warmupNanos = nowNanos() - warmupStart
        Log.line("warmup: \(cfg.workers) workers x 1 iter completed in "
            + humanDuration((warmupNanos + 50_000_000) / 100_000_000 * 100_000_000)
            + " (baseline rss=\(humanBytes(Int64(r.rssWarmup))))")

        // Open the gate; the duration timer is a deadline the waiter
        // below enforces in duration mode.
        r.startNanos = nowNanos()
        r.finishNanos = r.startNanos
        r.release.wait()

        // Wait for every worker, polling every 100 ms so the deadline
        // and a signal are both noticed promptly.
        r.doneCondition.lock()
        while r.active > 0 {
            if SignalState.seen != 0 {
                r.stop.store(true, ordering: .relaxed)
            }
            if cfg.iterations == 0 && nowNanos() - r.startNanos >= cfg.durationNanos {
                r.stop.store(true, ordering: .relaxed)
            }
            _ = r.doneCondition.wait(until: Date().addingTimeInterval(0.1))
        }
        r.doneCondition.unlock()
        for w in r.workers {
            pthread_join(w.thread, nil)
        }
        let elapsedNanos = r.finishNanos - r.startNanos
        (r.rssFinal, r.rssPeak) = readRSS()
        r.poolSteady = poolSnapshot()

        if !cfg.memprofile.isEmpty {
            do {
                try ItbRuntime.writeHeapProfile(cfg.memprofile)
                Log.line("memprofile: heap profile written to \(cfg.memprofile)")
            } catch let e as ItbError {
                Log.err("memprofile: \(e.message)")
            } catch {
                Log.err("memprofile: \(error)")
            }
        }

        let verdict = finalSummary(r, elapsedNanos)

        // Swift-specific. The plaintext buffers are raw allocations
        // and are released here; the Pipeline handles, the blobs and
        // the accumulators are reclaimed by ARC when the run state
        // goes out of scope.
        for w in r.workers {
            w.plaintext.deallocate()
        }
        return verdict
    }
}

exit(LoopMain.run(CommandLine.arguments))
