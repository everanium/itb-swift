## ITB Swift Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the C binding's public surface
([`bindings/c/include/itb3.h`](https://github.com/everanium/itb/blob/main/bindings/c/include/itb3.h), `libitb3_c`),
which in turn wraps the libitb3 shared library's `ITB_Triple_*`
surface (`cmd/cshared`). The C header is imported as the Swift
module `CItb` through a SwiftPM system-library target
(`Sources/CItb/module.modulemap`); both native libraries are
**linked at compile time** (`-litb3_c -litb3` with embedded RPATHs) —
no runtime symbol loading. Every hash-name / MAC-name / cipher-name
/ profile-name is an opaque string passed through to Go for
validation; the binding carries no ITB construction logic. Buffer
sizing (the caller-allocated-buffer convention with the retry-once
on `BUFFER_TOO_SMALL`) lives in the C layer; the Swift layer moves
opaque bytes and relays status codes.

The public surface is one `Pipeline` class (init / load / save /
rekey / maxWorkers, Single Message encrypt / decrypt, whole-buffer
stream entries (`encryptStreamOneShot` and the pumps), incremental
`EncryptStream` / `DecryptStream` sessions with
write / end / read), an `Opts` query-string builder for init
overrides, the `Profile` record with `register` / `lookup` /
`profiles` / `inspect`, and the Go runtime knobs under `ItbRuntime`.
Every fallible entry `throws ItbError`; `Result`-shaped and
`async` variants wrap the same calls, and `AsyncSequence`
adapters cover streaming (`session.chunks()`,
`pipeline.encryptStream(from:)` / `decryptStream(from:)`).
Handle lifetime is ARC-managed: `Pipeline` and stream sessions
release their C handles on deinit (key material is zeroed
Go-side), and a session strongly pins its parent `Pipeline`.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go gcc make
paru -S swift-bin        # Swift 6+ (AUR)
```

Generic Linux: a Go toolchain, a C11 compiler, GNU make, and a
Swift 6+ toolchain (swift.org tarball or distribution package).
macOS: the same via Xcode; libitb3 builds as `libitb3.dylib`.

## Build

The convenience driver builds `libitb3.so`, the C binding library
(`libitb3_c`), and the Swift package in release configuration:

```bash
./bindings/swift/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb3.so ./cmd/cshared
make -C bindings/c build/libitb3_c.a build/libitb3_c.so
cd bindings/swift && swift build -c release
```

`Package.swift` derives the `-L` / RPATH flags from its own
location, so the package builds from any checkout path without
`LD_LIBRARY_PATH`.

## Library lookup order

Both `libitb3_c` and `libitb3` are resolved at **compile time** through
the linker settings declared in `Package.swift`:

1. `-L bindings/c/build` (the C binding library's build output) and
   `-L dist/<os>-<arch>` (the libitb3 shared library) — both directory
   paths derived from the manifest's own file location so the flags
   stay valid across checkout paths.
2. `-Xlinker -rpath` entries for the same two directories are embedded
   into every produced executable, so the binaries run without
   `LD_LIBRARY_PATH` (Linux) or `DYLD_LIBRARY_PATH` (macOS).
3. The OS default loader path is the final fallback.

Moving `libitb3.so` or `libitb3_c.so` after build requires either the
baked RPATHs to stay valid or the appropriate loader-path env var at
run time.

## Usage example

```swift
import Itb3

let sender = try Pipeline(profile: "singlemsg-triple-mac-v1")
let receiver = try Pipeline(load: try sender.save())

let wire = try sender.encryptMessage(Data("any text or binary data".utf8))
let plain = try receiver.decryptMessage(wire)
```

`Opts` overrides the profile default at init (chunk size, outer
cipher, parallax on/off, wrapper on/off, MAC name, palette, worker
cap); every setter goes through `set(key, value)`. The resolved shape
travels inside the blob, so the receiver needs no options of its own:

```swift
let opts = try Opts()
try opts.set("chunkSize", "65536")
try opts.set("withWrapper", "false")
try opts.set("maxWorkers", "4")
let sender = try Pipeline(profile: "singlemsg-triple-mac-v1", opts: opts)
let receiver = try Pipeline(load: try sender.save())
```

`Pipeline.rekey` rotates the parallax + wrapper masters mid-session
(the eight ITB seeds and MAC key are fixed for the session lifetime
by design) and returns the fresh blob; the receiver picks up the new
masters by loading it:

```swift
let rotated = try sender.rekey(permMaster: Data(repeating: 0x11, count: 32),
                               wrapMaster: Data(repeating: 0x22, count: 32))
let receiver2 = try Pipeline(load: rotated)
```

The same rotation is available on the receiver side as a master
override pair on load: `Pipeline(load: blob, permMaster: perm,
wrapMaster: wrap)` reopens the blob with fresh masters folded in.

## Persisting sessions

The blob returned by `save()` is a self-describing session bundle: it
carries the resolved profile record, the inner key material, and the
parallax / wrapper masters. `Pipeline(load:)` reconstructs a Pipeline
from it without naming a profile.

```swift
let blob = try sender.save()                              // current blob bytes
let receiver = try Pipeline(load: blob)                   // reopen from bytes
try sender.saveF("session.blob")                          // write to a file (mode 0600)
let receiver2 = try Pipeline(loadFile: "session.blob")    // reopen from a file
let profile = try inspect(blob)                           // metadata only, no Pipeline
assert(profile.name == "singlemsg-triple-mac-v1")
```

`inspect` decodes the embedded `Profile` record without constructing
a Pipeline. `saveF` / `Pipeline(loadFile:)` perform the file access
inside libitb3.

Load works for blobs generated with shipped primitives (every entry in
the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to load such a blob through this
binding throws `ItbError` with `.recipePrimitiveUnknown`.

**Runtime tuning.** The worker cap is per-machine and never travels
in the blob; the receiver may pick its own after load:

```swift
try receiver.maxWorkers(4)   // clamped by libitb3; <= 0 selects auto
```

## Profile registry

`register` installs a user-defined profile under a new name from a
`Profile` record; `lookup` reads a registered record back; `profiles`
lists every registered name. The record's field rules are enforced by
libitb3.

```swift
var custom = try lookup(name: "singlemsg-triple-nomac-v1")
custom.name = ""                 // a non-empty name must equal the register argument
custom.wrapper = false
custom.outerCipher = ""
try register(name: "my-nomac-plain", profile: custom)
assert(try profiles().contains("my-nomac-plain"))
```

The same calls carry `async` variants (`try await
sender.encryptMessage(...)`) that hop the blocking FFI call onto a
background task, and `Result`-shaped variants
(`encryptMessageResult` returning `Result<Data, ItbError>`).

`encryptStreamOneShot` / `decryptStreamOneShot` put a whole
in-memory payload through the stream chain in a single call. For
bounded-memory streaming, `encryptStreamPump` /
`decryptStreamPump` move a whole buffer through an incremental
session; the explicit `encryptStream()` / `decryptStream()`
sessions expose `write` / `end` / `read` for caller-driven loops
plus a `chunks()` `AsyncSequence` for the drain side. The
transform shape consumes any async chunk source:

```swift
for try await wireChunk in sender.encryptStream(from: plainChunks) {
    // forward wireChunk
}
```

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string surfaces as a thrown `ItbError`
carrying the status code plus the `itb_last_error()` diagnostic.

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable
at libitb3 load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically. Pass `-1` to query without
changing. Long-running or allocation-heavy workloads (benchmarks,
bulk encryption) should set both — without a soft cap + aggressive
GC the Go scratch heap grows unboundedly under allocation churn:

```swift
ItbRuntime.setMemoryLimit(4 << 30) // 4 GiB soft cap
ItbRuntime.setGCPercent(100)        // balanced GC
```

## Testing

```bash
./bindings/swift/run_tests.sh
```

The harness builds `libitb3.so` + the C binding library and invokes
`swift test` (XCTest). Positional arguments are forwarded (e.g.
`./run_tests.sh --filter Smoke`). The suite covers Single Message
round trips per shipped profile, stream pumps, incremental sessions
with pathological batch sizes, tampered-wire failure stickiness,
mid-flight cancellation, rekey, profile registration, error
mapping, and the async / `Result` / `AsyncSequence` surfaces —
surface parity checks; the deep suite lives in Go under the shipped
tree.

## Benchmarking

```bash
./bindings/swift/run_bench.sh            # both shapes
./bindings/swift/run_bench.sh message    # Single Message only
./bindings/swift/run_bench.sh stream     # stream pump only
```

Micro-benches: `message` (encryptMessage) and `stream_pump`
(encryptStreamPump) throughput at 1 MiB / 16 MiB / 64 MiB, reported
as an MB/s table on stdout. The runner exports
`ITB_GOMEMLIMIT=4GiB` + `ITB_GOGC=100` defaults (respecting caller
overrides) and the bench main applies the same caps
programmatically; the bench shape follows the fleet-canonical
env-var surface documented in [`bindings/BENCH.md`](https://github.com/everanium/itb/blob/main/bindings/BENCH.md).

## itb3 CLI

The Go core ships an openssl-style CLI utility
[`itb3`](https://github.com/everanium/itb/tree/main/cmd/itb3/) that generates session blobs on disk
(`itb3 genblob <mode> <hash> -o blob.json`); this binding reopens
such blobs via `Pipeline(loadFile:)`. `itb3` also encrypts /
decrypts payloads directly on disk (`-i` / `-o`) or through stdin /
stdout, rotates outer masters, and inspects stored blobs. See
[`cmd/itb3/README.md`](https://github.com/everanium/itb/blob/main/cmd/itb3/README.md) for the full
subcommand reference.

## eitb utility

A small CLI mirrors the shipped Go `tools/eitb` scope for shell
smoke tests:

```bash
cd bindings/swift && swift build -c release
.build/release/eitb version
.build/release/eitb profiles
.build/release/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin   # blob hex on stderr
.build/release/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

`decrypt` reopens the session with `Pipeline(load:)` from the blob
hex; the profile argument only selects the Single Message or
streaming cipher pair.

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- The `itb_last_error()` text is process-global last-write-wins on
  the Go side; the `message` attached to an `ItbError` may belong
  to a different call under concurrent FFI use. The status code is
  always attributable.
- `rekey` must not run concurrently with cipher calls or open
  stream sessions on the same `Pipeline`.
- A stream session strongly references its `Pipeline`, so the
  Pipeline cannot be released while a session is alive; sessions
  free their C handle on deinit or on an explicit `free()`
  (idempotent — later calls fail with `.badInput`).
- The `CItb` module resolves the C header by relative path inside
  the monorepo; the package is built in-repo, not as a standalone
  registry package.

## License

Apache-2.0 — see [LICENSE](https://github.com/everanium/itb/blob/main/LICENSE).
