// swift-tools-version: 6.0
//
// Package.swift — SwiftPM manifest for the ITB Swift binding.
//
// The binding is a thin proxy over the C binding's public surface
// (bindings/c/include/itb3.h, libitb3_c) which in turn links the
// libitb3 shared library (cmd/cshared). Both native libraries are
// resolved at compile time with embedded RPATHs — no runtime symbol
// loading. Build bindings/c first (./build.sh does both steps).

import PackageDescription
import Foundation

// Absolute paths derived from the manifest location so the link +
// rpath flags stay machine-independent inside the repository.
let packageDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let bindingsDir = packageDir.deletingLastPathComponent()
let repoRoot = bindingsDir.deletingLastPathComponent()
let cBuildDir = bindingsDir.appendingPathComponent("c/build").path
let distDir = repoRoot.appendingPathComponent("dist/linux-amd64").path

// libitb3_c.so carries its own RPATH to dist/, but both directories are
// embedded here so the produced binaries run from any working
// directory without LD_LIBRARY_PATH.
let itbLinkerSettings: [LinkerSetting] = [
    .linkedLibrary("itb3_c"),
    .linkedLibrary("itb3"),
    .unsafeFlags([
        "-L\(cBuildDir)",
        "-L\(distDir)",
        "-Xlinker", "-rpath", "-Xlinker", cBuildDir,
        "-Xlinker", "-rpath", "-Xlinker", distDir,
    ]),
]

let package = Package(
    name: "LibItb3",
    products: [
        .library(name: "LibItb3", targets: ["Itb3"]),
        .executable(name: "Itb3Bench", targets: ["Itb3Bench"]),
        .executable(name: "eitb", targets: ["eitb"]),
    ],
    targets: [
        .systemLibrary(name: "CItb", path: "Sources/CItb"),
        .target(
            name: "Itb3",
            dependencies: ["CItb"],
            linkerSettings: itbLinkerSettings
        ),
        .executableTarget(name: "Itb3Bench", dependencies: ["Itb3"]),
        .executableTarget(name: "eitb", dependencies: ["Itb3"]),
        .testTarget(name: "Itb3Tests", dependencies: ["Itb3"]),
    ]
)
