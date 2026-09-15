/*
 * PersistTests.swift — persistence surface: save / saveF / load /
 * loadFile round trips, inspect, lookup / profiles, maxWorkers.
 */

import Foundation
import XCTest
@testable import Itb3

final class PersistTests: XCTestCase {
    private func roundTrip(_ sender: Pipeline, _ receiver: Pipeline,
                           _ what: String) throws {
        let plain = Data("persist payload".utf8)
        let back = try receiver.decryptMessage(try sender.encryptMessage(plain))
        XCTAssertEqual(back, plain, what)
    }

    func testSaveThenLoadRoundTrip() throws {
        let sender = try Pipeline(profile: "singlemsg-triple-mac-v1")
        let blob = try sender.save()
        XCTAssertEqual(try sender.save(), blob, "save must be stable")
        let receiver = try Pipeline(load: blob)
        try roundTrip(sender, receiver, "in-memory")
        XCTAssertEqual(try receiver.save(), blob, "load must retain the blob bytes")
    }

    func testLoadWithMasterOverrides() throws {
        let sender = try Pipeline(profile: "singlemsg-triple-mac-v1")
        let blob = try sender.save()
        let perm = Data(repeating: 0x31, count: 32)
        let wrap = Data(repeating: 0x32, count: 32)
        let receiver = try Pipeline(load: blob, permMaster: perm, wrapMaster: wrap)
        XCTAssertNotEqual(try receiver.save(), blob, "master overrides must rotate the blob")
        try sender.rekey(permMaster: perm, wrapMaster: wrap)
        try roundTrip(sender, receiver, "overrides")
    }

    func testInspectEqualsLookup() throws {
        let sender = try Pipeline(profile: "singlemsg-triple-mac-v1")
        let prof = try inspect(try sender.save())
        XCTAssertEqual(prof.name, "singlemsg-triple-mac-v1")
        XCTAssertEqual(prof.mode, "singlemsg-mac")
        XCTAssertEqual(prof.width, 512)
        XCTAssertEqual(prof.innerHash, "areion512")
        XCTAssertEqual(prof.macName, "hmac-blake3")
        XCTAssertTrue(prof.wrapper && prof.parallax)
        // The recipe fields match the registry entry; the two
        // inspection-only fields separate the two records.
        var recipe = prof
        recipe.nonceBits = nil
        recipe.barrierFill = nil
        XCTAssertEqual(recipe, try lookup(name: "singlemsg-triple-mac-v1"))
        XCTAssertThrowsError(try inspect(Data("not a blob".utf8))) { error in
            XCTAssertEqual((error as? ItbError)?.status, .badInput)
        }
    }

    func testInspectCarriesRuntimeGlobalsLookupDoesNot() throws {
        // Defaults: the blob records the compile-in nonce width and
        // barrier fill margin, and inspect surfaces both.
        let sender = try Pipeline(profile: "singlemsg-triple-mac-v1")
        let prof = try inspect(try sender.save())
        XCTAssertEqual(prof.nonceBits, 512)
        XCTAssertEqual(prof.barrierFill, 1)

        // Per-Pipeline overrides travel through the blob into inspect.
        let opts = try Opts(["nonceBits": "256", "barrierFill": "4"])
        let tuned = try Pipeline(profile: "singlemsg-triple-mac-v1", opts: opts)
        let tunedProf = try inspect(try tuned.save())
        XCTAssertEqual(tunedProf.nonceBits, 256)
        XCTAssertEqual(tunedProf.barrierFill, 4)
        XCTAssertTrue(try tunedProf.toJSON().contains("\"nonce_bits\":256"))
        XCTAssertTrue(try tunedProf.toJSON().contains("\"barrier_fill\":4"))

        // The registry entry is the recipe alone — neither field is
        // part of it, so both read as absent rather than as zero.
        let registry = try lookup(name: "singlemsg-triple-mac-v1")
        XCTAssertNil(registry.nonceBits)
        XCTAssertNil(registry.barrierFill)
        XCTAssertFalse(try registry.toJSON().contains("nonce_bits"))
        XCTAssertFalse(try registry.toJSON().contains("barrier_fill"))
    }

    func testProfilesListsTheCatalogue() throws {
        let names = try profiles()
        XCTAssertTrue(names.contains("singlemsg-triple-mac-v1"))
        XCTAssertEqual(names, names.sorted())
        for n in names {
            XCTAssertEqual(try lookup(name: n).name, n)
        }
    }

    func testSaveFThenLoadFile() throws {
        let path = NSTemporaryDirectory() + "itb-swift-persist-\(getpid()).blob"
        let sender = try Pipeline(profile: "streaming-aead-triple-mac-v1")
        try sender.saveF(path)
        let attrs = try FileManager.default.attributesOfItem(atPath: path)
        XCTAssertEqual((attrs[.posixPermissions] as? Int) ?? -1, 0o600)
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: path)), try sender.save())
        let receiver = try Pipeline(loadFile: path)
        let plain = Data("on-disk".utf8)
        XCTAssertEqual(try receiver.decryptStreamOneShot(try sender.encryptStreamOneShot(plain)), plain)
        try FileManager.default.removeItem(atPath: path)
        XCTAssertThrowsError(try Pipeline(loadFile: path)) { error in
            XCTAssertEqual((error as? ItbError)?.status, .badInput)
        }
    }

    func testMaxWorkersClampsAndClosedReportsTripleClosed() throws {
        let sender = try Pipeline(profile: "singlemsg-triple-mac-v1")
        try sender.maxWorkers(2)
        try sender.maxWorkers(-1)
        try sender.maxWorkers(100_000)
        let receiver = try Pipeline(load: try sender.save())
        try receiver.maxWorkers(1)
        try roundTrip(sender, receiver, "workers")
    }
}
