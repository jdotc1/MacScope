// Test-only helper for the component evidence tests: synthesizes Mach-O bytes, owned temporary .app trees and
// deterministic fault seams. Nothing here executes or loads a binary.

import Darwin
import Foundation
import XCTest
@testable import MacScope

typealias CE = ComponentEvidence

enum CEBytes {
    static func le32(_ values: [UInt32]) -> [UInt8] { values.flatMap { v in (0..<4).map { UInt8((v >> UInt32($0 * 8)) & 0xff) } } }
    static func be32(_ values: [UInt32]) -> [UInt8] { values.flatMap { v in (0..<4).map { UInt8((v >> UInt32((3 - $0) * 8)) & 0xff) } } }

    /// 56-byte thin 64-bit arm64 executable with one LC_BUILD_VERSION for macOS 14.1.0.
    static var arm64: [UInt8] {
        [0xcf, 0xfa, 0xed, 0xfe] + le32([0x0100000c, 0, 2, 1, 24, 0, 0]) + le32([0x32, 24, 1, 0x000e0100, 0, 0])
    }
    /// 48-byte x86_64 legacy variant with LC_VERSION_MIN_MACOSX 12.3.0.
    static var x86Legacy: [UInt8] {
        [0xcf, 0xfa, 0xed, 0xfe] + le32([0x01000007, 3, 2, 1, 16, 0, 0]) + le32([0x24, 16, 0x000c0300, 0])
    }
    /// 56-byte x86_64 with a 24-byte build-version command (macOS 13.0.0).
    static var x86Build: [UInt8] {
        [0xcf, 0xfa, 0xed, 0xfe] + le32([0x01000007, 3, 2, 1, 24, 0, 0]) + le32([0x32, 24, 1, 0x000d0000, 0, 0])
    }
    /// Universal container holding arm64 at 4096 and x86_64 legacy at 8192 (8240 bytes).
    static var universal: [UInt8] {
        var out = [0xca, 0xfe, 0xba, 0xbe] + be32([2])
        out += be32([0x0100000c, 0, 0x1000, 56, 12]) + be32([0x01000007, 3, 0x2000, 48, 12])
        out += [UInt8](repeating: 0, count: 4096 - out.count) + arm64
        out += [UInt8](repeating: 0, count: 8192 - out.count) + x86Legacy
        return out
    }
    /// 4096-byte candidate: valid thin header followed by zero padding.
    static var padded: [UInt8] { arm64 + [UInt8](repeating: 0, count: 4096 - arm64.count) }
    /// 32 zero bytes with magic and filetype 1 (object).
    static var object: [UInt8] {
        var out = [UInt8](repeating: 0, count: 32)
        out.replaceSubrange(0..<4, with: [0xcf, 0xfa, 0xed, 0xfe]); out[12] = 1
        return out
    }
    static var badFat: [UInt8] { [0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 0x41] }
    /// LC_LOAD_DYLIB for @rpath/Owned.dylib in an arm64 thin image (80 bytes).
    static func loadDylib(nameOffset: UInt32 = 24) -> [UInt8] {
        [0xcf, 0xfa, 0xed, 0xfe] + le32([0x0100000c, 0, 2, 1, 48, 0, 0]) + le32([0xc, 48, nameOffset, 0, 0x10000, 0x10000])
            + Array("@rpath/Owned.dylib".utf8) + [0] + [UInt8](repeating: 0, count: 5)
    }
    static func plist(_ dictionary: [String: Any]) -> [UInt8] {
        [UInt8]((try? PropertyListSerialization.data(fromPropertyList: dictionary, format: .xml, options: 0)) ?? Data())
    }
}

/// An owned temporary `.app` tree. Removed again at test teardown.
final class CEBundle {
    let base: URL
    let root: URL
    init(_ test: XCTestCase, name: String = "Owned.app") throws {
        base = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("ce1314-" + UUID().uuidString)
        root = base.appendingPathComponent(name)
        try FileManager.default.createDirectory(at: root.appendingPathComponent("Contents"), withIntermediateDirectories: true)
        let base = self.base
        test.addTeardownBlock { try? FileManager.default.removeItem(at: base) }
    }
    func url(_ path: String) -> URL { root.appendingPathComponent(path) }
    func write(_ path: String, _ bytes: [UInt8], executable: Bool = true) throws {
        let target = url(path)
        try FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data(bytes).write(to: target)
        chmod(target.path, executable ? 0o755 : 0o644)
    }
    func writeRaw(_ path: String, name: [UInt8], _ bytes: [UInt8]) throws {
        let directory = url(path)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var full = Array(directory.path.utf8) + [0x2f] + name + [0]
        let fd = full.withUnsafeMutableBytes { raw in Darwin.open(raw.baseAddress!.assumingMemoryBound(to: CChar.self), O_CREAT | O_WRONLY, 0o644) }
        guard fd >= 0 else { throw XCTSkip("host refuses raw file name bytes") }
        _ = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, bytes.count) }
        Darwin.close(fd)
    }
    func directory(_ path: String) throws { try FileManager.default.createDirectory(at: url(path), withIntermediateDirectories: true) }
    func symlink(_ path: String, to target: String) throws {
        try FileManager.default.createDirectory(at: url(path).deletingLastPathComponent(), withIntermediateDirectories: true)
        try FileManager.default.createSymbolicLink(atPath: url(path).path, withDestinationPath: target)
    }
    func hardLink(_ path: String, to existing: String) throws {
        try FileManager.default.createDirectory(at: url(path).deletingLastPathComponent(), withIntermediateDirectories: true)
        XCTAssertEqual(link(url(existing).path, url(path).path), 0)
    }
    func info(_ extra: [String: Any] = [:], executable: String? = "OwnedMain", at path: String = "Contents/Info.plist") throws {
        var dictionary = extra
        if let executable { dictionary["CFBundleExecutable"] = executable }
        try write(path, CEBytes.plist(dictionary), executable: false)
    }
    /// The brief's discovery layout.
    func standardLayout() throws {
        try info(["CFBundleIdentifier": "com.example.owned", "CFBundleShortVersionString": "1.0"])
        try write("Contents/MacOS/OwnedMain", CEBytes.arm64)
        try write("Contents/Frameworks/Owned.framework/Versions/A/Owned", CEBytes.arm64)
        try symlink("Contents/Frameworks/Owned.framework/Versions/Current", to: "A")
        try write("Contents/Helpers/helper", CEBytes.arm64)
        try write("Contents/XPCServices/Owned.xpc/Contents/MacOS/service", CEBytes.arm64)
        try write("Contents/Helpers/readme.txt", Array("Resource, not image".utf8), executable: false)
        try write("Contents/Resources/outside-code-scope", CEBytes.arm64)
    }
}

enum CEHarness {
    /// One capture with no requests unless supplied.
    @discardableResult
    static func capture(_ bundle: CEBundle, limits: CE.BundleDiscovery.Limits = .init(), fault: @escaping CE.FaultInjector = { _, _ in nil },
                        requests: ((CE.LiveComponentInventory, CE.SessionID) -> [CE.CaptureRequest])? = nil) throws -> CE.CaptureResult {
        try CE.capture(selection: bundle.root, limits: limits, fault: fault) { live, session in requests?(live, session) ?? [] }
    }
    static func paths(_ inventory: CE.ComponentInventory) -> [String] { inventory.components.map { $0.path.display } }
    static func exclusions(_ inventory: CE.ComponentInventory, _ state: CE.ExclusionState) -> [String] {
        inventory.scope.exclusions.filter { $0.state == state }.map { $0.rawPath.display }
    }
    static func key(_ text: String) -> CE.ExactUTF8Key { CE.ExactUTF8Key(text) }
    static func path(_ text: String) -> CE.RelativePath { try! CE.RelativePath(text) }
    /// Pure-value record for matcher/review tests.
    static func record(_ path: String, kind: String = "helper", id: String? = nil, version: String? = nil,
                       architectures: [String] = ["arm64"], issues: [CE.EvidenceIssue] = []) -> CE.ComponentRecord {
        CE.ComponentRecord(id: UUID(), parentID: nil, path: Self.path(path), kind: key(kind),
                           declaredBundleID: id.map(key), declaredVersion: version.map(key), architectures: architectures.map(key),
                           minimumOS: [], slices: [], issues: issues, issueOverflow: nil, metadataAvailable: true, isDeclarationOnly: false)
    }
    static func scope(_ completion: CE.InventoryCompletion = .complete, exclusions: [CE.ExclusionRecord] = []) -> CE.InventoryScope {
        CE.InventoryScope(searchedLocations: [], completion: completion, exclusions: exclusions, exclusionOverflow: nil, issues: [],
                          issueOverflow: nil, visited: 0, headerBytes: 0, remainderUnknown: false,
                          limitEntries: 4096, limitDepth: 12, limitCandidates: 128, limitHeaderBytes: 1_048_576)
    }
    static func inventory(_ records: [CE.ComponentRecord], _ scope: CE.InventoryScope? = nil) -> CE.ComponentInventory {
        CE.ComponentInventory(id: UUID(), components: records, scope: scope ?? Self.scope())
    }
}
