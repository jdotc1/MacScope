import Foundation
import XCTest
@testable import MacScope

final class RegenerationMachOStructureFixtureTests: XCTestCase {
    func testCompileOnlyObjectiveCFixturePair() throws {
        guard let root = ProcessInfo.processInfo.environment["MACSCOPE_REGEN_FIXTURE_ROOT"], !root.isEmpty else {
            throw XCTSkip("Set MACSCOPE_REGEN_FIXTURE_ROOT to the retained compile-only fixture pair")
        }
        let directory = URL(fileURLWithPath: root, isDirectory: true)
        let parser = MachOParser()
        let original = try parser.parse(Data(contentsOf: directory.appendingPathComponent("original")))
        let rebuilt = try parser.parse(Data(contentsOf: directory.appendingPathComponent("rebuilt")))
        XCTAssertEqual(original.architectureName, "arm64")
        XCTAssertEqual(rebuilt.architectureName, "arm64")
        let dimensions = try MachOStructureProjection.compare(original: original, rebuilt: rebuilt, budget: .start())
        let methods = try XCTUnwrap(dimensions.first { $0.name == "Objective-C methods" })
        let ivars = try XCTUnwrap(dimensions.first { $0.name == "Objective-C ivars" })
        XCTAssertFalse(methods.available, "Parser diagnostics do not certify complete lists")
        XCTAssertFalse(ivars.available, "Parser diagnostics do not certify complete lists")
        XCTAssertTrue(methods.original.contains { $0.key.contains("read:") })
        XCTAssertFalse(methods.rebuilt.contains { $0.key.contains("read:") })
        XCTAssertTrue(ivars.original.contains { $0.value == "i" })
        XCTAssertTrue(ivars.rebuilt.contains { $0.value == "q" })

    }
}
