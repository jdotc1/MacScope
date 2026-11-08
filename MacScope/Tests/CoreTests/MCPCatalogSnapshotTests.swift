import XCTest
@testable import MacScope

// Authored, unrun. Proves ordered metadata/index/set invariants and a lazy-owner
// construction count; the latter does not observe the process static's initializer.
private extension MCPCatalogSnapshot {
    init(testCommands: [ScriptingCommandInfo], didConstruct: () -> Void) {
        didConstruct()
        self.init(commands: testCommands)
    }
}

@MainActor
final class MCPCatalogSnapshotTests: XCTestCase {
    private final class Counter { var value = 0 }
    private final class Owner {
        let commands: [ScriptingCommandInfo]
        let counter: Counter
        lazy var snapshot = MCPCatalogSnapshot(testCommands: commands) {
            self.counter.value += 1
        }
        init(commands: [ScriptingCommandInfo], counter: Counter) {
            self.commands = commands
            self.counter = counter
        }
    }

    // Type-presence: absent at the pin; expected not to compile there.
    func testNewSnapshotTypePresence() {
        let snapshot = MCPCatalogSnapshot.capture([])
        XCTAssertEqual(snapshot.commands, [])
        XCTAssertEqual(snapshot.mutatingNames, [])
        XCTAssertNil(snapshot.command(named: "missing"))
    }

    // Invariant/control: same-build authoritative array, not a historical capture.
    func testAuthoritativeOrderMetadataAndNavigatorSuffix() throws {
        let authoritative = HeadlessAutomationAuthority.availableCommands
        let snapshot = MCPCatalogSnapshot.capture(authoritative)
        XCTAssertFalse(authoritative.isEmpty)
        XCTAssertEqual(snapshot.commands, authoritative)
        XCTAssertEqual(snapshot.mutatingNames,
                       Set(authoritative.filter(\.mutates).map(\.name)))
        let navigator = NavigatorMCPCommands.catalog
        XCTAssertFalse(navigator.isEmpty)
        XCTAssertEqual(Array(snapshot.commands.suffix(navigator.count)), navigator)
        XCTAssertEqual(snapshot.commands[authoritative.count - navigator.count].name,
                       NavigatorMCPCommands.nameFacts)
        let prefix = Array(authoritative.dropLast(navigator.count))
        XCTAssertEqual(prefix.map(\.name), prefix.map(\.name).sorted())
        for info in authoritative {
            XCTAssertEqual(snapshot.command(named: info.name),
                           authoritative.first { $0.name == info.name })
        }
    }

    // Invariant/control, conditional on H1 landing; this does not reset a Swift static.
    func testProcessSnapshotUsesAuthoritativeArray() {
        let expected = HeadlessAutomationAuthority.availableCommands
        let first = HeadlessAutomationAuthority.catalogSnapshot
        XCTAssertEqual(first.commands, expected)
        for _ in 0..<17 {
            XCTAssertEqual(HeadlessAutomationAuthority.catalogSnapshot, first)
        }
    }

    // Invariant/control: legacy first(where:) and legacy mutating set deliberately differ.
    func testDuplicateFirstWinsButMutationSetIncludesEveryOccurrence() {
        let read = ScriptingCommandInfo(name: "same", summary: "first",
                                       mutates: false, arguments: ["a"])
        let write = ScriptingCommandInfo(name: "same", summary: "second",
                                        mutates: true, arguments: ["b"])
        let onlyWrite = ScriptingCommandInfo(name: "write", summary: "third",
                                            mutates: true, arguments: [])
        let snapshot = MCPCatalogSnapshot(commands: [read, write, onlyWrite])
        XCTAssertEqual(snapshot.commands, [read, write, onlyWrite])
        XCTAssertEqual(snapshot.command(named: "same"), read)
        XCTAssertEqual(snapshot.mutates("same"), false)
        XCTAssertEqual(snapshot.mutates("write"), true)
        XCTAssertNil(snapshot.mutates("unknown"))
        XCTAssertEqual(snapshot.mutatingNames, ["same", "write"])
    }

    // New seam unit oracle; no timing assertion or claim about process-wide wiring.
    func testConstructionCounterIsOneAfterRepeatedLookups() {
        let counter = Counter()
        let command = ScriptingCommandInfo(name: "read", summary: "unchanged",
                                          mutates: false, arguments: [])
        let owner = Owner(commands: [command], counter: counter)
        XCTAssertEqual(counter.value, 0)
        for _ in 0..<17 { // DERIVED: chosen bounded lookup count, not a sample result.
            XCTAssertEqual(owner.snapshot.command(named: "read"), command)
            XCTAssertNil(owner.snapshot.mutates("missing"))
        }
        XCTAssertEqual(counter.value, 1)
    }
}
