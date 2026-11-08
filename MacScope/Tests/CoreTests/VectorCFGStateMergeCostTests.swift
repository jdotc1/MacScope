import Darwin
import Foundation
import XCTest
@testable import MacScope

final class VectorCFGStateMergeCostTests: XCTestCase {
    private func row(_ address: UInt64, word: UInt32,
                     mnemonic: String, operands: String) -> InstructionRow {
        let bytes = (0..<4).map {
            String(format: "%02x", (word >> ($0 * 8)) & 255)
        }.joined(separator: " ")
        return .init(address: address, bytes: bytes, mnemonic: mnemonic,
                     operands: operands, hasBreakpoint: false, comment: nil)
    }

    private func addv(_ address: UInt64) -> InstructionRow {
        row(address, word: 0x4eb1_b820, mnemonic: "addv", operands: "s0, v1.4s")
    }

    private func decrement(_ register: Int, at address: UInt64) -> InstructionRow {
        let word = UInt32(0xd100_0000) | (UInt32(1) << 10)
            | (UInt32(register) << 5) | UInt32(register)
        return row(address, word: word, mnemonic: "sub",
                   operands: "x\(register), x\(register), #1")
    }

    private func seed(_ register: Int, at address: UInt64) -> InstructionRow {
        let word = UInt32(0xd280_0040) | UInt32(register)
        return row(address, word: word, mnemonic: "mov",
                   operands: "x\(register), #2")
    }

    private func cbnz(_ register: Int, at address: UInt64,
                      target: UInt64) -> InstructionRow {
        let delta = Int64(target) - Int64(address)
        precondition(delta.isMultiple(of: 4))
        let imm19 = UInt32(truncatingIfNeeded: delta / 4) & 0x7ffff
        let word = UInt32(0xb500_0000) | (imm19 << 5) | UInt32(register)
        return row(address, word: word, mnemonic: "cbnz",
                   operands: "x\(register), 0x\(String(target, radix: 16))")
    }

    private func ret(_ address: UInt64) -> InstructionRow {
        row(address, word: 0xd65f_03c0, mnemonic: "ret", operands: "")
    }

    private func sequentialLoops(_ count: Int, start: UInt64) -> [InstructionRow] {
        var rows = [addv(start)]
        var address = start + 4
        for ordinal in 0..<count {
            let register = ordinal % 30 + 1
            rows.append(seed(register, at: address))
            address += 4
            let header = address
            rows.append(decrement(register, at: address))
            address += 4
            rows.append(cbnz(register, at: address, target: header))
            address += 4
        }
        rows.append(ret(address))
        return rows
    }

    private func region(_ name: String, _ rows: [InstructionRow]) -> MacIRFunction? {
        MacIRBuilder().buildGeneralVectorRegion(
            name: name, startAddress: rows.first?.address, rows: rows,
            initialState: BuilderState(parameters: []), hasExternalFacts: false,
            isVariadic: false)
    }

    func testThreeAndFourSequentialLoopsAdmit() {
        for count in [3, 4] {
            XCTAssertNotNil(region("sequential_\(count)",
                                   sequentialLoops(count, start: 0x10_000)))
        }
    }

    func testTwoNestedLoopsAndSiblingLoopAdmit() {
        let start: UInt64 = 0x20_000
        let outer = start + 8
        let inner = start + 16
        let sibling = start + 32
        let rows = [
            addv(start),
            seed(1, at: start + 4),
            decrement(1, at: outer),
            seed(2, at: start + 12),
            decrement(2, at: inner),
            cbnz(2, at: start + 20, target: inner),
            cbnz(1, at: start + 24, target: outer),
            seed(3, at: start + 28),
            decrement(3, at: sibling),
            cbnz(3, at: start + 36, target: sibling),
            ret(start + 40),
        ]
        XCTAssertNotNil(region("nested_and_sibling", rows))
    }

    func testStateMergeCellBoundRefusesTwoHundredFiftyEightInputs() {
        // 129 loop headers x two predecessor snapshots x 64 state cells =
        // 16,512 cells, which exceeds the 16,384-cell admission budget.
        XCTAssertNil(region("merge_cell_limit", sequentialLoops(129, start: 0x30_000)))
    }

    func testOneAndTwoBackedgeWitnessesKeepByteIdenticalRouting() throws {
        let options = DecompilerOptions(
            structureControlFlow: true, deadCodeElimination: false,
            nopElision: false, functionSizeGate: 1_024)
        for count in [1, 2] {
            let rows = sequentialLoops(count, start: 0x40_000 + UInt64(count * 0x100))
            let routed = MacIRBuilder().buildFunction(
                name: "legacy_\(count)", startAddress: rows[0].address,
                instructions: rows)
            let direct = try XCTUnwrap(MacIRBuilder().buildGeneralVectorRegion(
                name: "legacy_\(count)", startAddress: rows[0].address, rows: rows,
                initialState: BuilderState(parameters: routed.parameters),
                hasExternalFacts: false, isVariadic: routed.isVariadic))
            let directBytes = Data(PseudocodePrinter(options: options)
                .print(function: direct).text.utf8)
            let routedBytes = Data(PseudocodePrinter(options: options)
                .print(function: routed).text.utf8)
            XCTAssertEqual(routedBytes, directBytes)
        }
    }

    private final class StackProbe860: @unchecked Sendable {
        private let lock = NSLock()
        private var first: (name: String?, bytes: Int)?

        func observe() {
            let sample = (Thread.current.name, pthread_get_stacksize_np(pthread_self()))
            lock.lock()
            if first == nil { first = sample }
            lock.unlock()
        }

        func sample() -> (name: String?, bytes: Int)? {
            lock.lock()
            defer { lock.unlock() }
            return first
        }
    }

    // Fails before the fix by thread-placement predicate, never by a stack overflow.
    // No matching function exists, so parameterBindingAuditRead exits before lifting.
    @MainActor
    func test860ParameterAuditPreflightUsesRenderingStack() async throws {
        let probe = StackProbe860()
        let snapshot = WorkspaceSnapshot(
            binaries: [], functions: [], instructions: [], xrefs: [], hexBytes: Data())
        let store = WorkspaceStore(workspaceName: "stack-placement-probe", snapshot: snapshot,
                                   engine: AnalysisEngine(), autosaveScheduler: nil)
        let api = WorkspaceScriptingAPI(store: store, snapshotReadCheckpoint: { probe.observe() })
        do {
            _ = try await api.executeAsync("parameter-binding-audit", arguments: .object([
                "function": .string("stack_probe_only")
            ]))
            XCTFail("fixture must stop before any function lift")
        } catch let error as ScriptingError {
            guard case .invalidArgument(let detail) = error else {
                return XCTFail("unexpected preflight error: \(error)")
            }
            XCTAssertTrue(detail == "no analyzed image exists in the focused slot"
                || detail == "no function named 'stack_probe_only'")
        }
        let observed = try XCTUnwrap(probe.sample())
        XCTAssertEqual(observed.name, "Pseudocode rendering")
        XCTAssertGreaterThanOrEqual(observed.bytes, 16 * 1_024 * 1_024)
    }

    private enum StackProbeError860: Error { case unexpectedlySmallRenderingStack }

    // Positive control (passes before): one-row leaf and two-row leaf-plus-return.
    // All lifting occurs only after checking the existing 16 MiB rendering stack.
    func test860SmallRegionRoutingRemainsIdenticalOnRenderingStack() async throws {
        for count in [1, 2] {
            let printed = try await PseudocodeRenderingThread.run {
                guard pthread_get_stacksize_np(pthread_self()) >= 16 * 1_024 * 1_024 else {
                    throw StackProbeError860.unexpectedlySmallRenderingStack
                }
                var rows = [InstructionRow(
                    address: 0x1000, bytes: "20 b8 b1 4e", mnemonic: "addv",
                    operands: "s0, v1.4s", hasBreakpoint: false, comment: nil)]
                if count == 2 {
                    rows.append(InstructionRow(
                        address: 0x1004, bytes: "c0 03 5f d6", mnemonic: "ret",
                        operands: "", hasBreakpoint: false, comment: nil))
                }
                let builder = MacIRBuilder(explicitCFGEnabled: false, ssaEnabled: false)
                let routed = builder.buildFunction(
                    name: "small_region", startAddress: 0x1000, instructions: rows)
                let direct = try XCTUnwrap(builder.buildGeneralVectorRegion(
                    name: "small_region", startAddress: 0x1000, rows: rows,
                    initialState: BuilderState(parameters: routed.parameters),
                    hasExternalFacts: false, isVariadic: routed.isVariadic))
                let options = DecompilerOptions(
                    structureControlFlow: true, deadCodeElimination: false,
                    nopElision: false, functionSizeGate: 1_024)
                return (
                    Data(PseudocodePrinter(options: options).print(function: routed).text.utf8),
                    Data(PseudocodePrinter(options: options).print(function: direct).text.utf8))
            }
            XCTAssertEqual(printed.0, printed.1)
        }
    }
}
