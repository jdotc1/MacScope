import Foundation

// Fixed-width advances and remembered-state semantics follow AIRS dwarf_cfi.py
// (AIRS 2639c14ae), whose evaluator follows gimli's. No source is copied from
// either; this evaluator runs over the existing structured DWARF reader.

/// The Apple ordinary-ARM64 recovery subset. Structured decoding is deliberately
/// separate from evaluation: a decoded operation need not have modeled effects.
struct UnwindAuditCFI {
    struct Row {
        var pc: UInt64
        var register: Int
        var offset: Int64
        var rules: [Int: Rule]

        func recover(_ state: UnwindAuditMachine) throws -> [String: UnwindAuditValue] {
            let base = register == 31 ? state.sp : state.registers[register]
            let cfa = try base.add(offset)
            var result: [String: UnwindAuditValue] = ["SP": cfa]
            for number in 19...30 {
                switch rules[number] ?? .same {
                case .same: result["x\(number)"] = state.registers[number]
                case .undefined: result["x\(number)"] = .unknown("DW_CFA_undefined")
                case .offset(let displacement):
                    let location = try cfa.add(displacement)
                    guard case .stack(let slot) = location,
                          case .stack(let stack) = state.sp,
                          slot % 8 == 0, slot >= stack, slot <= -8 else {
                        result["x\(number)"] = .unknown("CFI read is outside the modeled allocated frame")
                        continue
                    }
                    result["x\(number)"] = state.memory[slot] ?? .unknown("CFI slot has no modeled store")
                }
            }
            return result
        }
    }

    enum Rule { case same, undefined, offset(Int64) }
    struct FDE {
        var offset: Int
        var cieOffset: Int
        var start: UInt64
        var end: UInt64
        var rows: [Row]
        var refusal: String? = nil

        func row(at pc: UInt64) throws -> Row {
            if let refusal { throw UnwindAuditCFI.failure(refusal) }
            guard start <= pc, pc < end,
                  let row = rows.last(where: { $0.pc <= pc }) else {
                throw UnwindAuditCFI.failure("Requested PC is outside the exact FDE")
            }
            return row
        }
    }

    private struct LocalProgramRefusal: Error {
        let message: String
    }

    let fdes: [Int: FDE]
    let overlapping: Set<Int>

    init(table: DWARFStructuredCallFrameTable, enableCFIControls: Bool = false,
         localFDERefusal: Bool = false) throws {
        guard table.cies.count + table.fdes.count <= 4096 else {
            throw Self.failure("CFI record budget exhausted")
        }
        var operations = 0
        var rowCount = 0
        var initials: [Int: Row] = [:]
        for cie in table.cies {
            guard cie.version == 1, cie.augmentation == "zR",
                  cie.augmentationData == [0x10], cie.codeAlignmentFactor == 1,
                  cie.dataAlignmentFactor == -8, cie.returnAddressRegister == 30,
                  cie.fdePointerEncoding == 0x10,
                  initials[cie.sectionOffset] == nil else {
                throw Self.failure("Only CIEv1 zR, code1/data-8, RA30, pcrel-pointer64 is modeled")
            }
            let rows = try Self.evaluate(cie.initialProgram, start: 0, end: 0,
                                         initial: nil, enableCFIControls: enableCFIControls,
                                         localFDERefusal: localFDERefusal,
                                         operations: &operations, rowCount: &rowCount)
            initials[cie.sectionOffset] = rows.last
        }
        var decoded: [Int: FDE] = [:]
        for fde in table.fdes {
            let (end, overflow) = fde.initialLocation.addingReportingOverflow(fde.rangeSize)
            guard let initial = initials[fde.cieSectionOffset],
                  fde.cieSectionOffset < fde.sectionOffset,
                  fde.augmentationData.isEmpty, !overflow, fde.rangeSize > 0,
                  fde.initialLocation % 4 == 0, fde.rangeSize % 4 == 0,
                  decoded[fde.sectionOffset] == nil else {
                throw Self.failure("Malformed, unsupported or duplicate FDE")
            }
            do {
                let rows = try Self.evaluate(fde.program, start: fde.initialLocation, end: end,
                                             initial: initial, enableCFIControls: enableCFIControls,
                                             localFDERefusal: localFDERefusal,
                                             operations: &operations, rowCount: &rowCount)
                decoded[fde.sectionOffset] = FDE(offset: fde.sectionOffset, cieOffset: fde.cieSectionOffset,
                                                start: fde.initialLocation, end: end, rows: rows)
            } catch let refusal as LocalProgramRefusal {
                decoded[fde.sectionOffset] = FDE(offset: fde.sectionOffset, cieOffset: fde.cieSectionOffset,
                                                start: fde.initialLocation, end: end, rows: [],
                                                refusal: refusal.message)
            }
        }
        var overlaps = Set<Int>()
        var furthest: FDE?
        for fde in decoded.values.sorted(by: { ($0.start, $0.end, $0.offset) < ($1.start, $1.end, $1.offset) }) {
            if let previous = furthest, fde.start < previous.end {
                overlaps.insert(previous.offset)
                overlaps.insert(fde.offset)
            }
            if let previous = furthest {
                if fde.end > previous.end { furthest = fde }
            } else { furthest = fde }
        }
        fdes = decoded
        overlapping = overlaps
    }

    func select(offset: UInt32, start: UInt64, end: UInt64) throws -> FDE {
        guard let fde = fdes[Int(offset)], !overlapping.contains(Int(offset)),
              fde.start == start, fde.end == end else {
            throw Self.failure("Exact nonoverlapping FDE record and independent function extent are required")
        }
        if let refusal = fde.refusal { throw Self.failure(refusal) }
        return fde
    }

    private static func evaluate(_ program: DWARFStructuredCFAProgram, start: UInt64,
                                 end: UInt64, initial: Row?, enableCFIControls: Bool,
                                 localFDERefusal: Bool,
                                 operations: inout Int,
                                 rowCount: inout Int) throws -> [Row] {
        guard program.status == .complete else { throw failure("CFI program is unsupported or malformed") }
        var pc = start
        var cfa: (Int, Int64)? = initial.map { ($0.register, $0.offset) }
        var rules = initial?.rules ?? Dictionary(uniqueKeysWithValues: (19...30).map { ($0, Rule.same) })
        var rows: [Row] = []
        // Swift tuples, dictionaries and Rule values snapshot by value. The PC is
        // intentionally absent: restoring recovery state never rewinds a row.
        // This stack belongs to this one program and never changes CIE initials.
        var savedStates: [(cfa: (Int, Int64), rules: [Int: Rule])] = []
        func save() throws {
            guard let cfa else { throw failure("No explicit supported CFA definition is available") }
            let row = Row(pc: pc, register: cfa.0, offset: cfa.1, rules: rules)
            if rows.last?.pc == pc { rows[rows.count - 1] = row }
            else {
                rowCount += 1
                guard rowCount <= 50_000 else { throw failure("CFI row budget exhausted") }
                rows.append(row)
            }
        }
        func advance(_ delta: UInt64) throws {
            // The admitted CIE fixes code_alignment_factor at one.
            let (next, overflow) = pc.addingReportingOverflow(delta)
            guard initial != nil, delta > 0, !overflow, next <= end, next % 4 == 0 else {
                throw failure("CFI location advance is outside the supported aligned FDE")
            }
            try save()
            pc = next
        }
        for (index, operation) in program.operations.enumerated() {
            operations += 1
            guard operations <= 200_000 else { throw failure("CFI instruction budget exhausted") }
            func operand(_ index: Int) throws -> UInt64 {
                guard operation.operands.indices.contains(index),
                      case .unsigned(let value) = operation.operands[index] else {
                    throw failure("CFI operand is absent or unsupported")
                }
                return value
            }
            func register(_ index: Int) throws -> Int {
                let value = try operand(index)
                guard (19...30).contains(value) else { throw failure("Register rule is outside x19–x30") }
                return Int(value)
            }
            switch operation.opcode & 0xc0 {
            case 0x40:
                try advance(operand(0))
            case 0x80:
                let number = try register(0), scaled = try operand(1)
                guard scaled <= UInt64(Int64.max) / 8 + 1 else { throw failure("CFI stack offset overflows") }
                let displacement = scaled == UInt64(Int64.max) / 8 + 1 ? Int64.min : -Int64(scaled) * 8
                rules[number] = .offset(displacement)
            case 0xc0:
                guard let initial else { throw failure("Restore has no CIE initial rule") }
                rules[try register(0)] = initial.rules[try register(0)]
            default:
                switch operation.opcode {
                case 0: break
                case 2, 3, 4:
                    guard enableCFIControls, operation.operands.count == 1 else {
                        throw failure("Fixed-width CFI advances require the control model and one unsigned operand")
                    }
                    let delta = try operand(0)
                    let maximum: UInt64 = operation.opcode == 2 ? UInt64(UInt8.max)
                        : (operation.opcode == 3 ? UInt64(UInt16.max) : UInt64(UInt32.max))
                    guard delta <= maximum else { throw failure("CFI advance operand exceeds its unsigned width") }
                    try advance(delta)
                case 7: rules[try register(0)] = .undefined
                case 8: rules[try register(0)] = .same
                case 10, 11:
                    if !enableCFIControls, initial != nil, localFDERefusal {
                        let remaining = program.operations.count - (index + 1)
                        operations += remaining
                        guard operations <= 200_000 else { throw failure("CFI instruction budget exhausted") }
                        rowCount += remaining + 1
                        guard rowCount <= 50_000 else { throw failure("CFI row budget exhausted") }
                        throw LocalProgramRefusal(message: "CFI row-state opcode \(operation.opcode) refuses the entire FDE")
                    }
                    guard enableCFIControls, initial != nil, let currentCFA = cfa,
                          operation.operands.isEmpty else {
                        throw failure("Remembered CFI state requires an FDE, a supported CFA and no operands")
                    }
                    if operation.opcode == 10 {
                        guard savedStates.count < 64 else { throw failure("CFI state depth budget exhausted") }
                        savedStates.append((currentCFA, rules))
                    } else {
                        guard let saved = savedStates.popLast() else {
                            throw failure("CFI restore_state lacks a remembered FDE state")
                        }
                        cfa = saved.cfa
                        rules = saved.rules
                    }
                case 12:
                    let number = try operand(0), offset = try operand(1)
                    guard [29, 31].contains(number), offset <= UInt64(Int64.max) else {
                        throw failure("CFA requires x29/SP and a bounded unsigned offset")
                    }
                    cfa = (Int(number), Int64(offset))
                case 13:
                    let number = try operand(0)
                    guard let old = cfa, [29, 31].contains(number) else {
                        throw failure("CFA register update lacks a supported prior definition")
                    }
                    cfa = (Int(number), old.1)
                case 14:
                    let offset = try operand(0)
                    guard let old = cfa, offset <= UInt64(Int64.max) else {
                        throw failure("CFA offset update lacks a supported prior definition")
                    }
                    cfa = (old.0, Int64(offset))
                default: throw failure("CFI opcode 0x\(String(operation.opcode, radix: 16)) is outside the evaluation subset")
                }
            }
        }
        // An unconsumed snapshot is valid; it has no effect outside this FDE.
        // Any late error above throws before the table can publish any rows.
        try save()
        return rows
    }

    private static func failure(_ message: String) -> UnwindAuditModelError {
        UnwindAuditModelError(code: "dwarf_cfi_unsupported", message: message, address: nil)
    }
}
