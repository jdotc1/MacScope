import Foundation

/// E4 slice B: opt-in ARC folding, non-SSA only.
///
/// A presentation projection in the same envelope as `projectDirectVoidCallResults`: it removes
/// proven ARC runtime calls (retain, release, autorelease, retainAutoreleasedReturnValue and the
/// catalog-backed swift/objc variants) from the rendered function. The MacIR model, call
/// signatures, header `calls` line and all recovered facts stay intact (Q7).
///
/// Soundness rules, each with a typed refusal reason:
/// - the callee identity comes only from `PseudocodeFoldRequest.arcCallSites` (import-table proof);
/// - an unused result removes the call; a used retain-like result is replaced by its argument
///   in every read, and only when every read can be rewritten exactly (otherwise refused);
/// - release forms, `_n` variants and `objc_retain_xN` (N != 0) fold only when the result is unused;
/// - a row that is a branch target is never removed (Q2), and a substitution never spans one;
/// - SSA functions are returned unchanged and disclosed as refused with reason `ssa-mode` (Q1).
/// The transform is deterministic, so the lexical twin projection receives the same rows removed.
extension PseudocodePrinter {
    static func projectARCFold(
        _ function: MacIRFunction, request: PseudocodeFoldRequest,
        isCancelled: () -> Bool = { false }
    ) -> (function: MacIRFunction, report: PseudocodeFoldReport) {
        guard request.kinds.contains(.arc) else { return (function, PseudocodeFoldReport()) }
        func refused(_ reason: String) -> (function: MacIRFunction, report: PseudocodeFoldReport) {
            (function, PseudocodeFoldReport(events: [],
                refused: [FoldRefusal(address: nil, callee: nil, reason: reason)]))
        }
        if function.ssaEnabled { return refused("ssa-mode") }
        if request.arcCallSites.isEmpty { return (function, PseudocodeFoldReport()) }
        if !function.phis.isEmpty { return refused("phis") }
        if function.cfg != nil { return refused("explicit-cfg") }
        let rows = function.instructions
        for row in rows {
            if case .unknown = row.operation { return refused("unknown-operation") }
            // Typed sidecars may carry additional uses; admit only the plain envelope.
            if row != MacIRInstruction(source: row.source, operation: row.operation,
                                       memoryAccess: row.memoryAccess, returnTarget: row.returnTarget) {
                return refused("typed-sidecars")
            }
            if case let .intrinsic(_, name, _) = row.operation, name == "branch_register" {
                return refused("indirect-branch")
            }
        }
        var branchTargets: Set<UInt64> = [function.startAddress]
        for row in rows { branchTargets.formUnion(CFGBuilder.branchTargetAddresses(of: row.operation)) }
        var addressCounts: [UInt64: Int] = [:]
        for row in rows { addressCounts[row.source.address, default: 0] += 1 }

        var working = rows
        var returnValue = function.returnValue
        var deleted: Set<Int> = []
        var events: [Int: FoldedEvent] = [:]
        var refusals: [FoldRefusal] = []
        var uses = ARCFoldUses(rows: working, deleted: deleted, returnValue: returnValue)
        if uses.hasUnknownValue { return refused("unknown-value") }

        for index in working.indices {
            if isCancelled() { return (function, PseudocodeFoldReport()) }
            let instruction = working[index]
            let address = instruction.source.address
            guard let identity = request.arcCallSites[address],
                  instruction.source.mnemonic.lowercased() == "bl",
                  case let .call(frame, result) = instruction.operation else { continue }
            func refuse(_ reason: String) {
                refusals.append(FoldRefusal(address: address, callee: identity.importSymbol, reason: reason))
            }
            guard addressCounts[address] == 1 else { refuse("ambiguous-address"); continue }
            guard branchTargets.contains(address) == false else { refuse("branch-target"); continue }
            guard frame.controlInputs.indirectTarget == nil, frame.controlInputs.pointerAuthenticationModifier == nil,
                  frame.typedIndirectSignature == nil, frame.typedIndirectCalleeType == nil,
                  frame.indirectResultPointer == nil, frame.richArguments == nil else {
                refuse("frame-shape"); continue
            }
            var replacement: MacIRValue?
            if let result {
                guard case let .register(name, version) = result, name == "x0" || name == "w0" else {
                    refuse("result-shape"); continue
                }
                let readers = uses.readers(ofVersion: version)
                if readers.isEmpty {
                    // Unused result: removal is exact for every role and variant.
                } else {
                    switch identity.role {
                    case .release: refuse("result-used-release"); continue
                    case .retain, .autorelease, .retainAutoreleasedReturn: break
                    }
                    guard !identity.isCountVariant else { refuse("result-used-count-variant"); continue }
                    guard identity.objectRegisterIndex == 0 else { refuse("result-used-register-helper"); continue }
                    guard name == "x0", !uses.mentionsW0(version: version) else { refuse("w0-view"); continue }
                    guard let argument = frame.arguments.argument(at: .gpr(index: 0))?.value else {
                        refuse("argument-unavailable"); continue
                    }
                    switch argument {
                    case .register, .argument, .immediate, .symbol: break
                    default: refuse("argument-not-simple"); continue
                    }
                    guard readers.allSatisfy({ $0 == ARCFoldUses.returnSentinel || $0 > index }) else {
                        refuse("use-before-call"); continue
                    }
                    let lastRow = readers.contains(ARCFoldUses.returnSentinel)
                        ? working.count - 1 : (readers.max() ?? index)
                    if lastRow > index {
                        let spanned = (index + 1)...lastRow
                        guard !spanned.contains(where: { branchTargets.contains(working[$0].source.address) }) else {
                            refuse("branch-target-in-range"); continue
                        }
                    }
                    let old = MacIRValue.register(name: "x0", version: version)
                    var rewritten = working
                    var rewrittenReturn = returnValue
                    var failed = false
                    for reader in readers where reader != ARCFoldUses.returnSentinel {
                        guard !deleted.contains(reader),
                              let operation = ARCFoldRewrite.operation(rewritten[reader].operation, old: old, new: argument),
                              rewritten[reader].returnTarget.map({ !ARCFoldRewrite.mentions($0, old) }) ?? true else {
                            failed = true; break
                        }
                        rewritten[reader].operation = operation
                    }
                    if !failed, let current = rewrittenReturn {
                        if let mapped = ARCFoldRewrite.rewrite(current, old: old, new: argument) {
                            rewrittenReturn = mapped
                        } else { failed = true }
                    }
                    guard !failed else { refuse("unrewritable-use"); continue }
                    // The substitution must leave no mention behind.
                    let check = ARCFoldUses(rows: rewritten, deleted: deleted.union([index]), returnValue: rewrittenReturn)
                    guard check.readers(ofVersion: version).isEmpty, !check.mentionsW0(version: version) else {
                        refuse("unrewritable-use"); continue
                    }
                    working = rewritten
                    returnValue = rewrittenReturn
                    replacement = argument
                }
            }
            deleted.insert(index)
            uses = ARCFoldUses(rows: working, deleted: deleted, returnValue: returnValue)
            events[index] = FoldedEvent(address: address, kind: .arc, callee: identity.importSymbol,
                role: identity.role, replacedWith: replacement.map(\.description),
                comment: nonEmpty(instruction.source.comment))
        }
        guard !deleted.isEmpty else {
            return (function, PseudocodeFoldReport(events: [], refused: refusals))
        }

        // Assemble survivors. A removed row's analysis comment moves to the next surviving
        // row when that row exists and is not a branch target; otherwise it stays in the event.
        var survivors: [MacIRInstruction] = []
        var pending: [Int] = []
        for index in working.indices {
            if deleted.contains(index) { pending.append(index); continue }
            var row = working[index]
            let address = row.source.address
            for removed in pending {
                guard var event = events[removed] else { continue }
                event.anchorAddress = address
                if let comment = event.comment, !branchTargets.contains(address) {
                    let note = "[arc-fold 0x\(String(event.address, radix: 16))] \(comment)"
                    row.source.comment = row.source.comment.flatMap(nonEmpty).map { $0 + " " + note } ?? note
                    event.commentPlacedAt = address
                }
                events[removed] = event
            }
            pending.removeAll()
            survivors.append(row)
        }
        var projected = function
        projected.instructions = survivors
        projected.returnValue = returnValue
        let ordered = events.keys.sorted().compactMap { events[$0] }
        return (projected, PseudocodeFoldReport(events: ordered, refused: refusals))
    }

    private static func nonEmpty(_ text: String?) -> String? {
        guard let text, !text.isEmpty else { return nil }
        return text
    }
}

/// Reader index for the x0 carrier: version -> row indices that read it. The function's
/// returned value counts as a read at the end of the function (`returnSentinel`).
struct ARCFoldUses {
    static let returnSentinel = Int.max
    private var readersByVersion: [Int: [Int]] = [:]
    private var w0Versions: Set<Int> = []
    private(set) var hasUnknownValue = false

    init(rows: [MacIRInstruction], deleted: Set<Int>, returnValue: MacIRValue?) {
        for index in rows.indices where !deleted.contains(index) {
            var values = PseudocodePrinter.presentationInputs(rows[index].operation)
            if let target = rows[index].returnTarget { values.append(target) }
            scan(values, row: index)
        }
        if let returnValue { scan([returnValue], row: Self.returnSentinel) }
    }

    private mutating func scan(_ values: [MacIRValue], row: Int) {
        var pending = values
        while let value = pending.popLast() {
            switch value {
            case let .register(name, version):
                if let carrier = MacIRBuilder.integerRegisterView(name), carrier.index == 0 {
                    if readersByVersion[version]?.last != row { readersByVersion[version, default: []].append(row) }
                    if name == "w0" { w0Versions.insert(version) }
                }
            case let .unary(_, inner), let .bitTest(inner, _): pending.append(inner)
            case let .binaryExpression(_, left, right): pending += [left, right]
            case let .signedBitfield(field): pending += [field.source, field.origin.definition]
            case let .abiComposite(_, fragments): pending += fragments
            case let .unknown(name):
                // Builder markers ("unavailable_x0", unresolved return contract) name a value
                // the printer could not bind. They reference no x0 version, so a rewrite
                // cannot miss a read through them. Any other unknown value stays a refusal.
                if !Self.isUnboundMarker(name) { hasUnknownValue = true }
            case .argument, .argumentFragment, .immediate, .stackSlot, .symbol, .temporary: break
            }
        }
    }

    private static func isUnboundMarker(_ name: String) -> Bool {
        name.hasPrefix("unavailable_") || name.hasPrefix("unbound_") || name.hasPrefix("cancelled_")
            || name == MacIRIndirectTargetResolution.unresolvedReturnContractMarker
    }

    func readers(ofVersion version: Int) -> [Int] { readersByVersion[version] ?? [] }
    func mentionsW0(version: Int) -> Bool { w0Versions.contains(version) }
}

/// Exact read-side rewriting. Every function returns nil when a value cannot be rewritten
/// without guessing, which makes the caller refuse the event.
enum ARCFoldRewrite {
    static func mentions(_ value: MacIRValue, _ old: MacIRValue) -> Bool {
        if value == old { return true }
        switch value {
        case let .unary(_, inner), let .bitTest(inner, _): return mentions(inner, old)
        case let .binaryExpression(_, left, right): return mentions(left, old) || mentions(right, old)
        case let .signedBitfield(field): return mentions(field.source, old) || mentions(field.origin.definition, old)
        case let .abiComposite(_, fragments): return fragments.contains { mentions($0, old) }
        default: return false
        }
    }

    static func rewrite(_ input: MacIRValue, old: MacIRValue, new: MacIRValue) -> MacIRValue? {
        if input == old { return new }
        switch input {
        case let .unary(op, inner):
            return rewrite(inner, old: old, new: new).map { .unary(op: op, value: $0) }
        case let .bitTest(inner, bit):
            return rewrite(inner, old: old, new: new).map { .bitTest(value: $0, bit: bit) }
        case let .binaryExpression(op, left, right):
            guard let l = rewrite(left, old: old, new: new), let r = rewrite(right, old: old, new: new) else { return nil }
            return .binaryExpression(op: op, left: l, right: r)
        case let .abiComposite(type, fragments):
            var mapped: [MacIRValue] = []
            for fragment in fragments {
                guard let item = rewrite(fragment, old: old, new: new) else { return nil }
                mapped.append(item)
            }
            return .abiComposite(type: type, fragments: mapped)
        case .signedBitfield:
            return mentions(input, old) ? nil : input
        default:
            return input
        }
    }

    static func operation(_ operation: MacIROperation, old: MacIRValue, new: MacIRValue) -> MacIROperation? {
        func map(_ input: MacIRValue) -> MacIRValue? { rewrite(input, old: old, new: new) }
        switch operation {
        case let .assign(destination, source):
            return map(source).map { .assign(destination: destination, source: $0) }
        case let .binary(destination, op, left, right):
            guard let l = map(left), let r = map(right) else { return nil }
            return .binary(destination: destination, op: op, left: l, right: r)
        case let .load(destination, address):
            return map(address).map { .load(destination: destination, address: $0) }
        case let .store(source, address):
            guard let s = map(source), let a = map(address) else { return nil }
            return .store(source: s, address: a)
        case let .loadWriteback(destination, baseDestination, baseSource, delta, preIndex):
            return map(baseSource).map { .loadWriteback(destination: destination, baseDestination: baseDestination,
                baseSource: $0, delta: delta, preIndex: preIndex) }
        case let .storeWriteback(source, baseDestination, baseSource, delta, preIndex):
            guard let s = map(source), let b = map(baseSource) else { return nil }
            return .storeWriteback(source: s, baseDestination: baseDestination, baseSource: b,
                                   delta: delta, preIndex: preIndex)
        case let .stackSlotRead(destination, slot, stored):
            guard let s = map(slot), let v = map(stored) else { return nil }
            return .stackSlotRead(destination: destination, slot: s, value: v)
        case let .stackSlotPairRead(firstDestination, firstSlot, firstValue, secondDestination, secondSlot, secondValue):
            guard let a = map(firstSlot), let b = map(firstValue), let c = map(secondSlot), let d = map(secondValue) else { return nil }
            return .stackSlotPairRead(firstDestination: firstDestination, firstSlot: a, firstValue: b,
                secondDestination: secondDestination, secondSlot: c, secondValue: d)
        case let .call(frame, result):
            guard let rebuilt = frame.mappingReadValues(map) else { return nil }
            return .call(frame: rebuilt, result: result)
        case let .conditionalBranch(condition, left, right, target):
            guard let l = map(left), let r = map(right), let t = map(target) else { return nil }
            return .conditionalBranch(condition: condition, left: l, right: r, target: t)
        case let .select(destination, condition, left, right, yes, no):
            guard let l = map(left), let r = map(right), let y = map(yes), let n = map(no) else { return nil }
            return .select(destination: destination, condition: condition, left: l, right: r, trueValue: y, falseValue: n)
        case let .compareToBool(destination, condition, left, right):
            guard let l = map(left), let r = map(right) else { return nil }
            return .compareToBool(destination: destination, condition: condition, left: l, right: r)
        case let .returnValue(returned):
            guard let returned else { return operation }
            return map(returned).map { .returnValue($0) }
        case let .intrinsic(destination, name, arguments):
            var mapped: [MacIRValue] = []
            for argument in arguments {
                guard let item = map(argument) else { return nil }
                mapped.append(item)
            }
            return .intrinsic(destination: destination, name: name, arguments: mapped)
        case let .switchDispatch(index, cases, defaultTarget):
            guard let i = map(index) else { return nil }
            return .switchDispatch(index: i, cases: cases, defaultTarget: defaultTarget)
        case .unknown:
            return nil
        }
    }
}
