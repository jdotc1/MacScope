import Foundation

/// One renamed call target whose rendered spelling is not simply the stored name, or whose rename
/// loses a catalog special case. Both spellings are disclosed (E2, OQ-3 and OQ-7).
struct CallTargetNameDisclosure: Equatable, Sendable {
    /// Image-local address of the call target (the stub or import symbol).
    var address: UInt64
    /// The name the user stored.
    var stored: String
    /// The spelling the pseudocode call site uses.
    var rendered: String
    /// Non-empty subset of `CallTargetRenderName.Reason`, in a fixed order.
    var reasons: [String]
}

/// What `pseudocodeTarget` resolved for one function, plus the E2 carry-through data.
struct PseudocodeTargetResolution: Sendable {
    var function: FunctionSummary
    var instructions: [InstructionRow]
    var callTargetNames: [CallTargetNameDisclosure]
    /// Authored comments with an address inside `function`; empty unless the caller asked for them.
    var userComments: [UInt64: String]
}

enum CallTargetRenderName {
    enum Reason {
        static let escaped = "escaped"
        static let collision = "collision"
        static let objcSpecialCaseLost = "objcSpecialCaseLost"
    }

    static let maximumUTF8Bytes = 128

    /// OQ-3. A stored name that is already a valid C identifier renders verbatim. Otherwise each
    /// byte that is not an ASCII letter, digit or underscore becomes `_xHH` (uppercase hex of the
    /// UTF-8 byte); a leading digit gets a `_` prefix; a result over 128 bytes keeps its first 119
    /// bytes plus `_` and the 8-hex FNV-1a digest of the stored UTF-8, so truncation stays
    /// unambiguous. Deterministic: the result depends only on `stored`.
    static func rendered(_ stored: String) -> String {
        if PseudocodePrinter.isCIdentifier(stored) { return stored }
        var out = [UInt8]()
        for byte in stored.utf8 {
            let isWord = byte == 0x5F || (0x30...0x39).contains(byte)
                || (0x41...0x5A).contains(byte) || (0x61...0x7A).contains(byte)
            if isWord {
                out.append(byte)
            } else {
                out.append(0x5F); out.append(0x78)
                out.append(Self.hexDigit(byte >> 4)); out.append(Self.hexDigit(byte & 0xF))
            }
        }
        if let first = out.first, (0x30...0x39).contains(first) { out.insert(0x5F, at: 0) }
        if out.isEmpty { out = Array("_".utf8) }
        if out.count > maximumUTF8Bytes {
            let digest = fnv1a32(Array(stored.utf8))
            let suffix = Array(("_" + String(format: "%08x", digest)).utf8)
            out = Array(out.prefix(maximumUTF8Bytes - suffix.count)) + suffix
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// `base` + `_n`, keeping the 128-byte bound (the base is ASCII after `rendered`).
    static func suffixed(_ base: String, _ n: Int) -> String {
        let suffix = "_\(n)"
        let room = maximumUTF8Bytes - suffix.utf8.count
        return String(base.prefix(room)) + suffix
    }

    static func canonicalObjCMessageSend(_ name: String) -> Bool {
        let symbol = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return (symbol.hasPrefix("_") ? String(symbol.dropFirst()) : symbol) == "objc_msgSend"
    }

    /// Spellings a renamed stub may not take inside one function: register names the lifter emits
    /// as values, and the C names the printer reserves around them.
    static func isReservedSpelling(_ name: String) -> Bool {
        if ["sp", "wsp", "xzr", "wzr", "lr", "fp", "pc"].contains(name) { return true }
        guard let letter = name.first, "xwvqdshb".contains(letter) else { return false }
        let digits = name.dropFirst()
        guard !digits.isEmpty, digits.count <= 2, digits.allSatisfy(\.isNumber),
              let number = Int(digits) else { return false }
        return number <= 31
    }

    private static func hexDigit(_ value: UInt8) -> UInt8 {
        value < 10 ? 0x30 + value : 0x41 + value - 10
    }

    private static func fnv1a32(_ bytes: [UInt8]) -> UInt32 {
        var hash: UInt32 = 2_166_136_261
        for byte in bytes { hash = (hash ^ UInt32(byte)) &* 16_777_619 }
        return hash
    }
}

extension WorkspaceSnapshot {
    /// `function`'s half-open range (a zero-width function owns only its start), matching
    /// `enclosingFunction` and the decompile size check.
    static func function(_ function: FunctionSummary, contains address: UInt64) -> Bool {
        function.endAddress > function.startAddress
            ? address >= function.startAddress && address < function.endAddress
            : address == function.startAddress
    }

    /// The authored (non-blank) comments of `slot` whose address lies inside `function`. Only this
    /// function's own range is enumerated (OQ-8). `checkpoint` runs every 4,096 visited overrides.
    func userComments(
        in function: FunctionSummary,
        slot: ImageSlot,
        checkpoint: () throws -> Void = {}
    ) rethrows -> [UInt64: String] {
        var result: [UInt64: String] = [:]
        var visited = 0
        for (key, override) in addressOverrides {
            if visited > 0, visited.isMultiple(of: 4_096) { try checkpoint() }
            visited += 1
            guard key.slot == slot,
                  let comment = override.customComment,
                  !comment.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
                  Self.function(function, contains: key.address) else { continue }
            result[key.address] = comment
        }
        return result
    }

    /// Call-target display names for one function (E2). Starts from `branchTargetNames`, then, for
    /// every target that is NOT a function start but carries a user name, applies the OQ-3 spelling
    /// and de-duplicates inside the function: names are claimed in ascending target address, the
    /// lowest address keeps the plain spelling and a later one takes `_2`, `_3`, ... A spelling is
    /// taken if another call target of this function (renamed or not), a lifter register name or one
    /// of `reserving` already uses it. A rename that makes the original `objc_msgSend` identity
    /// unreachable for the lifter is disclosed, never silent (OQ-7).
    func resolvedCallTargetNames(
        in slot: ImageSlot,
        targets: Set<UInt64>,
        reserving: Set<String> = []
    ) -> (names: [UInt64: String], disclosures: [CallTargetNameDisclosure]) {
        var names = branchTargetNames(in: slot, restrictedTo: targets)
        let named = targets.filter {
            !(addressOverrides[key($0, in: slot)]?.customName?.isEmpty ?? true)
        }
        guard !named.isEmpty, let analysis = analysis(in: slot) else { return (names, []) }
        let functionStarts = Set(analysis.functions.map(\.startAddress))
        let renamed = named.subtracting(functionStarts).sorted()
        guard !renamed.isEmpty else { return (names, []) }
        let renamedSet = Set(renamed)
        var original: [UInt64: String] = [:]
        for symbol in analysis.symbols {
            if let address = symbol.address, renamedSet.contains(address), original[address] == nil {
                original[address] = symbol.name
            }
        }
        var occupied = reserving
        for (address, name) in names where !renamedSet.contains(address) { occupied.insert(name) }
        var disclosures: [CallTargetNameDisclosure] = []
        for address in renamed {
            guard let stored = addressOverrides[key(address, in: slot)]?.customName else { continue }
            var rendered = CallTargetRenderName.rendered(stored)
            var reasons: [String] = []
            if rendered != stored { reasons.append(CallTargetRenderName.Reason.escaped) }
            if occupied.contains(rendered) || CallTargetRenderName.isReservedSpelling(rendered) {
                var n = 2
                var candidate = CallTargetRenderName.suffixed(rendered, n)
                while occupied.contains(candidate) {
                    n += 1
                    candidate = CallTargetRenderName.suffixed(rendered, n)
                }
                rendered = candidate
                reasons.append(CallTargetRenderName.Reason.collision)
            }
            occupied.insert(rendered)
            names[address] = rendered
            if let source = original[address], CallTargetRenderName.canonicalObjCMessageSend(source),
               !CallTargetRenderName.canonicalObjCMessageSend(rendered) {
                reasons.append(CallTargetRenderName.Reason.objcSpecialCaseLost)
            }
            if !reasons.isEmpty {
                disclosures.append(CallTargetNameDisclosure(
                    address: address, stored: stored, rendered: rendered, reasons: reasons))
            }
        }
        return (names, disclosures)
    }
}
