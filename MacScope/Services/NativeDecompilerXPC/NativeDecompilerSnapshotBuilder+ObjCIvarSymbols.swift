import Foundation

/// E1 (item 1331): pure planning of exact `_OBJC_IVAR_$_<Class>.<ivar>` data symbols from the
/// selected image's ObjC metadata. The planner reads only supplied values: it performs no read,
/// scan or layout verification, and it never removes or renames a real symbol. Every planned
/// record carries the one provenance marker; there is no unmarked synthetic fallback.
extension NativeDecompilerSnapshotBuilder {
    /// The single provenance value carried by a projected ObjC ivar offset-global record.
    static let objCIvarProvenanceMarker = "objc-ivar-metadata"

    /// Shipped builds keep the projection disabled: marked records would be rejected by the
    /// pin-era strict request readers (decision D4 is not ruled). The validation call site gates
    /// the planner inputs on this value; with empty inputs the symbol projection follows the old path.
    static let objCIvarMetadataProjectionEnabled = false

    /// Width of the offset variable (an `int32`).
    static let objCIvarOffsetVariableWidth: UInt64 = 4

    enum ObjCIvarPlanState: Equatable, Sendable {
        case resolved
        case abstain
        case unchanged
    }

    struct ObjCIvarPlanDecision: Equatable, Sendable {
        let imageID: String
        let address: UInt64
        let name: String
        let className: String
        let classAddress: UInt64?
        let ivarName: String
        let state: ObjCIvarPlanState
        /// RESOLVED: the marker token; ABSTAIN: the selected reason; UNCHANGED: empty.
        /// Harness-only; never placed on the wire, in names or in persisted analysis.
        let diagnostics: [String]
    }

    struct ObjCIvarSymbolPlan: Equatable, Sendable {
        /// Marked data records, one per surviving claim, in deterministic order.
        let candidates: [NativeDecompilerWireSymbolRecord]
        let decisions: [ObjCIvarPlanDecision]
    }

    static let objCIvarReasonMultipleClaimants = "metadata-address-multiple-claimants"
    static let objCIvarReasonNameMultipleAddresses = "metadata-name-multiple-addresses"
    static let objCIvarReasonRealAddressNameMismatch = "real-address-name-mismatch"
    static let objCIvarReasonRealNameOtherAddress = "real-name-other-address"

    /// One metadata claim. Identity is the explicit byte tuple, never `ObjCIvar` equality.
    private struct ObjCIvarClaim: Hashable {
        let classNameBytes: [UInt8]
        let classAddress: UInt64?
        let ivarNameBytes: [UInt8]
        let target: UInt64
        let nameBytes: [UInt8]
        let className: String
        let ivarName: String

        static func == (lhs: ObjCIvarClaim, rhs: ObjCIvarClaim) -> Bool {
            lhs.classNameBytes == rhs.classNameBytes && lhs.classAddress == rhs.classAddress
                && lhs.ivarNameBytes == rhs.ivarNameBytes && lhs.target == rhs.target
        }

        func hash(into hasher: inout Hasher) {
            hasher.combine(classNameBytes)
            hasher.combine(classAddress)
            hasher.combine(ivarNameBytes)
            hasher.combine(target)
        }
    }

    private static func bytesLess(_ lhs: [UInt8], _ rhs: [UInt8]) -> Bool {
        lhs.lexicographicallyPrecedes(rhs)
    }

    private static func claimLess(_ lhs: ObjCIvarClaim, _ rhs: ObjCIvarClaim) -> Bool {
        if lhs.target != rhs.target { return lhs.target < rhs.target }
        if lhs.nameBytes != rhs.nameBytes { return bytesLess(lhs.nameBytes, rhs.nameBytes) }
        if lhs.classNameBytes != rhs.classNameBytes { return bytesLess(lhs.classNameBytes, rhs.classNameBytes) }
        if lhs.classAddress != rhs.classAddress {
            switch (lhs.classAddress, rhs.classAddress) {
            case (nil, _?): return true
            case (_?, nil): return false
            case let (l?, r?): return l < r
            default: return false
            }
        }
        return bytesLess(lhs.ivarNameBytes, rhs.ivarNameBytes)
    }

    private static func hasForbiddenControl(_ bytes: [UInt8]) -> Bool {
        bytes.contains { $0 < 0x20 || $0 == 0x7F }
    }

    /// `address` lies in a single mapped segment with at least the offset variable's width left.
    /// Subtraction happens only after the bounds guards, so no `address + width` can overflow.
    private static func isMappedOffsetVariable(
        _ address: UInt64, layout: [VerifiedSegment]
    ) -> Bool {
        let containing = layout.filter { segment in
            segment.isMapped
                && segment.record.preferredVMStart <= address
                && address < segment.virtualEnd
                && segment.virtualEnd - address >= objCIvarOffsetVariableWidth
        }
        return containing.count == 1
    }

    /// Plans the marked offset-global data records. Not connected to any request by itself.
    ///
    /// - Parameters:
    ///   - classes: the selected image's recovered ObjC classes.
    ///   - source: the analysis symbols of the same image.
    ///   - recovered: the recovered stub symbols already derived from `source`.
    ///   - functions: the same image's functions (only their start addresses are used).
    ///   - mappedLayout: the already verified mapped segments of the same image.
    static func planObjCIvarOffsetSymbols(
        classes: [ObjCClass],
        source: [SymbolSummary],
        recovered: [SymbolSummary] = [],
        functions: [FunctionSummary],
        imageID: String,
        mappedLayout: [VerifiedSegment]
    ) -> ObjCIvarSymbolPlan {
        // Claims: every known-nonzero retained offset-variable address, coalesced by byte tuple.
        var claimSet = Set<ObjCIvarClaim>()
        let prefixBytes = Array(objCIvarSymbolPrefix.utf8)
        for cls in classes {
            let classBytes = Array(cls.name.utf8)
            for ivar in cls.ivars {
                guard let target = ivar.offsetVariable, target != 0 else { continue }
                let ivarBytes = Array(ivar.name.utf8)
                claimSet.insert(ObjCIvarClaim(
                    classNameBytes: classBytes, classAddress: cls.address,
                    ivarNameBytes: ivarBytes, target: target,
                    nameBytes: prefixBytes + classBytes + [UInt8(ascii: ".")] + ivarBytes,
                    className: cls.name, ivarName: ivar.name
                ))
            }
        }
        let claims = claimSet.sorted(by: claimLess)

        // Veto indexes over ALL claims, before any eligibility filtering.
        var claimantsAtAddress: [UInt64: Int] = [:]
        var addressesForName: [[UInt8]: Set<UInt64>] = [:]
        for claim in claims {
            claimantsAtAddress[claim.target, default: 0] += 1
            addressesForName[claim.nameBytes, default: []].insert(claim.target)
        }

        // Authority reservations from real and recovered symbols and function starts.
        var reservedAddresses = Set(functions.map(\.startAddress))
        var rawNamesAtAddress: [UInt64: Set<[UInt8]>] = [:]
        var rawNameAddresses: [[UInt8]: Set<UInt64>] = [:]
        var rawNamesWithoutAddress = Set<[UInt8]>()
        var displayNamesWithoutRaw = Set<[UInt8]>()
        for symbol in source + recovered {
            if let address = symbol.address { reservedAddresses.insert(address) }
            if let raw = symbol.rawLinkageName {
                let bytes = Array(raw.utf8)
                if let address = symbol.address {
                    rawNamesAtAddress[address, default: []].insert(bytes)
                    rawNameAddresses[bytes, default: []].insert(address)
                } else {
                    rawNamesWithoutAddress.insert(bytes)
                }
            } else {
                // Display text is a conservative veto only, never proof of the loader spelling.
                displayNamesWithoutRaw.insert(Array(symbol.name.utf8))
            }
        }

        var decisions: [ObjCIvarPlanDecision] = []
        var candidates: [NativeDecompilerWireSymbolRecord] = []
        for claim in claims {
            func decision(_ state: ObjCIvarPlanState, _ diagnostics: [String]) -> ObjCIvarPlanDecision {
                ObjCIvarPlanDecision(
                    imageID: imageID, address: claim.target,
                    name: String(decoding: claim.nameBytes, as: UTF8.self),
                    className: claim.className, classAddress: claim.classAddress,
                    ivarName: claim.ivarName, state: state, diagnostics: diagnostics
                )
            }
            let eligible = !claim.classNameBytes.isEmpty && !claim.ivarNameBytes.isEmpty
                && !claim.className.unicodeScalars.contains("\u{FFFD}")
                && !claim.ivarName.unicodeScalars.contains("\u{FFFD}")
                && !hasForbiddenControl(claim.classNameBytes)
                && !hasForbiddenControl(claim.ivarNameBytes)
                && isWireText(String(decoding: claim.nameBytes, as: UTF8.self), maximum: 1_024)
                && isMappedOffsetVariable(claim.target, layout: mappedLayout)
            guard eligible else {
                decisions.append(decision(.unchanged, []))
                continue
            }
            let name = String(decoding: claim.nameBytes, as: UTF8.self)
            if (claimantsAtAddress[claim.target] ?? 0) > 1 {
                decisions.append(decision(.abstain, [objCIvarReasonMultipleClaimants]))
            } else if (addressesForName[claim.nameBytes]?.count ?? 0) > 1 {
                decisions.append(decision(.abstain, [objCIvarReasonNameMultipleAddresses]))
            } else if let atAddress = rawNamesAtAddress[claim.target],
                      atAddress.contains(where: { $0 != claim.nameBytes }) {
                decisions.append(decision(.abstain, [objCIvarReasonRealAddressNameMismatch]))
            } else if rawNamesWithoutAddress.contains(claim.nameBytes)
                        || (rawNameAddresses[claim.nameBytes]?.contains(where: { $0 != claim.target }) ?? false) {
                decisions.append(decision(.abstain, [objCIvarReasonRealNameOtherAddress]))
            } else if rawNamesAtAddress[claim.target]?.contains(claim.nameBytes) == true
                        || reservedAddresses.contains(claim.target)
                        || displayNamesWithoutRaw.contains(claim.nameBytes) {
                // The real entry already agrees, or an unproven reservation holds the address.
                decisions.append(decision(.unchanged, []))
            } else {
                decisions.append(decision(.resolved, [objCIvarSymbolProvenanceDiagnostic]))
                candidates.append(NativeDecompilerWireSymbolRecord(
                    imageID: imageID, address: .init(claim.target), name: name, kind: .data,
                    provenance: objCIvarProvenanceMarker
                ))
            }
        }
        return ObjCIvarSymbolPlan(candidates: candidates, decisions: decisions)
    }

    private static let objCIvarSymbolProvenanceDiagnostic = "provenance=\(objCIvarProvenanceMarker)"
}
