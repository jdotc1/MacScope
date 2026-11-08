import Foundation

extension WorkspaceScriptingAPI {
    nonisolated static let maximumTypeAtlasPreparation = 4_194_304
    nonisolated static let maximumTypeAtlasRowNodes = 65_536
    nonisolated static let maximumTypeAtlasPageFrameBytes = 200_000
    nonisolated static let maximumTypeAtlasNamesPageFrameBytes = 99_999
    // Frozen oracle: ID 1, one synthetic generation, frame and one LF.
    // Covers even a 1024-byte all-slash cursor and maximal integer widths.
    nonisolated static let typeAtlasPageFrameReserve = 5_000
    nonisolated static let maximumTypeAtlasFullEscapedRowBytes =
        maximumTypeAtlasPageFrameBytes - typeAtlasPageFrameReserve
    nonisolated static let maximumTypeAtlasNamesEscapedRowBytes =
        maximumTypeAtlasNamesPageFrameBytes - typeAtlasPageFrameReserve
    nonisolated static let typeAtlasPageHint =
        "Default replies, including explicit limit, have a byte allowance. Continue a default nextCursor as cursor with page:true, fields:\"full\", limit:1 and the original image/kind. For browsing use page:true, fields:\"names\" (kind, name or nameContains narrow it), preserving those filters on continuation."

    /// Absent or null page with a non-null name, nameContains or fields selects page mode.
    nonisolated static func typeAtlasPageImplied(_ arguments: ScriptValue) -> Bool {
        switch arguments["page"] {
        case .none, .some(.null): break
        default: return false
        }
        // SW5 (dot 1251): only a non-null explicit selector implies paging.
        if arguments["format"] != nil && arguments["format"] != .null { return true }
        return ["name", "nameContains", "fields"].contains { arguments[$0] != nil && arguments[$0] != .null }
    }

    nonisolated static var typeAtlasPreparationRefusal: ScriptingError {
        .structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
            detail: "Type Atlas preparation exceeds 4194304 derived user entries for this image (the image catalog is not cached); no argument narrows it",
            budget: .init(unit: .workSteps, limit: Int64(maximumTypeAtlasPreparation)), narrowing: []))
    }

    nonisolated static let typeAtlasPreparationOverflowNote =
        " used is an observed operand lower bound, not the full sum."

    nonisolated static func typeAtlasPreparationRefusalReporting(
        used: Int64, lowerBound: Bool = false
    ) -> ScriptingError {
        guard case .structuredRefusal(var refusal) = typeAtlasPreparationRefusal else {
            return typeAtlasPreparationRefusal
        }
        refusal.used = used
        if lowerBound { refusal.detail += typeAtlasPreparationOverflowNote }
        return .structuredRefusal(refusal)
    }

    nonisolated static func isTypeAtlasPreparationRefusal(_ error: ScriptingError) -> Bool {
        guard case .structuredRefusal(var refusal) = error,
              case .structuredRefusal(let template) = typeAtlasPreparationRefusal else { return false }
        refusal.used = nil
        if refusal.detail == template.detail + typeAtlasPreparationOverflowNote {
            refusal.detail = template.detail
        }
        return refusal == template
    }

    /// All preparation counters are nonnegative. Returns only sums representable by Int.
    nonisolated static func typeAtlasPreparationSum(_ lhs: UInt, _ rhs: UInt) throws -> Int {
        let (value, overflow) = lhs.addingReportingOverflow(rhs)
        guard !overflow, value <= UInt(Int.max) else {
            throw typeAtlasPreparationRefusalReporting(
                used: Int64(clamping: max(lhs, rhs)), lowerBound: true)
        }
        return Int(value)
    }

    /// Whether page mode would pass its preparation bound for this image.
    nonisolated static func typeAtlasPageWouldPrepare(
        _ analysis: ImageAnalysis?, checkpoint: () throws -> Void
    ) throws -> Bool {
        guard let analysis, analysis.typeCatalog == nil else { return true }
        var checkpointError: Error?
        do {
            try typeAtlasPreparationBound(analysis, checkpoint: {
                do { try checkpoint() }
                catch { checkpointError = error; throw error }
            })
        } catch {
            if let checkpointError { throw checkpointError }
            if let refusal = error as? ScriptingError, isTypeAtlasPreparationRefusal(refusal) { return false }
            throw error
        }
        return true
    }

    nonisolated static func typeAtlasPage(
        _ arguments: ScriptValue, snapshot: WorkspaceSnapshot,
        checkpoint: () throws -> Void, swiftObjCLinks: Bool = true,
        declarationWireBudget: Bool = false
    ) throws -> ScriptValue? {
        if try typeAtlasDeclarationSelected(arguments) {
            return try typeAtlasWireBoundedDeclarationPage(arguments, snapshot: snapshot,
                checkpoint: checkpoint, swiftObjCLinks: swiftObjCLinks)
        }
        let paged: Bool
        switch arguments["page"] {
        case .none, .some(.null): paged = typeAtlasPageImplied(arguments)
        case .some(.bool(false)): paged = false
        case .some(.bool(true)): paged = true
        default: throw ScriptingError.invalidArgument("page must be a boolean")
        }
        guard paged else {
            if let cursor = arguments["cursor"], cursor != .null {
                throw ScriptingError.invalidArgument("cursor requires page:true")
            }
            if ["name", "nameContains", "fields"].contains(where: {
                arguments[$0] != nil && arguments[$0] != .null
            }) {
                throw ScriptingError.invalidArgument("name, nameContains and fields require page:true")
            }
            return nil
        }
        try checkpoint()
        let limit: Int
        switch arguments["limit"] {
        case .none, .some(.null): limit = defaultListPageLimit
        case .some(.int(let value)) where (1...Int64(maximumListPageLimit)).contains(value):
            limit = Int(value)
        default:
            throw ScriptingError.invalidArgument("limit must be an integer from 1 to 1000 when page is true")
        }
        if let value = arguments["kind"], value != .null, value.stringValue == nil {
            throw ScriptingError.invalidArgument("kind must be a string")
        }
        let kind: TypeAtlasKind?
        if let text = arguments["kind"]?.stringValue {
            guard let parsed = TypeAtlasKind(rawValue: text) else {
                throw ScriptingError.invalidArgument(
                    "kind must be one of \(TypeAtlasKind.allCases.map(\.rawValue).joined(separator: "|"))")
            }
            kind = parsed
        } else { kind = nil }
        func filter(_ key: String) throws -> String? {
            guard let value = arguments[key], value != .null else { return nil }
            guard case .string(let text) = value, !text.isEmpty,
                  text.utf8.prefix(1_025).count <= 1_024 else {
                throw ScriptingError.invalidArgument("\(key) must be a non-empty string of at most 1024 UTF-8 bytes")
            }
            return text
        }
        let name = try filter("name")
        let contains = try filter("nameContains")
        let fields: String
        switch arguments["fields"] {
        case .none, .some(.null): fields = "full"
        case .some(.string(let value)) where value == "full" || value == "names": fields = value
        default: throw ScriptingError.invalidArgument("fields must be full or names")
        }
        let digest = typeAtlasFilterDigest(kind: kind, name: name, contains: contains, fields: fields)
        let cursor: (slot: Int, offset: Int, generation: UUID, filter: String)? = try arguments["cursor"].flatMap { value in
            if value == .null { return nil }
            return try decodeTypeAtlasCursor(value)
        }
        do {
            var budget = AttachedTypeReadBudget()
            do {
                try budget.definitions(snapshot.typeDefinitions, includeLayout: true, checkpoint: checkpoint)
            } catch let error as ScriptingError where error == AttachedTypeReadBudget.refused {
                throw TypeAtlasDefaultReplyPolicy.labelBudgetPrefix(budget.reportingRefusal(error))
            }
        }
        let slot = try resolveImageSlot(arguments, snapshot: snapshot)
        if let cursor {
            guard cursor.slot == slot.rawValue, cursor.generation == snapshot.analysisGenerationID,
                  cursor.filter == digest else { throw typeAtlasStaleCursor }
        }
        if let analysis = snapshot.analysisBySlot[slot], analysis.typeCatalog == nil {
            try typeAtlasPreparationBound(analysis, checkpoint: checkpoint)
        }
        try checkpoint()
        let catalog = snapshot.typeCatalog(in: slot)
        let links = try swiftObjCLinks
            ? makeTypeAtlasSwiftObjCLinks(catalog.entries, checkpoint: checkpoint) : TypeAtlasSwiftObjCLinks()
        try checkpoint()
        func matches(_ entry: TypeAtlasEntry) -> Bool {
            if let kind, kind != entry.kind { return false }
            if let name, name != entry.name && name != entry.qualifiedName { return false }
            if let contains {
                let locale = Locale(identifier: "en_US_POSIX")
                let found = entry.name.range(of: contains, options: [.caseInsensitive, .literal], locale: locale) != nil
                    || entry.qualifiedName?.range(of: contains, options: [.caseInsensitive, .literal], locale: locale) != nil
                if !found { return false }
            }
            return true
        }
        let offset = cursor?.offset ?? 0
        if cursor != nil {
            guard offset < catalog.entries.count, matches(catalog.entries[offset]) else {
                throw typeAtlasStaleCursor
            }
        }
        var total = 0
        var rows: [ScriptValue] = []
        rows.reserveCapacity(min(limit, catalog.entries.count))
        let rowAllowance = fields == "names"
            ? maximumTypeAtlasNamesEscapedRowBytes : maximumTypeAtlasFullEscapedRowBytes
        let declarationHeaderWireBytes = declarationWireBudget
            ? try listPageWireBytes(.string(typeAtlasDeclarationText([], checkpoint: checkpoint))) : 0
        func measuredRowWireBytes(_ row: ScriptValue) throws -> Int {
            let ordinary = try listPageWireBytes(row)
            // Let the existing bytes fallback happen before attempting a renderer
            // whose independent string/text limits could refuse the full row.
            guard declarationWireBudget, ordinary < rowAllowance else { return ordinary }
            let text = try typeAtlasDeclarationText([row], checkpoint: checkpoint)
            let rendered = try listPageWireBytes(.string(text)) - declarationHeaderWireBytes
            return max(ordinary, rendered)
        }
        var bytes = 0
        var nextOffset: Int?
        for (index, entry) in catalog.entries.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            guard matches(entry) else { continue }
            total += 1
            guard index >= offset, nextOffset == nil else { continue }
            if rows.count == limit { nextOffset = index; continue }
            let row: ScriptValue
            let rowWireBytes: Int
            if fields == "names" {
                row = try applyingTypeAtlasLink(typeAtlasNamesRow(entry), link: links.byIndex[index],
                    namesOnly: true, checkpoint: checkpoint)
                rowWireBytes = try measuredRowWireBytes(row)
            } else if try typeAtlasRowNodeBound(entry, linked: links.byIndex[index] != nil, checkpoint: checkpoint) > maximumTypeAtlasRowNodes {
                row = try applyingTypeAtlasLink(typeAtlasNamesRow(entry, omitted: "nodes"), link: links.byIndex[index],
                    namesOnly: true, checkpoint: checkpoint)
                rowWireBytes = try measuredRowWireBytes(row)
            } else {
                let full = try applyingTypeAtlasLink(typeAtlasEntryValue(entry), link: links.byIndex[index], checkpoint: checkpoint)
                let fullWireBytes = try measuredRowWireBytes(full)
                if fullWireBytes >= rowAllowance {
                    row = try applyingTypeAtlasLink(typeAtlasNamesRow(entry, omitted: "bytes"), link: links.byIndex[index],
                        namesOnly: true, checkpoint: checkpoint)
                    rowWireBytes = try measuredRowWireBytes(row)
                } else {
                    row = full
                    rowWireBytes = fullWireBytes
                }
            }
            // Compare before adding the separator. There is no first-row exemption.
            if rowWireBytes >= rowAllowance - bytes {
                if rows.isEmpty {
                    throw ScriptingError.structuredRefusal(MCPToolRefusal(code: .budgetExceeded,
                        detail: "Type Atlas names projection exceeds the page wire allowance; filters can select other rows but cannot make this row smaller.",
                        field: "rows", budget: .init(unit: .bytes, limit: Int64(rowAllowance)),
                        used: Int64(rowWireBytes + 1), narrowing: []))
                }
                nextOffset = index
                continue
            }
            rows.append(row)
            bytes += rowWireBytes + 1
        }
        var result = imageProvenanceFields(slot: slot, snapshot: snapshot)
        result["rows"] = .array(rows)
        result["total"] = .int(Int64(total))
        result["isTruncated"] = .bool(nextOffset != nil)
        result["nextCursor"] = nextOffset.map {
            .string(encodeTypeAtlasCursor(slot: slot, offset: $0,
                generation: snapshot.analysisGenerationID, filter: digest))
        } ?? .null
        result["sourceComplete"] = .null
        if let counts = links.counts { result["swiftObjCLinks"] = typeAtlasLinkCountsValue(counts) }
        try checkpoint()
        return .object(result)
    }

    private nonisolated static func typeAtlasWireBoundedDeclarationPage(
        _ arguments: ScriptValue, snapshot: WorkspaceSnapshot,
        checkpoint: () throws -> Void, swiftObjCLinks: Bool
    ) throws -> ScriptValue {
        try checkpoint()
        guard case .object(var fields) = arguments else {
            throw ScriptingError.invalidArgument("arguments must be an object")
        }
        switch fields["page"] {
        case .none, .some(.null), .some(.bool(true)): break
        case .some(.bool(false)):
            throw ScriptingError.invalidArgument("declarations-v1 requires page:true or an omitted page")
        default: throw ScriptingError.invalidArgument("page must be a boolean")
        }
        fields.removeValue(forKey: "format")
        fields["page"] = .bool(true)
        if let cursor = fields["cursor"], cursor != .null {
            fields["cursor"] = try typeAtlasDeclarationCursor(cursor)
        }
        guard let page = try typeAtlasPage(.object(fields), snapshot: snapshot,
            checkpoint: checkpoint, swiftObjCLinks: swiftObjCLinks, declarationWireBudget: true) else {
            throw typeAtlasDeclarationRefusal("The bounded page producer returned no page.",
                unit: .rows, limit: 1, used: 0)
        }
        return try typeAtlasDeclarationResult(page, checkpoint: checkpoint)
    }

    private nonisolated static var typeAtlasStaleCursor: ScriptingError {
        .invalidArgument("staleCursor: the list changed or the cursor belongs to another list; restart without a cursor")
    }

    /// Offset is the first omitted matching ORIGINAL catalog index, never a prefix index.
    nonisolated static func typeAtlasDefaultContinuation(
        slot: ImageSlot, offset: Int, generation: UUID, kind: TypeAtlasKind?
    ) -> String {
        precondition(offset > 0)
        return encodeTypeAtlasCursor(slot: slot, offset: offset, generation: generation,
            filter: typeAtlasFilterDigest(kind: kind, name: nil, contains: nil, fields: "full"))
    }

    private nonisolated static func typeAtlasFilterDigest(
        kind: TypeAtlasKind?, name: String?, contains: String?, fields: String
    ) -> String {
        func tagged(_ value: String?) -> String {
            guard let value else { return "0" }
            let escaped = value.replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\0", with: "\\0")
            return "1" + escaped
        }
        let text = "k=\(tagged(kind?.rawValue))\0n=\(tagged(name))\0c=\(tagged(contains))\0f=\(fields)"
        var hash: UInt64 = 0xcbf29ce484222325
        for byte in text.utf8 { hash = (hash ^ UInt64(byte)) &* 0x100000001b3 }
        let hex = String(hash, radix: 16)
        return String(repeating: "0", count: 16 - hex.count) + hex
    }

    private nonisolated static func encodeTypeAtlasCursor(
        slot: ImageSlot, offset: Int, generation: UUID, filter: String
    ) -> String {
        Data("l1|list-image-types|\(slot.rawValue)|\(offset)|\(generation.uuidString)|\(filter)".utf8)
            .base64EncodedString()
    }

    private nonisolated static func decodeTypeAtlasCursor(
        _ value: ScriptValue
    ) throws -> (slot: Int, offset: Int, generation: UUID, filter: String) {
        let bad = ScriptingError.invalidArgument("malformed cursor")
        guard case .string(let text) = value,
              text.utf8.prefix(maximumListCursorBytes + 1).count <= maximumListCursorBytes,
              let data = Data(base64Encoded: text), data.base64EncodedString() == text,
              let body = String(data: data, encoding: .utf8) else { throw bad }
        let parts = body.split(separator: "|", omittingEmptySubsequences: false)
        func decimal(_ part: Substring) -> Bool {
            !part.isEmpty && part.utf8.allSatisfy { (48...57).contains($0) }
        }
        guard parts.count == 6, parts[0] == "l1", parts[1] == "list-image-types",
              decimal(parts[2]), let slot = Int(parts[2]),
              decimal(parts[3]), let offset = Int(parts[3]), offset > 0,
              let generation = UUID(uuidString: String(parts[4])),
              parts[5].utf8.count == 16,
              parts[5].utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw bad }
        return (slot, offset, generation, String(parts[5]))
    }

    private nonisolated static func typeAtlasNamesRow(
        _ entry: TypeAtlasEntry, omitted: String? = nil
    ) -> ScriptValue {
        // Three escaped strings share one row; halve the ordinary one-field cap.
        let cap = maximumListPageFieldBytes / 2
        func capped(_ text: String) -> (String, Int, Bool) {
            let length = text.utf8.count
            guard length > cap else { return (text, length, false) }
            var prefix = ""
            var used = 0
            for scalar in text.unicodeScalars {
                let width: Int
                switch scalar.value {
                case 0...0x7f: width = 1
                case 0x80...0x7ff: width = 2
                case 0x800...0xffff: width = 3
                default: width = 4
                }
                guard width <= cap - used else { break }
                prefix.unicodeScalars.append(scalar)
                used += width
            }
            return (prefix, length, true)
        }
        var id: [String: ScriptValue] = [
            "slot": .int(Int64(entry.id.slot.rawValue)), "kind": .string(entry.id.kind.rawValue),
        ]
        var row: [String: ScriptValue] = [
            "imageSlot": .int(Int64(entry.id.slot.rawValue)), "kind": .string(entry.kind.rawValue),
        ]
        let name = capped(entry.name)
        row["name"] = .string(name.0)
        if name.2 {
            row["nameTruncated"] = .bool(true)
            row["nameByteLength"] = .int(Int64(name.1))
        }
        switch entry.id.key {
        case .address(let address): id["address"] = .hex(address)
        case .name(let text):
            let value = capped(text)
            id["name"] = .string(value.0)
            if value.2 {
                row["idNameTruncated"] = .bool(true)
                row["idNameByteLength"] = .int(Int64(value.1))
            }
        }
        row["id"] = .object(id)
        switch entry.kind {
        case .swiftClass, .swiftStruct, .swiftEnum:
            // Ownership uncertainty survives names-only and oversized-row projections.
            // Preserve nil for legacy rows; false is not extraction completeness.
            row["hasUnassignedSwiftConformanceRecords"] = entry.hasUnassignedSwiftConformanceRecords.map(ScriptValue.bool) ?? .null
            if let text = entry.qualifiedName {
                let value = capped(text)
                row["qualifiedName"] = .string(value.0)
                if value.2 {
                    row["qualifiedNameTruncated"] = .bool(true)
                    row["qualifiedNameByteLength"] = .int(Int64(value.1))
                }
            } else { row["qualifiedName"] = .null }
        default: break
        }
        if let omitted {
            row["fullRowOmitted"] = .bool(true)
            row["fullRowReason"] = .string(omitted)
        }
        return .object(row)
    }

    /// Bounds derived image fan-out, not total input storage or builder wall time.
    private nonisolated static func typeAtlasPreparationBound(
        _ analysis: ImageAnalysis, checkpoint: () throws -> Void
    ) throws {
        func sum(_ lhs: Int, _ rhs: Int) throws -> Int {
            try typeAtlasPreparationSum(UInt(lhs), UInt(rhs))
        }
        var addresses = Set<UInt64>()
        for (index, cls) in analysis.objcClasses.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            if let address = cls.address { addresses.insert(address) }
        }
        var dataUsers: [UInt64: Int] = [:]
        var classAddressUsers: [UInt64: Int] = [:]
        var classNameUsers: [String: Int] = [:]
        var selectorUsers: [String: Int] = [:]
        for (index, ref) in analysis.xrefs.enumerated() {
            if index % 4_096 == 0 { try checkpoint() }
            switch ref.kind {
            case XRefKind.data where addresses.contains(ref.to):
                dataUsers[ref.to] = try sum(dataUsers[ref.to, default: 0], 1)
            case XRefKind.classref:
                guard let target = analysis.objcClassReferences[ref.to] else { continue }
                if let address = target.classAddress {
                    classAddressUsers[address] = try sum(classAddressUsers[address, default: 0], 1)
                }
                if let name = target.name {
                    classNameUsers[name] = try sum(classNameUsers[name, default: 0], 1)
                }
            case XRefKind.selref:
                guard let selector = analysis.objcSelectors[ref.to] else { continue }
                selectorUsers[selector] = try sum(selectorUsers[selector, default: 0], 1)
            default: break
            }
        }
        var fanout = 0
        func take(_ count: Int) throws {
            fanout = try sum(fanout, count)
            guard fanout <= maximumTypeAtlasPreparation else {
                throw typeAtlasPreparationRefusalReporting(used: Int64(fanout))
            }
        }
        func methods(_ values: [ObjCMethod]) throws {
            for (index, method) in values.enumerated() {
                if index % checkpointInterval == 0 { try checkpoint() }
                try take(selectorUsers[method.selector, default: 0])
            }
        }
        for cls in analysis.objcClasses {
            try checkpoint()
            try take(classNameUsers[cls.name, default: 0])
            if let address = cls.address {
                try take(dataUsers[address, default: 0])
                try take(classAddressUsers[address, default: 0])
            }
            try methods(cls.classMethods)
            try methods(cls.instanceMethods)
        }
        for category in analysis.objcCategories {
            try checkpoint()
            try methods(category.classMethods)
            try methods(category.instanceMethods)
        }
        for proto in analysis.objcProtocols {
            try checkpoint()
            try methods(proto.requiredMethods)
            try methods(proto.optionalMethods)
        }
        var conformanceNames: [String: Int] = [:]
        var conformanceMethods: [UInt64: Int] = [:]
        for (index, conformance) in analysis.swiftConformances.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            conformanceNames[conformance.typeName] = try sum(
                conformanceNames[conformance.typeName, default: 0], 1)
            if let descriptor = conformance.typeDescriptorAddress {
                let amount = try sum(1, conformance.methods?.count ?? 0)
                conformanceMethods[descriptor] = try sum(conformanceMethods[descriptor, default: 0], amount)
            }
        }
        for (index, type) in analysis.swiftTypes.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            switch type.kind {
            case .class, .struct, .enum: break
            case .unknown: continue
            }
            try take(conformanceNames[type.name, default: 0])
            if let descriptor = type.descriptorAddress {
                try take(conformanceMethods[descriptor, default: 0])
            }
        }
        try checkpoint()
    }

    /// Each scalar, array and object is one ScriptValue node. Saturate above the cap.
    private nonisolated static func typeAtlasRowNodeBound(
        _ entry: TypeAtlasEntry, linked: Bool = false, checkpoint: () throws -> Void
    ) throws -> Int {
        var count = 49 + (linked ? 16 : 0) // Common/Swift/protocol fields, id and optional imported record.
        func take(_ amount: Int, times: Int = 1) -> Bool {
            let (product, overflow1) = amount.multipliedReportingOverflow(by: times)
            let (next, overflow2) = count.addingReportingOverflow(product)
            guard !overflow1, !overflow2, next <= maximumTypeAtlasRowNodes else {
                count = maximumTypeAtlasRowNodes + 1
                return false
            }
            count = next
            return true
        }
        guard take(entry.members.count, times: 15), take(entry.conformances.count),
              take(entry.users.count), take(entry.methods.count, times: 13),
              take(entry.declaredProperties?.count ?? 0, times: 3),
              take(entry.swiftConformanceMethods?.count ?? 0, times: 4) else { return count }
        for (index, method) in entry.methods.enumerated() {
            if index % checkpointInterval == 0 { try checkpoint() }
            guard take(method.selectorUsers.count) else { return count }
        }
        for conformance in entry.swiftConformanceMethods ?? [] {
            try checkpoint()
            let methods = conformance.methods ?? []
            guard take(methods.count, times: 13) else { return count }
            for (index, method) in methods.enumerated() {
                if index % checkpointInterval == 0 { try checkpoint() }
                guard take(method.selectorUsers.count) else { return count }
            }
        }
        return count
    }
}
