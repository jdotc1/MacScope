import Foundation

// Port of ar4a src/airs/swift_nominal_context.py:5–67. This reads only
// already-admitted immutable image bytes, never runtime metadata.
func admitSwiftOutcomeLegacyStructContext(
    image: SwiftOutcomeLegacyAdmittedImage,
    declaration: SwiftThrowingDeclaration,
    maxEntries: Int = 1024,
    charge: () throws -> Void = {}
) throws -> SwiftOutcomeJSON {
    let declined: SwiftOutcomeJSON = .object([
        "status": .string("declined"), "reason": .string("method_context_not_admitted")])
    guard let section = image.sections.first(where: { $0.segment == "__TEXT" && $0.name == "__swift5_types" }),
          section.size % 4 == 0, Int128(section.size / 4) <= Int128(maxEntries) else {
        return declined
    }

    // Only byte-mapping/metadata errors are declined. In particular, never
    // swallow a caller's work-budget refusal thrown by charge (donor:65).
    func bytes(_ pc: Int128, _ size: Int) throws -> Data {
        guard let address = UInt64(exactly: pc) else { throw SwiftOutcomeNominalMetadataRefusal.malformed }
        do { return try image.bytesAt(address: address, size: size) }
        catch let error as SwiftOutcomeError where error.code == "unmapped_address" || error.code == "unmapped_bytes" {
            throw SwiftOutcomeNominalMetadataRefusal.malformed
        }
    }
    func rawWord(_ pc: Int128) throws -> UInt32 {
        let data = [UInt8](try bytes(pc, 4))
        guard data.count == 4 else { throw SwiftOutcomeNominalMetadataRefusal.malformed }
        return UInt32(data[0]) | UInt32(data[1]) << 8 | UInt32(data[2]) << 16 | UInt32(data[3]) << 24
    }
    func word(_ pc: Int128) throws -> UInt32 {
        try charge()
        return try rawWord(pc)
    }
    func relative(_ pc: Int128) throws -> Int128 {
        try charge()
        let offset = Int32(bitPattern: try rawWord(pc))
        let target = pc + Int128(offset)
        guard offset != 0, target >= 0, target <= Int128(UInt64.max) else {
            throw SwiftOutcomeNominalMetadataRefusal.malformed
        }
        return target
    }
    func identifier(_ pc: Int128) throws -> String {
        var data: [UInt8] = []
        for offset in 0..<129 {
            try charge()
            guard let byte = try bytes(pc + Int128(offset), 1).first else {
                throw SwiftOutcomeNominalMetadataRefusal.malformed
            }
            if byte == 0 {
                guard data.allSatisfy({ $0 < 128 }) else { throw SwiftOutcomeNominalMetadataRefusal.malformed }
                return String(decoding: data, as: UTF8.self)
            }
            data.append(byte)
        }
        throw SwiftOutcomeNominalMetadataRefusal.malformed
    }
    func hexBytes(_ data: Data) -> String {
        data.map { byte in
            let digits = String(byte, radix: 16)
            return byte < 16 ? "0" + digits : digits
        }.joined()
    }

    var matches: [[String: SwiftOutcomeJSON]] = []
    do {
        var offset: UInt64 = 0
        while offset < section.size {
            let field = Int128(section.address) + Int128(offset)
            offset += 4
            // Tagged indirect entries invalidate the complete table, even if
            // another entry already matched (donor:38–40).
            if try word(field) & 1 != 0 { return declined }
            let descriptor = try relative(field)
            let flags = try word(descriptor)
            if flags & 31 != 17 { continue }
            let owner = try identifier(relative(descriptor + 8))
            if owner != declaration.typeName { continue }
            let parent = try relative(descriptor + 4)
            let parentFlags = try word(parent)
            let module = try identifier(relative(parent + 8))
            if module != declaration.module { continue }
            if flags != 0x51 || (parentFlags != 0 && parentFlags != 0x40) { return declined }
            if try word(parent + 4) != 0 { return declined }
            try charge()
            _ = try bytes(descriptor, 28)
            // Preserve the donor's two uncharged evidence reads after its
            // charged descriptor extent check (donor:56–62).
            matches.append([
                "descriptor_pc": .string(swiftOutcomeHex(descriptor)),
                "descriptor_flags": .string(swiftOutcomeHex(flags)),
                "parent_pc": .string(swiftOutcomeHex(parent)),
                "parent_flags": .string(swiftOutcomeHex(parentFlags)),
                "type_name": .string(owner), "module": .string(module),
                "raw_descriptor": .string(hexBytes(try bytes(descriptor, 28))),
                "raw_parent": .string(hexBytes(try bytes(parent, 12)))])
        }
        if matches.count == 1 {
            var result = matches[0]
            result["status"] = .string("admitted_struct_context")
            return .object(result)
        }
    } catch is SwiftOutcomeNominalMetadataRefusal {
        return declined
    }
    return declined
}

private enum SwiftOutcomeNominalMetadataRefusal: Error { case malformed }
