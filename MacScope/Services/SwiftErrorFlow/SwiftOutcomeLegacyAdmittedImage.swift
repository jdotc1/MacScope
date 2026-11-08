import Foundation

/// Immutable selected-slice bytes plus caller-supplied, already-admitted metadata.
/// This is NOT a Mach-O parser, admission seal, or authorization for live v2 use.
/// Offsets refer to this selected slice; containerOffset is presentation provenance.
struct SwiftOutcomeLegacyAdmittedImage: Sendable {
    struct Section: Equatable, Sendable {
        let address: UInt64, size: UInt64, fileOffset: UInt64
        let executable: Bool
        let flags: UInt32
        let segment: String, name: String
        var end: Int128 { Int128(address) + Int128(size) }
    }
    let data: Data
    let sliceSHA256: String, containerSHA256: String, architecture: String
    let cpuSubtype: UInt32
    let uuid: String?
    let sliceOffset: UInt64, sliceSize: UInt64, preferredBase: UInt64
    let sections: [Section]
    let functions: [SwiftErrorFlowFunction]
    func unsigned(at offset: Int128, count: Int) throws -> UInt64 {
        guard count >= 0, count <= 8, offset >= 0, offset + Int128(count) <= Int128(data.count), let start = Int(exactly: offset) else {
            throw SwiftOutcomeError(code: "malformed_or_incomplete_evidence")
        }
        var value: UInt64 = 0
        for i in 0..<count { value |= UInt64(data[data.startIndex + start + i]) << (i * 8) }
        return value
    }
    func bytesAt(address: UInt64, size: Int) throws -> Data {
        guard size >= 0, let s = sections.first(where: { $0.address <= address && Int128(address) + Int128(size) <= $0.end }) else {
            throw SwiftOutcomeError(code: "unmapped_address")
        }
        let offset = Int128(s.fileOffset) + Int128(address) - Int128(s.address)
        guard ![UInt32(1),12,18].contains(s.flags & 255), offset >= 0, offset + Int128(size) <= Int128(data.count), offset + Int128(size) <= Int128(sliceSize), let start = Int(exactly: offset) else {
            throw SwiftOutcomeError(code: "unmapped_bytes")
        }
        return Data(data[(data.startIndex + start)..<(data.startIndex + start + size)])
    }
    func wordAt(_ address: UInt64) throws -> UInt32 {
        let b = [UInt8](try bytesAt(address: address,size: 4))
        return UInt32(b[0]) | UInt32(b[1]) << 8 | UInt32(b[2]) << 16 | UInt32(b[3]) << 24
    }
    var identity: SwiftOutcomeJSON {
        .object(["architecture": .string(architecture),"cpu_subtype": .integer(Int128(cpuSubtype)),"uuid": uuid.map(SwiftOutcomeJSON.string) ?? .null,
                 "slice_sha256": .string(sliceSHA256),"container_sha256": .string(containerSHA256),"slice_offset": .integer(Int128(sliceOffset)),
                 "slice_size": .integer(Int128(sliceSize)),"preferred_base": .string(swiftOutcomeHex(preferredBase))])
    }
}
