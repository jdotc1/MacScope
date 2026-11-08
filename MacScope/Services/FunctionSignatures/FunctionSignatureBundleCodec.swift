import Foundation

// Owned by MacScopeApp through its Services source glob. Existing model types
// remain in MacScopeAnalysisCore, implicitly imported by current target flags.
/// A local wire adapter for the existing schema-v1 model, not a FLIRT parser.
enum FunctionSignatureBundleCodec {
    static let maximumPayloadBytes = 32 * 1_024 * 1_024
    static let maximumRecords = 8_192
    static let maximumTextBytes = 4_096

    static func decode(_ payload: Data) throws -> FunctionSignatureDatabase {
        guard (12...maximumPayloadBytes).contains(payload.count) else {
            throw FunctionSignatureBundleError.payloadLength
        }
        var reader = Reader(bytes: Array(payload))
        guard try reader.bytes(4) == [0x46, 0x53, 0x49, 0x47],
              try reader.u16() == FunctionSignatureDatabase.currentSchemaVersion,
              try reader.u8() == FunctionSignatureArchitecture.arm64.rawValue,
              try reader.u8() == 0 else { throw FunctionSignatureBundleError.wireHeader }
        let count = Int(try reader.u32())
        guard (1...maximumRecords).contains(count) else { throw FunctionSignatureBundleError.countLimit }
        var signatures: [FunctionSignature] = []
        for _ in 0..<count {
            let name = try reader.text()
            let library = try reader.text()
            let length = try reader.u32()
            let prefixCount = Int(try reader.u8())
            guard (1...32).contains(prefixCount) else { throw FunctionSignatureBundleError.countLimit }
            let prefix = try FunctionSignatureMaskedPattern(
                bytes: reader.bytes(prefixCount), comparisonMask: reader.bytes(prefixCount))
            let checksum = try FunctionSignatureChecksumSpan(
                offset: reader.u32(), byteCount: reader.u32(), crc32: reader.u32())
            let tailCount = Int(try reader.u8())
            guard tailCount <= 8 else { throw FunctionSignatureBundleError.countLimit }
            var runs: [FunctionSignatureMaskedByteRun] = []
            for _ in 0..<tailCount {
                let offset = try reader.u32()
                let byteCount = Int(try reader.u32())
                guard (1...1_048_576).contains(byteCount) else { throw FunctionSignatureBundleError.countLimit }
                runs.append(try .init(offset: offset, bytes: reader.bytes(byteCount),
                                      comparisonMask: reader.bytes(byteCount)))
            }
            let referenceCount = Int(try reader.u8())
            guard referenceCount <= 8 else { throw FunctionSignatureBundleError.countLimit }
            var references: [FunctionSignatureImportedReference] = []
            for _ in 0..<referenceCount {
                references.append(try .init(instructionOffset: reader.u32(), expectedSymbolName: reader.text()))
            }
            signatures.append(.init(architecture: .arm64, name: name, libraryName: library,
                totalLength: length, prefix: prefix, checksum: checksum,
                collisionTail: .init(byteRuns: runs, importedReferences: references)))
        }
        guard reader.isAtEnd else { throw FunctionSignatureBundleError.trailingBytes }
        return .init(schemaVersion: FunctionSignatureDatabase.currentSchemaVersion, signatures: signatures)
    }

    private struct Reader {
        let storage: [UInt8]
        private var position = 0
        init(bytes: [UInt8]) { self.storage = bytes }
        var isAtEnd: Bool { position == storage.count }
        mutating func bytes(_ count: Int) throws -> [UInt8] {
            guard count >= 0, count <= storage.count - position else {
                throw FunctionSignatureBundleError.truncatedPayload
            }
            defer { position += count }
            return Array(storage[position..<(position + count)])
        }
        mutating func u8() throws -> UInt8 { try bytes(1)[0] }
        mutating func u16() throws -> UInt16 {
            let value = try bytes(2)
            return UInt16(value[0]) | UInt16(value[1]) << 8
        }
        mutating func u32() throws -> UInt32 {
            let value = try bytes(4)
            return UInt32(value[0]) | UInt32(value[1]) << 8 | UInt32(value[2]) << 16 | UInt32(value[3]) << 24
        }
        mutating func text() throws -> String {
            let count = Int(try u16())
            guard (1...maximumTextBytes).contains(count) else { throw FunctionSignatureBundleError.countLimit }
            guard let result = String(bytes: try bytes(count), encoding: .utf8) else {
                throw FunctionSignatureBundleError.invalidUTF8
            }
            return result
        }
    }
}
