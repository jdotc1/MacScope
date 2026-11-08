import Foundation
import XCTest
@testable import NEWFEATURESCore

final class TypesAndExportTests: XCTestCase {
    private func image() throws -> NEWFEATURESImageKey {
        try NEWFEATURESImageKey(slot: 0, binaryID: UUID(), sha256: String(repeating: "d", count: 64), analysisRevision: 1)
    }

    func testExactUnsignedReadAndWriteWitnesses() throws {
        let layout = try NEWFEATURESBitfieldLayout(memberName: "flags", storageBits: 32,
                                             offset: 3, width: 5, isSigned: false)
        XCTAssertNotNil(NEWFEATURESBitfieldRecovery.unsignedRead(
            layout: layout, shift: 3, mask: 31, hasSideEffects: false
        ))
        XCTAssertNil(NEWFEATURESBitfieldRecovery.unsignedRead(
            layout: layout, shift: 3, mask: 63, hasSideEffects: false
        ))
        XCTAssertNil(NEWFEATURESBitfieldRecovery.unsignedRead(
            layout: layout, shift: 3, mask: 31, hasSideEffects: true
        ))
        XCTAssertNotNil(NEWFEATURESBitfieldRecovery.unsignedWrite(
            layout: layout, clearMask: (~(UInt64(31) << 3)) & 0xffffffff,
            valueMask: 31, shift: 3, hasSideEffects: false
        ))
    }

    func testNoSignedFieldInference() throws {
        let signed = try NEWFEATURESBitfieldLayout(memberName: "sign", storageBits: 64,
                                             offset: 63, width: 1, isSigned: true)
        XCTAssertNil(NEWFEATURESBitfieldRecovery.unsignedRead(
            layout: signed, shift: 63, mask: 1, hasSideEffects: false
        ))
    }

    func testSignaturePackRequiresHashAndAllowlist() throws {
        let payload = Data("fixture".utf8)
        let good = NEWFEATURESSignaturePackManifest(
            schemaVersion: 1, architecture: "arm64", producer: "local-compiler-rt",
            sourceCommit: String(repeating: "e", count: 40),
            payloadSHA256: NEWFEATURESSignaturePackAdmission.digest(payload),
            payloadBytes: payload.count
        )
        let accepted = try NEWFEATURESSignaturePackAdmission.admit(
            payload: payload, manifest: good, trustedPins: [
                .init(producer: "local-compiler-rt", sourceCommit: good.sourceCommit,
                      payloadSHA256: good.payloadSHA256),
            ]
        )
        XCTAssertEqual(accepted.data, payload)
        XCTAssertThrowsError(try NEWFEATURESSignaturePackAdmission.admit(
            payload: payload, manifest: good, trustedPins: []
        ))
    }

    func testUnsignedStorageWidthMasks() throws {
        for width in [8, 16, 32, 64] {
            let layout = try NEWFEATURESBitfieldLayout(
                memberName: "bit", storageBits: width,
                offset: 1, width: 3, isSigned: false
            )
            let clear = (~layout.positionedMask) & layout.storageMask
            XCTAssertNotNil(NEWFEATURESBitfieldRecovery.unsignedWrite(
                layout: layout, clearMask: clear, valueMask: 7,
                shift: 1, hasSideEffects: false
            ))
        }
    }

    func testTypeOverlappingLayoutAndCycleRefused() throws {
        let i = try image()
        let provenance = try NEWFEATURESProvenance(
            source: .classMetadata, sourceID: "fixture", sourceSHA256: i.sha256
        )
        let a = NEWFEATURESTypeKey(image: i, language: .swift, declarationID: "A")
        let b = NEWFEATURESTypeKey(image: i, language: .swift, declarationID: "B")
        let overlap = NEWFEATURESClassType(
            key: a, displayName: "A", superclass: nil,
            members: [.init(name: "x", typeName: "Int", bitOffset: 0, bitWidth: 16),
                      .init(name: "y", typeName: "Int", bitOffset: 8, bitWidth: 16)],
            methods: [], provenance: provenance
        )
        XCTAssertThrowsError(try NEWFEATURESTypeIndex([overlap]))
        let left = NEWFEATURESClassType(
            key: a, displayName: "A", superclass: b, members: [], methods: [],
            provenance: provenance
        )
        let right = NEWFEATURESClassType(
            key: b, displayName: "B", superclass: a, members: [], methods: [],
            provenance: provenance
        )
        XCTAssertThrowsError(try NEWFEATURESTypeIndex([left, right]))
    }

    func testForgedSDKTypeWithoutPinRefused() throws {
        let i = try image()
        let externalDigest = String(repeating: "e", count: 64)
        let source = try NEWFEATURESProvenance(
            source: .sdkHeader, sourceID: "fixture-sdk", sourceSHA256: externalDigest
        )
        let declaration = NEWFEATURESClassType(
            key: NEWFEATURESTypeKey(image: i, language: .cpp, declarationID: "Fake"),
            displayName: "Fake", superclass: nil, members: [], methods: [],
            provenance: source
        )
        XCTAssertThrowsError(try NEWFEATURESTypeIndex([declaration]))
        XCTAssertNoThrow(try NEWFEATURESTypeIndex(
            [declaration], trustedSDKHeaderDigests: [externalDigest]
        ))
    }
}
