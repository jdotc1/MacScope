import Foundation
import XCTest
@testable import MacScope

// Item 1312. Supplied pin ec7378046184c6d5cc579a1539d15f9691926d79.
// Static authored only: not compiled or run. No token accessor or production edits.
// Mirror observes reflected stored values, not computed/static properties or all possible
// states. Populated optional/collection children are essential. Custom reflection can hide
// storage. Closure types are checked by their reflected type name, not by class detection.
final class NativeValidationTypeShapeTests: XCTestCase {
    func testNativeValidationSevenPopulatedAuthorityShapes() throws {
        let digest = String(repeating: "a", count: 64) // Literal test data, not a computed hash.
        let identity = try MachOSliceArtifactIdentity(
            uuid: UUID(uuidString: "10000000-0000-0000-0000-000000000001")!,
            rawCPUType: 0x0100_000C,
            rawCPUSubtype: 0,
            selectedSliceSHA256: digest,
            selectedSliceByteCount: 512
        )
        let layout = try MachOPreferredSegmentLayout(
            records: [MachOPreferredSegmentLayout.Record(
                name: "__TEXT", preferredVMStart: 0x1_0000_0000,
                preferredVMSize: 512, sliceRelativeFileOffset: 0,
                fileSize: 512, initialProtections: 5
            )],
            selectedSliceByteCount: 512
        )
        let facet = try AnalysisFacetFingerprint(
            kind: .selectedSliceBytes, itemCount: 1, byteCount: 512, sha256: digest
        )
        let archive = ELFArchiveMemberSelection(
            container: ELFArchiveContainerIdentity(byteCount: 1024, sha256: digest),
            member: ELFArchiveMemberIdentity(
                index: 0, archiveHeaderIndex: 0, name: "member.o",
                payloadOffset: 64, byteCount: 512, sha256: digest
            )
        )
        // Input 2:348-354 requires the member to fit in its container.
        XCTAssertTrue(BinaryImage.isValidArchiveMemberIdentity(archive))
        let archiveFingerprint = try AnalysisInputFingerprint(
            imageSlot: ImageSlot(rawValue: 1),
            binaryID: UUID(uuidString: "20000000-0000-0000-0000-000000000002")!,
            binaryName: "member.o", binaryPath: "/shape-only/archive.a",
            selectedSliceIndex: nil, artifactIdentity: identity,
            elfArchiveMemberIdentity: archive, imageByteCount: 512,
            imageBytesSHA256: digest, facets: [facet], overallSHA256: digest,
            inputKey: digest
        )
        let sliceFingerprint = try AnalysisInputFingerprint(
            imageSlot: ImageSlot(rawValue: 1),
            binaryID: UUID(uuidString: "20000000-0000-0000-0000-000000000002")!,
            binaryName: "slice", binaryPath: "/shape-only/image",
            selectedSliceIndex: 0, artifactIdentity: identity,
            elfArchiveMemberIdentity: nil, imageByteCount: 512,
            imageBytesSHA256: digest, facets: [facet], overallSHA256: digest,
            inputKey: digest
        )
        let metadata = MachOLoadMetadata(
            codeSignature: MachOLoadMetadata.CodeSignatureInfo(
                teamIdentifier: "SHAPETEAM", identifier: "shape.example",
                hashTypeName: "SHA-256", codeSignatureFlags: 1,
                entitlementsFormat: "XML", entitlementsXML: "<plist><dict/></plist>",
                entitlementsDER: false, entitlementsKeyCount: 1,
                entitlementsKeys: ["shape.entitlement"], entitlementsParsed: true
            ),
            importedSymbols: [MachOLoadMetadata.ImportedSymbol(
                name: "_shape", libraryOrdinal: 1,
                libraryName: "/usr/lib/libShape.dylib", isWeak: false,
                addend: 1, source: "import table",
                origins: [
                    ImportOrigin(encoding: .nlistDesc, rawOrdinal: 1,
                                 isWeak: false, tableIndex: 0),
                    ImportOrigin(encoding: .chainedFixup, rawOrdinal: 1,
                                 isWeak: false, tableIndex: 1)
                ]
            )],
            dependentDylibs: [MachOLoadMetadata.DependentDylib(
                path: "/usr/lib/libShape.dylib", kind: "required",
                currentVersion: "1.0.0", compatibilityVersion: "1.0.0", ordinal: 1
            )],
            exportNamespace: ExportNamespaceSummary(
                complete: true, terminalCount: 2, reexportCount: 1
            )
        )

        nativeValidationAssertShape(identity, path: "SHAPE-MACHO-SLICE-ARTIFACT-IDENTITY")
        nativeValidationAssertShape(layout, path: "SHAPE-MACHO-PREFERRED-SEGMENT-LAYOUT")
        nativeValidationAssertShape(facet, path: "SHAPE-ANALYSIS-FACET-FINGERPRINT")
        nativeValidationAssertShape(archive, path: "SHAPE-ELF-ARCHIVE-MEMBER-SELECTION")
        nativeValidationAssertShape(metadata, path: "SHAPE-MACHO-LOAD-METADATA")
        nativeValidationAssertShape(
            archiveFingerprint, path: "SHAPE-ANALYSIS-INPUT-FINGERPRINT-ARCHIVE-MEMBER",
            allowedNilPaths: ["SHAPE-ANALYSIS-INPUT-FINGERPRINT-ARCHIVE-MEMBER.selectedSliceIndex"]
        )
        nativeValidationAssertShape(
            sliceFingerprint, path: "SHAPE-ANALYSIS-INPUT-FINGERPRINT-SLICE-INDEX",
            allowedNilPaths: ["SHAPE-ANALYSIS-INPUT-FINGERPRINT-SLICE-INDEX.elfArchiveMemberIdentity"]
        )
        // SHAPE-DEBUGGER-CANONICAL-SOURCE-TABLE-PATH: exercise both enum payloads.
        nativeValidationAssertShape(
            DebuggerCanonicalSourceTablePath.absoluteUTF8("/shape-only/source.c"),
            path: "SHAPE-DEBUGGER-ABSOLUTE"
        )
        nativeValidationAssertShape(
            DebuggerCanonicalSourceTablePath.compilationDirectoryRelativeUTF8("source.c"),
            path: "SHAPE-DEBUGGER-RELATIVE"
        )
    }

    // SHAPE-POSITIVE-CONTROL: the private class-bearing struct must be rejected.
    func testNativeValidationWalkerRejectsClassPositiveControl() {
        let violations = nativeValidationViolations(
            NativeValidationClassControl(), path: "control", allowedNilPaths: []
        )
        XCTAssertTrue(violations.contains { $0.contains("control.instance: class") },
                      "Walker must detect the stored final class: \(violations)")
    }

    func testNativeValidationWalkerRejectsClosureByTypeName() {
        let violations = nativeValidationViolations(
            NativeValidationClosureControl(), path: "control", allowedNilPaths: []
        )
        XCTAssertTrue(violations.contains { $0.contains("control.callback: closure") },
                      "A closure is not a class; its type name must be checked: \(violations)")
    }

    private func nativeValidationAssertShape(
        _ value: Any, path: String, allowedNilPaths: Set<String> = [],
        file: StaticString = #filePath, line: UInt = #line
    ) {
        let mirror = Mirror(reflecting: value)
        XCTAssertTrue(mirror.displayStyle == .struct || mirror.displayStyle == .enum,
                      "\(path): root must be a struct or enum", file: file, line: line)
        // All seven supplied declarations have stored fields or associated payloads.
        XCTAssertFalse(mirror.children.isEmpty,
                       "\(path): populated root must expose children", file: file, line: line)
        let violations = nativeValidationViolations(
            value, path: path, allowedNilPaths: allowedNilPaths
        )
        XCTAssertTrue(violations.isEmpty, violations.joined(separator: "\n"),
                      file: file, line: line)
    }

    private func nativeValidationViolations(
        _ value: Any, path: String, allowedNilPaths: Set<String>
    ) -> [String] {
        let mirror = Mirror(reflecting: value)
        if mirror.displayStyle == .class || type(of: value) is AnyClass {
            // Stop at a reference: report it without risking traversal of a reference cycle.
            return ["\(path): class \(String(reflecting: type(of: value)))"]
        }
        let typeName = String(reflecting: type(of: value))
        if typeName.contains("->") {
            return ["\(path): closure/function type \(typeName)"]
        }
        if mirror.displayStyle == .optional && mirror.children.isEmpty {
            return allowedNilPaths.contains(path) ? [] : ["\(path): unpopulated optional"]
        }
        if (mirror.displayStyle == .collection || mirror.displayStyle == .dictionary
            || mirror.displayStyle == .set) && mirror.children.isEmpty {
            return ["\(path): unpopulated collection"]
        }
        var violations: [String] = []
        // No style whitelist: includes optionals, arrays, dictionary key/value tuples,
        // enum payloads, tuples and nested structs. Scalar leaf mirrors end naturally.
        for (index, child) in mirror.children.enumerated() {
            let childPath = path + "." + (child.label ?? "[\(index)]")
            violations += nativeValidationViolations(
                child.value, path: childPath, allowedNilPaths: allowedNilPaths
            )
        }
        return violations
    }
}

private final class NativeValidationReferenceControl {}

private struct NativeValidationClassControl {
    let instance = NativeValidationReferenceControl()
}

private struct NativeValidationClosureControl {
    let callback: () -> Void = {}
}
