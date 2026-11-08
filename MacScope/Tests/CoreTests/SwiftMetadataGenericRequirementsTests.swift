import Foundation
import XCTest
@testable import MacScope

/// ABI-derived fixtures. These tests must be executed by the accepting local lane.
final class SwiftMetadataGenericRequirementsTests: XCTestCase {
    // SW3 / item 1249: authored crafted-byte controls.
    // No app fixtures or swift-section counts (1 / 10 / 216 / 32) are reproduced.
    func testSW3NominalListsAllRequirementsInOrderIncludingUnrenderable() throws {
        let kinds: [UInt32] = [1, 5, 31, 4, 2]
        let f = genericTypeFixture(parameters: [0x80], requirementKinds: kinds)
        let report = f.builder.makeParser(lists: ["__swift5_types": (f.list, 1)]).parseTypesReport()
        let type = try XCTUnwrap(report.types.first)
        let signature = try XCTUnwrap(type.genericSignature)
        let start = f.descriptor + 28 + 16 + 4
        XCTAssertEqual(type.descriptorAddress, f.builder.va(f.descriptor))
        XCTAssertEqual(type.isGeneric, true)
        XCTAssertEqual(signature.requirements.count, kinds.count)
        XCTAssertEqual(signature.requirements.map(\.flags), kinds)
        XCTAssertEqual(signature.requirements.map(\.address),
                       kinds.indices.map { f.builder.va(start + $0 * 12) })
        XCTAssertEqual(signature.requirements.map(\.subjectMangledName), Array(repeating: "x", count: kinds.count))
        XCTAssertEqual(signature.requirements[0].rendered, "A == Int")
        XCTAssertNil(signature.requirements[1].rendered)
        XCTAssertEqual(signature.requirements[1].rawPayload, 0)
        XCTAssertEqual(signature.requirements[1].unresolvedReason, "unverifiedInvertibleProtocolEncoding")
        XCTAssertEqual(signature.requirements[2].rendered, "A: AnyObject")
        XCTAssertEqual(signature.requirements[3].rendered, "sameShape(A, Int)")
        XCTAssertEqual(signature.requirements[4].targetMangledName, "Si")
        let restored = try JSONDecoder().decode(SwiftTypeDescriptor.self,
                                               from: JSONEncoder().encode(type))
        let stored = try XCTUnwrap(restored.genericSignature)
        XCTAssertEqual(stored.requirements.map(\.address), signature.requirements.map(\.address))
        XCTAssertEqual(stored.requirements.map(\.flags), kinds)
        XCTAssertEqual(stored.requirements.map(\.rendered), signature.requirements.map(\.rendered))
        XCTAssertTrue(stored.requirements.allSatisfy { $0.rawPayload == nil })
        XCTAssertTrue(report.diagnostics.isEmpty)
        XCTAssertTrue(report.genericAbstentions.contains { $0.code == .unsupportedGenericMetadata })
        // Direct helper coverage, not a claim that an endpoint is wired.
        let projected = SwiftMetadataFactProjection.genericMetadataReport(types: report.types,
            conformances: [], protocols: [], diagnostics: report.diagnostics)
        guard case .object(let root) = projected, case .array(let types)? = root["types"],
              case .object(let entry)? = types.first,
              case .object(let generic)? = entry["genericSignature"],
              case .array(let requirements)? = generic["requirements"] else {
            return XCTFail("Expected projected nominal signature")
        }
        XCTAssertEqual(types.count, 1)
        XCTAssertEqual(entry["descriptorAddress"], .string("0x" + String(f.builder.va(f.descriptor), radix: 16)))
        XCTAssertEqual(requirements.count, kinds.count)
        for (index, value) in requirements.enumerated() {
            guard case .object(let requirement) = value else { return XCTFail("Expected requirement object") }
            XCTAssertEqual(requirement["address"], .string("0x" + String(f.builder.va(start + index * 12), radix: 16)))
            XCTAssertEqual(requirement["flags"], .int(Int64(kinds[index])))
            XCTAssertEqual(requirement["subjectMangledName"], .string("x"))
            XCTAssertEqual(requirement["rendered"], signature.requirements[index].rendered.map { NavigatorJSONValue.string($0) } ?? .null)
            if index == 1 { XCTAssertEqual(requirement["rendered"], .null) }
        }
    }

    func testSW3KnownEmptyNominalSignatureIsDistinctFromUnreadable() throws {
        let f = genericTypeFixture(parameters: [0x80])
        let known = f.builder.makeParser(lists: ["__swift5_types": (f.list, 1)]).parseTypesReport()
        let type = try XCTUnwrap(known.types.first)
        XCTAssertEqual(try XCTUnwrap(type.genericSignature).requirements, [])
        XCTAssertTrue(known.diagnostics.isEmpty)
        let unknown = f.builder.makeParser(constEnd: f.descriptor + 28 + 15,
                                           lists: ["__swift5_types": (f.list, 1)]).parseTypesReport()
        let unreadable = try XCTUnwrap(unknown.types.first)
        XCTAssertEqual(unreadable.descriptorAddress, type.descriptorAddress)
        XCTAssertEqual(unreadable.isGeneric, true)
        XCTAssertNil(unreadable.genericSignature)
        XCTAssertTrue(unknown.diagnostics.contains { $0.code == .truncatedGenericMetadata })
        let projected = SwiftMetadataFactProjection.genericMetadataReport(types: [type, unreadable],
            conformances: [], protocols: [], diagnostics: unknown.diagnostics)
        guard case .object(let root) = projected, case .array(let entries)? = root["types"],
              entries.count == 2, case .object(let knownEntry) = entries[0],
              case .object(let unknownEntry) = entries[1],
              case .object(let signature)? = knownEntry["genericSignature"] else {
            return XCTFail("Expected known and unknown nominal entries")
        }
        XCTAssertEqual(signature["requirements"], .array([]))
        XCTAssertEqual(unknownEntry["genericSignature"], .null)
        XCTAssertEqual(knownEntry["descriptorAddress"], unknownEntry["descriptorAddress"])
    }

    func testSW3NominalSectionCrossingNeverPublishesPartialRequirements() throws {
        let f = genericTypeFixture(parameters: [0x80], requirementKinds: [1, 31])
        let start = f.descriptor + 28 + 16 + 4
        let boundary = start + 12 // The first requirement is intact; the second is elsewhere.
        let report = f.builder.makeParser(constEnd: boundary,
            lists: ["__swift5_types": (f.list, 1)], extraSections: [
                .init(name: "__adjacent", address: f.builder.va(boundary), fileOffset: UInt64(boundary),
                      size: UInt64(f.list - boundary))
            ]).parseTypesReport()
        let type = try XCTUnwrap(report.types.first)
        XCTAssertEqual(type.descriptorAddress, f.builder.va(f.descriptor))
        XCTAssertNil(type.genericSignature)
        XCTAssertTrue(report.diagnostics.contains { $0.code == .truncatedGenericMetadata })
        var diagnostics: [MetadataParseDiagnostic] = []
        let requirements = f.builder.makeParser(constEnd: boundary).genericRequirements(
            at: f.builder.va(start), count: 2, diagnostics: &diagnostics)
        XCTAssertNil(requirements) // Not [], and not a one-record prefix.
        XCTAssertTrue(diagnostics.contains { $0.code == .truncatedGenericMetadata })
    }

    func testSW3AssociatedNameOccurrencesAndReflectionPopulationsAreSeparate() throws {
        var f = protocolSignatureFixture(signatureCount: 0, requirementCount: 2, names: "Element Element Index")
        // Associated-type-kind count is UNAVAILABLE in the protocol descriptor path.
        // Conformance witness subsets are not this population; no ABI tag is invented.
        for _ in 0..<4 { f.image.appendU32(0) }
        let reflection = f.image.count
        let conforming = f.image.rel(), proto = f.image.rel()
        f.image.appendU32(2); f.image.appendU32(8)
        let name1 = f.image.rel(), type1 = f.image.rel()
        let name2 = f.image.rel(), type2 = f.image.rel()
        let reflectionEnd = f.image.count
        let int = f.image.cstr("Si"), string = f.image.cstr("SS"), element = f.image.cstr("Element")
        f.image.patchRel(conforming, int); f.image.patchRel(proto, string)
        f.image.patchRel(name1, element); f.image.patchRel(type1, int)
        f.image.patchRel(name2, element); f.image.patchRel(type2, string)
        f.image.align(4)
        let list = f.image.rel(); f.image.patchRel(list, f.descriptor)
        let parser = f.image.makeParser(constEnd: reflection,
            lists: ["__swift5_protos": (list, 1)], extraSections: [
                .init(name: "__swift5_assocty", address: f.image.va(reflection),
                      fileOffset: UInt64(reflection), size: UInt64(reflectionEnd - reflection)),
                .init(name: "__swift5_typeref", address: f.image.va(reflectionEnd),
                      fileOffset: UInt64(reflectionEnd), size: UInt64(list - reflectionEnd))
            ])
        let protocols = parser.parseProtocolsReport()
        let descriptor = try XCTUnwrap(protocols.protocols.first)
        let names = try XCTUnwrap(descriptor.associatedTypeNames)
        XCTAssertEqual(names, ["Element", "Element", "Index"])
        XCTAssertEqual(names.count, 3) // (a) Name-entry occurrences, not unique spellings.
        XCTAssertEqual(Set(names).count, 2) // Supplemental spelling statistic, not identity.
        XCTAssertEqual(descriptor.requirementSignature, []) // Signature population is separate.
        let restored = try JSONDecoder().decode(SwiftProtocolDescriptor.self,
                                               from: JSONEncoder().encode(descriptor))
        XCTAssertEqual(restored, descriptor)
        let associated = parser.parseAssociatedTypesReport()
        XCTAssertEqual(associated.records.count, 1) // (c) Reflection descriptor occurrences.
        let record = try XCTUnwrap(associated.records.first)
        XCTAssertEqual(record.descriptorAddress, f.image.va(reflection))
        XCTAssertEqual(record.associatedTypes.count, 2) // (d) Substitution occurrences.
        XCTAssertEqual(record.associatedTypes.map(\.name), ["Element", "Element"])
        XCTAssertEqual(record.associatedTypes.map(\.substitutedTypeName), ["Int", "String"])
        XCTAssertTrue(protocols.diagnostics.isEmpty)
        XCTAssertTrue(associated.diagnostics.isEmpty)
    }

    func testSW3AssociatedNamesKnownEmptyVersusBadPointerAndInvalidUTF8() throws {
        let empty = protocolSignatureFixture(signatureCount: 0, requirementCount: 0, names: nil)
        let known = protocolSignatureReport(empty.image, descriptor: empty.descriptor)
        XCTAssertEqual(try XCTUnwrap(known.protocols.first).associatedTypeNames, [])
        XCTAssertTrue(known.diagnostics.isEmpty)
        var badPointer = empty
        badPointer.image.patchU32(badPointer.descriptor + 20, UInt32(Int32.max))
        let missing = protocolSignatureReport(badPointer.image, descriptor: badPointer.descriptor)
        XCTAssertNil(try XCTUnwrap(missing.protocols.first).associatedTypeNames)
        XCTAssertTrue(missing.diagnostics.contains { $0.code == .unresolvedGenericReference })
        var badUTF8 = protocolSignatureFixture(signatureCount: 0, requirementCount: 0, names: "A")
        badUTF8.image.data[try XCTUnwrap(badUTF8.names)] = 0xff
        let invalid = protocolSignatureReport(badUTF8.image, descriptor: badUTF8.descriptor)
        XCTAssertNil(try XCTUnwrap(invalid.protocols.first).associatedTypeNames)
        XCTAssertTrue(invalid.diagnostics.contains { $0.code == .invalidGenericRequirement })
        var truncated = empty
        truncated.image.patchU32(truncated.descriptor + 12, 1) // Declared signature record is absent.
        let unknownSignature = protocolSignatureReport(truncated.image, descriptor: truncated.descriptor)
        let projected = SwiftMetadataFactProjection.genericMetadataReport(types: [], conformances: [],
            protocols: known.protocols + missing.protocols + invalid.protocols + unknownSignature.protocols,
            diagnostics: missing.diagnostics + invalid.diagnostics + unknownSignature.diagnostics)
        guard case .object(let root) = projected, case .array(let entries)? = root["protocols"],
              entries.count == 4 else { return XCTFail("Expected four parsed protocol states") }
        for (index, value) in entries.enumerated() {
            guard case .object(let entry) = value else { return XCTFail("Expected protocol object") }
            XCTAssertEqual(entry["associatedTypeNames"], index == 0 ? .array([]) : .null)
            XCTAssertEqual(entry["requirementSignature"], index == 3 ? .null : .array([]))
        }
    }

    func testSW3SameNamedProtocolsKeepDescriptorIdentityAndOccurrenceOrder() throws {
        var f = protocolSignatureFixture(signatureCount: 0, requirementCount: 0, names: "Element")
        let second = f.image.count
        let sameName = f.image.cstr("Container")
        f.image.align(4)
        let descriptor2 = f.image.count
        f.image.appendU32(3); f.image.appendU32(0)
        let name = f.image.rel()
        f.image.appendU32(0); f.image.appendU32(0); f.image.appendU32(0)
        f.image.patchRel(name, sameName)
        let list = f.image.count
        let firstEntry = f.image.rel(), secondEntry = f.image.rel(), repeatedEntry = f.image.rel()
        f.image.patchRel(firstEntry, f.descriptor)
        f.image.patchRel(secondEntry, descriptor2)
        f.image.patchRel(repeatedEntry, f.descriptor)
        let report = f.image.makeParser(lists: ["__swift5_protos": (list, 3)]).parseProtocolsReport()
        XCTAssertGreaterThanOrEqual(descriptor2, second)
        XCTAssertEqual(report.protocols.map(\.name), ["Container", "Container", "Container"])
        XCTAssertEqual(report.protocols.map(\.descriptorAddress),
                       [f.image.va(f.descriptor), f.image.va(descriptor2), f.image.va(f.descriptor)])
        XCTAssertEqual(report.protocols.map(\.associatedTypeNames), [["Element"], [], ["Element"]])
        XCTAssertTrue(report.diagnostics.isEmpty)
        // Image identity is supplied by this parser fixture. Do not join another image by name/VA alone.
        let projected = SwiftMetadataFactProjection.genericMetadataReport(types: [], conformances: [],
            protocols: report.protocols, diagnostics: report.diagnostics)
        guard case .object(let root) = projected, case .array(let entries)? = root["protocols"] else {
            return XCTFail("Expected projected protocol occurrences")
        }
        XCTAssertEqual(entries.count, 3)
        for (index, value) in entries.enumerated() {
            guard case .object(let entry) = value else { return XCTFail("Expected protocol object") }
            let address = report.protocols[index].descriptorAddress
            XCTAssertEqual(entry["descriptorAddress"], .string("0x" + String(address, radix: 16)))
            XCTAssertEqual(entry["name"], .string("Container"))
            XCTAssertEqual(entry["requirementSignature"], .array([]))
            XCTAssertEqual(entry["associatedTypeNames"], index == 1 ? .array([]) : .array([.string("Element")]))
        }
    }

    func testOldConformanceAndTypeJSONLeaveGenericFieldsUnknown() throws {
        let conformance = try JSONDecoder().decode(SwiftConformance.self,
            from: Data(#"{"typeName":"Box","protocolName":"P"}"#.utf8))
        XCTAssertNil(conformance.conditionalRequirements)
        XCTAssertNil(conformance.resilientWitnessCount)
        let type = try JSONDecoder().decode(SwiftTypeDescriptor.self,
            from: Data(#"{"kind":"struct","name":"Box","fields":[]}"#.utf8))
        XCTAssertNil(type.genericSignature)
    }

    func testAllRequirementKindsRetainTheirDistinctPayloads() throws {
        for kind in [UInt32(0), 1, 2, 3, 4, 5, 31] {
            var b = GenericImageBuilder()
            let subject = b.cstr("x"), rhs = b.cstr("Si"), protocolName = b.cstr("Equatable")
            b.align(4)
            let proto = b.count
            b.appendU32(3); b.appendU32(0)
            let name = b.rel()
            b.appendU32(0); b.appendU32(0); b.appendU32(0)
            b.patchRel(name, protocolName)
            let targetConformance = b.count
            for _ in 0..<4 { b.appendU32(0) }
            let requirement = b.count
            b.appendU32(kind)
            let param = b.rel(), payload = b.rel()
            b.patchRel(param, subject)
            switch kind {
            case 0: b.patchRel(payload, proto)
            case 1, 2, 4: b.patchRel(payload, rhs)
            case 3: b.patchRel(payload, targetConformance)
            case 5: b.patchU32(payload, 0x0003ffff)
            default: break
            }
            var diagnostics: [MetadataParseDiagnostic] = []
            let values = b.makeParser().genericRequirements(at: b.va(requirement), count: 1,
                                                          diagnostics: &diagnostics)
            let value = try XCTUnwrap(values?.first, "kind \(kind): \(diagnostics)")
            XCTAssertEqual(value.kind?.rawValue, kind)
            XCTAssertEqual(value.subjectMangledName, "x")
            XCTAssertEqual(value.subject, "A") // Existing demangler's positional spelling.
            switch kind {
            case 0: XCTAssertEqual(value.rendered, "A: Equatable")
            case 1: XCTAssertEqual(value.rendered, "A == Int")
            case 2: XCTAssertEqual(value.target, "Int") // Payload decoding, not semantic type checking.
            case 3: XCTAssertEqual(value.conformanceDescriptorAddress, b.va(targetConformance))
            case 4: XCTAssertEqual(value.rendered, "sameShape(A, Int)")
            case 5:
                XCTAssertEqual(value.invertedProtocols, 3)
                XCTAssertEqual(value.genericParameterIndex, 0xffff)
                XCTAssertNil(value.rendered) // Missing bit-to-protocol specification is not guessed.
            default: XCTAssertEqual(value.rendered, "A: AnyObject")
            }
        }
    }

    func testDependentRequirementUsesExistingDemangler() throws {
        var b = GenericImageBuilder()
        let subject = b.cstr("7ElementQz"), rhs = b.cstr("Si")
        b.align(4)
        let requirement = b.count
        b.appendU32(1); let p = b.rel(), t = b.rel()
        b.patchRel(p, subject); b.patchRel(t, rhs)
        var diagnostics: [MetadataParseDiagnostic] = []
        let value = try XCTUnwrap(b.makeParser().genericRequirements(at: b.va(requirement), count: 1,
                                                                   diagnostics: &diagnostics)?.first)
        XCTAssertEqual(value.rendered, "A.Element == Int")
    }

    func testRenderingWithholdsPackAndValueSyntaxUntilSpecified() {
        let scalar = SwiftGenericRequirement(address: 0x1000, flags: 1,
            subjectMangledName: "x", subject: "A", rawPayload: 0,
            targetMangledName: "Si", target: "Int")
        XCTAssertEqual(scalar.rendered, "A == Int")
        for subjectFlags in [UInt32(0x20), 0x100, 0x120] {
            var requirement = scalar
            requirement.flags |= subjectFlags
            XCTAssertNil(requirement.rendered)
            XCTAssertEqual(requirement.subject, "A")
            XCTAssertEqual(requirement.target, "Int")
            XCTAssertEqual(requirement.flags, subjectFlags | 1)
        }
    }

    func testRequirementRejectsTruncatedArrayAndSectionCrossing() {
        var b = GenericImageBuilder()
        let subject = b.cstr("x")
        b.align(4)
        let requirement = b.count
        b.appendU32(31); let p = b.rel(); b.appendU32(0)
        b.patchRel(p, subject)
        for end in [requirement + 4, requirement + 8, requirement + 11] {
            var diagnostics: [MetadataParseDiagnostic] = []
            let parser = b.makeParser(constEnd: end, extraSections: [
                .init(name: "__adjacent", address: b.va(end), fileOffset: UInt64(end),
                      size: UInt64(b.count - end))
            ])
            XCTAssertNil(parser.genericRequirements(at: b.va(requirement), count: 1,
                                                    diagnostics: &diagnostics))
            XCTAssertEqual(diagnostics.last?.code, .truncatedGenericMetadata)
        }
        var diagnostics: [MetadataParseDiagnostic] = []
        XCTAssertNil(b.makeParser().genericRequirements(at: b.va(requirement), count: 65536,
                                                       diagnostics: &diagnostics))
        XCTAssertFalse(diagnostics.isEmpty)
    }

    func testRequirementRejectsBadPointerUnknownKindAndFlags() {
        for flags in [6, 0x40 | 31, 0x200 | 31, 31] as [UInt32] {
            var b = GenericImageBuilder()
            let subject = b.cstr("x"); b.align(4)
            let requirement = b.count
            b.appendU32(flags); let p = b.rel(); b.appendU32(0)
            if flags == 31 { b.patchU32(p, UInt32.max) } else { b.patchRel(p, subject) }
            var diagnostics: [MetadataParseDiagnostic] = []
            XCTAssertNil(b.makeParser().genericRequirements(at: b.va(requirement), count: 1,
                                                           diagnostics: &diagnostics))
            XCTAssertNotNil(diagnostics.first?.code)
        }
    }

    func testRequirementRejectsUnterminatedMangledSubject() {
        var b = GenericImageBuilder()
        let requirement = b.count
        b.appendU32(31); let p = b.rel(); b.appendU32(0)
        let subject = b.count; b.appendU8(120)
        b.patchRel(p, subject)
        var diagnostics: [MetadataParseDiagnostic] = []
        XCTAssertNil(b.makeParser().genericRequirements(at: b.va(requirement), count: 1,
                                                       diagnostics: &diagnostics))
        XCTAssertEqual(diagnostics.last?.code, .invalidGenericRequirement)
    }

    func testRequirementRejectsAmbiguousOrZeroFillFootprint() {
        var b = GenericImageBuilder()
        let subject = b.cstr("x"); b.align(4)
        let requirement = b.count
        b.appendU32(31); let p = b.rel(); b.appendU32(0); b.patchRel(p, subject)
        for zeroFill in [false, true] {
            var diagnostics: [MetadataParseDiagnostic] = []
            let shadow = SwiftMetadataParser.Section(name: "__shadow", address: b.va(requirement + 4),
                fileOffset: UInt64(requirement + 4), size: 4, isZeroFill: zeroFill)
            XCTAssertNil(b.makeParser(extraSections: [shadow]).genericRequirements(
                at: b.va(requirement), count: 1, diagnostics: &diagnostics))
            XCTAssertEqual(diagnostics.last?.code, .truncatedGenericMetadata)
        }
    }

    func testRequirementRejectsOverflowAndPreservesVerifiedEmptyArray() {
        let parser = GenericImageBuilder().makeParser()
        var diagnostics: [MetadataParseDiagnostic] = []
        XCTAssertEqual(parser.genericRequirements(at: 0, count: 0, diagnostics: &diagnostics), [])
        XCTAssertNil(parser.genericRequirements(at: UInt64.max - 3, count: 1,
                                                diagnostics: &diagnostics))
        XCTAssertNil(parser.genericRequirements(at: 0, count: -1, diagnostics: &diagnostics))
        XCTAssertFalse(diagnostics.isEmpty)
    }

    func testRequirementIndirectProtocolNeedsWholePointerSlotAndKnownBind() throws {
        var b = GenericImageBuilder()
        let subject = b.cstr("x"); b.align(4)
        let requirement = b.count
        b.appendU32(0x80); let param = b.rel(), payload = b.rel()
        b.align(8); let slot = b.count; b.appendU64(0)
        b.patchRel(param, subject); b.patchRel(payload, slot, tag: 1)
        var diagnostics: [MetadataParseDiagnostic] = []
        let parser = b.makeParser(binds: [b.va(slot): "_$sSQMp"])
        let value = try XCTUnwrap(parser.genericRequirements(at: b.va(requirement), count: 1,
                                                             diagnostics: &diagnostics)?.first)
        XCTAssertEqual(value.rendered, "A: Equatable")
        XCTAssertTrue(value.hasKeyArgument)
        XCTAssertNil(value.protocolDescriptorAddress)
        diagnostics.removeAll()
        XCTAssertNil(b.makeParser(constEnd: slot + 7, binds: [b.va(slot): "_$sSQMp"])
            .genericRequirements(at: b.va(requirement), count: 1, diagnostics: &diagnostics))
        XCTAssertEqual(diagnostics.last?.code, .unresolvedGenericReference)
    }

    func testRequirementRejectsConflictingPointerFixups() {
        var b = GenericImageBuilder()
        let subject = b.cstr("x"); b.align(4)
        let requirement = b.count
        b.appendU32(0); let param = b.rel(), payload = b.rel()
        b.align(8); let slot = b.count; b.appendU64(0)
        b.patchRel(param, subject); b.patchRel(payload, slot, tag: 1)
        var diagnostics: [MetadataParseDiagnostic] = []
        XCTAssertNil(b.makeParser(rebases: [b.va(slot): b.va(0)], binds: [b.va(slot): "_$sSQMp"])
            .genericRequirements(at: b.va(requirement), count: 1, diagnostics: &diagnostics))
        XCTAssertEqual(diagnostics.last?.code, .unresolvedGenericReference)
    }

    func testRequirementDefersUnverifiedObjectiveCProtocolTag() {
        var b = GenericImageBuilder()
        let subject = b.cstr("x"); b.align(4)
        let requirement = b.count
        b.appendU32(0); let param = b.rel(); b.appendU32(2)
        b.patchRel(param, subject)
        var diagnostics: [MetadataParseDiagnostic] = []
        XCTAssertNil(b.makeParser().genericRequirements(at: b.va(requirement), count: 1,
                                                       diagnostics: &diagnostics))
        XCTAssertEqual(diagnostics.last?.code, .unsupportedGenericMetadata)
    }

    func testNonnullableSameConformanceAllowsZeroSelfDisplacement() throws {
        var b = GenericImageBuilder()
        let subject = b.cstr("x"); b.align(4)
        let requirement = b.count
        b.appendU32(3); let param = b.rel(), payload = b.rel()
        for _ in 0..<3 { b.appendU32(0) }
        b.patchRel(param, subject)
        var diagnostics: [MetadataParseDiagnostic] = []
        let value = try XCTUnwrap(b.makeParser().genericRequirements(at: b.va(requirement), count: 1,
                                                                   diagnostics: &diagnostics)?.first)
        XCTAssertEqual(value.conformanceDescriptorAddress, b.va(payload))
    }

    func testRequirementProtocolRejectsInvalidUTF8Name() {
        var b = GenericImageBuilder()
        let subject = b.cstr("x"), invalidName = b.count
        b.appendU8(0xff); b.appendU8(0); b.align(4)
        let proto = b.count
        b.appendU32(3); b.appendU32(0); let n = b.rel()
        b.appendU32(0); b.appendU32(0); b.appendU32(0); b.patchRel(n, invalidName)
        let requirement = b.count
        b.appendU32(0); let param = b.rel(), payload = b.rel()
        b.patchRel(param, subject); b.patchRel(payload, proto)
        var diagnostics: [MetadataParseDiagnostic] = []
        XCTAssertNil(b.makeParser().genericRequirements(at: b.va(requirement), count: 1,
                                                       diagnostics: &diagnostics))
        XCTAssertEqual(diagnostics.last?.code, .unresolvedGenericReference)
    }

    func testRequirementSymbolicNamePreservesItsEmbeddedZeroBytes() throws {
        var b = GenericImageBuilder()
        let moduleName = b.cstr("Fixture"), typeName = b.cstr("Value")
        let rhs = b.count
        b.appendU8(1); let symbolic = b.rel(); b.appendU8(0)
        b.align(4)
        let module = b.count
        b.appendU32(0); b.appendU32(0); let mn = b.rel(); b.patchRel(mn, moduleName)
        let type = b.count
        b.appendU32(17); let parent = b.rel(), tn = b.rel()
        for _ in 0..<4 { b.appendU32(0) }
        b.patchRel(parent, module); b.patchRel(tn, typeName)
        let subject = b.cstr("x")
        b.patchRel(symbolic, type)
        b.align(4)
        let requirement = b.count
        b.appendU32(1); let p = b.rel(), t = b.rel()
        b.patchRel(p, subject); b.patchRel(t, rhs)
        var diagnostics: [MetadataParseDiagnostic] = []
        let value = try XCTUnwrap(b.makeParser().genericRequirements(at: b.va(requirement), count: 1,
                                                                   diagnostics: &diagnostics)?.first)
        XCTAssertEqual(value.target, "Fixture.Value")
        XCTAssertEqual(value.targetMangledBytes?.count, 5)
        XCTAssertEqual(value.targetMangledBytes?.first, 1)
        XCTAssertTrue(value.targetMangledBytes?.dropFirst().contains(0) == true)
        XCTAssertEqual(value.rendered, "A == Fixture.Value")
    }

    func testRequirementIndirectSlotsMustBePointerAligned() {
        for kind in [UInt32(0), 3] {
            var b = GenericImageBuilder()
            let subject = b.cstr("x"); b.align(4)
            let requirement = b.count
            b.appendU32(kind); let param = b.rel(), payload = b.rel()
            b.appendU32(0)
            let slot = b.count; b.appendU64(0)
            let target = b.count
            for _ in 0..<4 { b.appendU32(0) }
            b.patchRel(param, subject); b.patchRel(payload, slot, tag: 1)
            var diagnostics: [MetadataParseDiagnostic] = []
            let parser = b.makeParser(rebases: kind == 3 ? [b.va(slot): b.va(target)] : [:],
                                      binds: kind == 0 ? [b.va(slot): "_$sSQMp"] : [:])
            XCTAssertNil(parser.genericRequirements(at: b.va(requirement), count: 1,
                                                    diagnostics: &diagnostics))
            XCTAssertEqual(diagnostics.last?.code, .unresolvedGenericReference)
        }
    }

    func testRequirementTargetMisalignmentHasTypedDiagnostic() {
        var b = GenericImageBuilder()
        b.appendU16(0); let target = b.count
        for _ in 0..<4 { b.appendU32(0) }
        let subject = b.cstr("x"); b.align(4)
        let requirement = b.count
        b.appendU32(3); let param = b.rel(), payload = b.rel()
        b.patchRel(param, subject); b.patchRel(payload, target)
        var diagnostics: [MetadataParseDiagnostic] = []
        XCTAssertNil(b.makeParser().genericRequirements(at: b.va(requirement), count: 1,
                                                       diagnostics: &diagnostics))
        XCTAssertEqual(diagnostics.last?.code, .unresolvedGenericReference)
    }

    // CP21-CONDITIONAL-TESTS

    func testConditionalRequirementsRespectRetroactivePrefix() throws {
        var fixture = conditionalFixture(flags: 0x40 | (1 << 8))
        let retroactive = fixture.image.rel()
        fixture.image.patchRel(retroactive, fixture.typeDescriptor)
        fixture.image.appendU32(1)
        let subject = fixture.image.rel()
        let rhs = fixture.image.rel()
        fixture.image.patchRel(subject, fixture.subject)
        fixture.image.patchRel(rhs, fixture.rhs)
        let result = conditionalReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        let requirements = try XCTUnwrap(conformance.conditionalRequirements)
        XCTAssertEqual(requirements.count, 1)
        XCTAssertEqual(requirements.first?.flags, 1)
        XCTAssertEqual(requirements.first?.subjectMangledName, "x")
        XCTAssertEqual(requirements.first?.targetMangledName, "Si")
        XCTAssertEqual(conformance.retroactiveContextAddress, fixture.image.va(fixture.typeDescriptor))
        XCTAssertEqual(conformance.conditionalPackShapes, [])
        XCTAssertTrue(result.diagnostics.isEmpty)
    }

    func testPlainConformanceHasVerifiedEmptyRequirements() throws {
        let fixture = conditionalFixture(flags: 0)
        let result = conditionalReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertEqual(conformance.conditionalRequirements, [])
        XCTAssertEqual(conformance.conditionalPackShapes, [])
        XCTAssertTrue(result.diagnostics.isEmpty)
    }

    func testConditionalRequirementsRejectTruncatedRecord() throws {
        var fixture = conditionalFixture(flags: 1 << 8)
        fixture.image.appendU32(1)
        let subject = fixture.image.rel()
        fixture.image.patchRel(subject, fixture.subject)
        let result = conditionalReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertNil(conformance.conditionalRequirements)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .invalidConformanceTail })
    }

    func testConditionalRequirementsRejectBadSubjectPointer() throws {
        var fixture = conditionalFixture(flags: 1 << 8)
        fixture.image.appendU32(1)
        fixture.image.appendU32(UInt32(bitPattern: Int32.max))
        let rhs = fixture.image.rel()
        fixture.image.patchRel(rhs, fixture.rhs)
        let result = conditionalReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertNil(conformance.conditionalRequirements)
        XCTAssertFalse(result.diagnostics.isEmpty)
    }

    func testConditionalPackDescriptorsHaveNoHeader() throws {
        var fixture = conditionalFixture(flags: (1 << 8) | (1 << 24))
        fixture.image.appendU32(0xa0)
        let subject = fixture.image.rel()
        let proto = fixture.image.rel()
        fixture.image.patchRel(subject, fixture.subject)
        fixture.image.patchRel(proto, fixture.protocolDescriptor)
        fixture.image.appendU16(1)
        fixture.image.appendU16(0)
        fixture.image.appendU16(3)
        fixture.image.appendU16(0)
        let result = conditionalReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertEqual(conformance.conditionalRequirements?.count, 1)
        XCTAssertEqual(conformance.conditionalPackShapes,
                       [.init(kind: 1, index: 0, shapeClass: 3, unused: 0)])
        XCTAssertTrue(result.diagnostics.isEmpty)
    }

    func testConditionalPackDescriptorRejectsReservedField() throws {
        var fixture = conditionalFixture(flags: 1 << 24)
        fixture.image.appendU16(1)
        fixture.image.appendU16(0)
        fixture.image.appendU16(0)
        fixture.image.appendU16(1)
        let result = conditionalReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertNil(conformance.conditionalPackShapes)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .invalidPackShape })
    }

    func testConditionalRequirementsRejectAdjacentSectionTail() throws {
        var fixture = conditionalFixture(flags: 1 << 8)
        fixture.image.appendU32(1)
        let subject = fixture.image.rel()
        let rhs = fixture.image.rel()
        fixture.image.patchRel(subject, fixture.subject)
        fixture.image.patchRel(rhs, fixture.rhs)
        let boundary = fixture.descriptor + 20
        let tail = SwiftMetadataParser.Section(name: "__adjacent", address: fixture.image.va(boundary),
                                               fileOffset: UInt64(boundary), size: 8)
        let list = fixture.image.rel()
        fixture.image.patchRel(list, fixture.descriptor)
        let result = fixture.image.makeParser(constEnd: boundary,
                                               lists: ["__swift5_proto": (offset: list, count: 1)],
                                               extraSections: [tail]).parseConformancesReport()
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertNil(conformance.conditionalRequirements)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .invalidConformanceTail })
    }

    func testRetroactiveRawPointerSlotNeedsRebaseEvidence() throws {
        var fixture = conditionalFixture(flags: 0x40)
        let retroactive = fixture.image.rel()
        fixture.image.align(8)
        let slot = fixture.image.count
        fixture.image.appendU64(fixture.image.va(fixture.typeDescriptor))
        fixture.image.patchRel(retroactive, slot, tag: 1)
        let result = conditionalReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertNil(conformance.retroactiveContextAddress)
        XCTAssertEqual(conformance.conditionalRequirements, [])
        XCTAssertTrue(result.diagnostics.contains { $0.code == .unresolvedGenericReference })
    }

    func testRetroactiveNonzeroDisplacementCanResolveMappedAddressZero() throws {
        var fixture = conditionalFixture(flags: 0x40, atZero: true)
        let retroactive = fixture.image.rel()
        fixture.image.patchRel(retroactive, 0)
        let result = conditionalReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertEqual(conformance.retroactiveContextAddress, 0)
        XCTAssertTrue(result.diagnostics.isEmpty)
    }

    func testConditionalTailRejectsMisalignedConformanceDescriptor() throws {
        var fixture = conditionalFixture(flags: 0)
        fixture.image.base += 1
        let result = conditionalReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertNil(conformance.conditionalRequirements)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .invalidConformanceTail })
    }

    private func conditionalFixture(flags: UInt32, atZero: Bool = false) ->
        (image: GenericImageBuilder, descriptor: Int, protocolDescriptor: Int,
         typeDescriptor: Int, subject: Int, rhs: Int) {
        var image = GenericImageBuilder()
        if atZero {
            image.base = 0
            image.appendU32(2)
            image.appendU32(0)
        }
        let protocolName = image.cstr("P")
        let typeName = image.cstr("Box")
        let subject = image.cstr("x")
        let rhs = image.cstr("Si")
        image.align(4)
        let proto = image.count
        image.appendU32(3)
        image.appendU32(0)
        let protocolNameField = image.rel()
        image.appendU32(0)
        image.appendU32(0)
        image.appendU32(0)
        image.patchRel(protocolNameField, protocolName)
        let type = image.count
        image.appendU32(17)
        image.appendU32(0)
        let typeNameField = image.rel()
        for _ in 0..<4 { image.appendU32(0) }
        image.patchRel(typeNameField, typeName)
        let descriptor = image.count
        let protocolReference = image.rel()
        let typeReference = image.rel()
        image.appendU32(0)
        image.appendU32(flags)
        image.patchRel(protocolReference, proto)
        image.patchRel(typeReference, type)
        return (image, descriptor, proto, type, subject, rhs)
    }

    private func conditionalReport(_ source: GenericImageBuilder, descriptor: Int) ->
        (conformances: [SwiftConformance], diagnostics: [MetadataParseDiagnostic],
         genericAbstentions: [MetadataParseDiagnostic], genericDiagnosticsDropped: Int) {
        var image = source
        let list = image.rel()
        image.patchRel(list, descriptor)
        return image.makeParser(constEnd: list,
                                lists: ["__swift5_proto": (offset: list, count: 1)]).parseConformancesReport()
    }

    // CP21-WITNESS-TESTS

    func testWitnessTailsFollowRetroactiveRequirementsAndPacks() throws {
        var fixture = witnessesFixture(flags: 0x40 | (1 << 8) | (1 << 24) | (1 << 16) | (1 << 17))
        let retroactive = fixture.image.rel()
        fixture.image.patchRel(retroactive, fixture.typeDescriptor)
        fixture.image.appendU32(0xa0)
        let subject = fixture.image.rel()
        let proto = fixture.image.rel()
        fixture.image.patchRel(subject, fixture.subject)
        fixture.image.patchRel(proto, fixture.protocolDescriptor)
        fixture.image.appendU16(1)
        fixture.image.appendU16(0)
        fixture.image.appendU16(0)
        fixture.image.appendU16(0)
        fixture.image.appendU32(2)
        for _ in 0..<4 { fixture.image.appendU32(0) }
        fixture.image.appendU16(5)
        fixture.image.appendU16(7)
        let instantiator = fixture.image.rel()
        let cache = fixture.image.rel()
        fixture.image.patchRel(instantiator, fixture.code)
        fixture.image.patchRel(cache, fixture.cache)
        let result = witnessesReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertEqual(conformance.resilientWitnessCount, 2)
        let table = try XCTUnwrap(conformance.genericWitnessTable)
        XCTAssertEqual(table.witnessTableSizeInWords, 5)
        XCTAssertEqual(table.privateSizeAndFlags, 7)
        XCTAssertNil(table.instantiatorAddress)
        XCTAssertEqual(table.instantiatorRawValue, UInt32(bitPattern: Int32(fixture.code - instantiator)))
        XCTAssertEqual(table.privateDataAddress, fixture.image.va(fixture.cache))
        XCTAssertTrue(result.diagnostics.isEmpty)
        XCTAssertEqual(result.genericAbstentions.map(\.code), [.unsupportedGenericMetadata])
    }

    func testAbsentWitnessTailHasVerifiedZeroCount() throws {
        let fixture = witnessesFixture(flags: 0)
        let result = witnessesReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertEqual(conformance.resilientWitnessCount, 0)
        XCTAssertNil(conformance.genericWitnessTable)
        XCTAssertTrue(result.diagnostics.isEmpty)
    }

    func testResilientWitnessCountRequiresAllRecords() throws {
        var fixture = witnessesFixture(flags: 1 << 16)
        fixture.image.appendU32(2)
        fixture.image.appendU32(0)
        fixture.image.appendU32(0)
        let result = witnessesReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertNil(conformance.resilientWitnessCount)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .invalidConformanceTail })
    }

    func testResilientWitnessRejectsExcessiveCount() throws {
        var fixture = witnessesFixture(flags: 1 << 16)
        fixture.image.appendU32(UInt32.max)
        let result = witnessesReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertNil(conformance.resilientWitnessCount)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .invalidConformanceTail })
    }

    func testResilientWitnessBadPointerIsDiagnosedWithoutLosingCount() throws {
        var fixture = witnessesFixture(flags: 1 << 16)
        fixture.image.appendU32(1)
        fixture.image.appendU32(UInt32(bitPattern: Int32.max))
        fixture.image.appendU32(0)
        let result = witnessesReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertEqual(conformance.resilientWitnessCount, 1)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .unresolvedGenericReference })
    }

    func testResilientWitnessRawPointerSlotNeedsRebaseEvidence() throws {
        var fixture = witnessesFixture(flags: 1 << 16)
        fixture.image.appendU32(1)
        let requirement = fixture.image.rel()
        fixture.image.appendU32(0)
        fixture.image.align(8)
        let slot = fixture.image.count
        fixture.image.appendU64(fixture.image.va(fixture.protocolDescriptor))
        fixture.image.patchRel(requirement, slot, tag: 1)
        let result = witnessesReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertEqual(conformance.resilientWitnessCount, 1)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .unresolvedGenericReference })
    }

    func testResilientImplementationWordStaysOpaqueWithoutTargetEncoding() throws {
        var fixture = witnessesFixture(flags: 1 << 16)
        fixture.image.appendU32(1)
        fixture.image.appendU32(0)
        fixture.image.appendU32(0xffff_fffc)
        let result = witnessesReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertEqual(conformance.resilientWitnessCount, 1)
        XCTAssertTrue(result.diagnostics.isEmpty)
        XCTAssertTrue(result.genericAbstentions.contains { $0.code == .unsupportedGenericMetadata })
    }

    func testGenericWitnessTableRequiresCompleteControlRecord() throws {
        var fixture = witnessesFixture(flags: 1 << 17)
        fixture.image.appendU16(4)
        fixture.image.appendU16(1)
        fixture.image.appendU32(0)
        let result = witnessesReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertNil(conformance.genericWitnessTable)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .invalidConformanceTail })
    }

    func testGenericWitnessCacheMayBeMappedZeroFillStorage() throws {
        var fixture = witnessesFixture(flags: 1 << 17)
        fixture.image.appendU16(4)
        fixture.image.appendU16(3)
        fixture.image.appendU32(0)
        let cacheField = fixture.image.rel()
        let cacheOffset = 0xf000
        fixture.image.patchRel(cacheField, cacheOffset)
        let list = fixture.image.rel()
        fixture.image.patchRel(list, fixture.descriptor)
        let cacheSection = SwiftMetadataParser.Section(name: "__bss", address: fixture.image.va(cacheOffset),
                                                       fileOffset: 0, size: 128, isZeroFill: true)
        let result = fixture.image.makeParser(constEnd: list,
                                               lists: ["__swift5_proto": (offset: list, count: 1)],
                                               extraSections: [cacheSection]).parseConformancesReport()
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertEqual(conformance.genericWitnessTable?.privateDataAddress, fixture.image.va(cacheOffset))
        XCTAssertTrue(result.diagnostics.isEmpty)
    }

    func testResilientWitnessCannotCrossAdjacentSection() throws {
        var fixture = witnessesFixture(flags: 1 << 16)
        fixture.image.appendU32(1)
        fixture.image.appendU32(0)
        fixture.image.appendU32(0)
        let boundary = fixture.descriptor + 24
        let tail = SwiftMetadataParser.Section(name: "__adjacent", address: fixture.image.va(boundary),
                                               fileOffset: UInt64(boundary), size: 4)
        let list = fixture.image.rel()
        fixture.image.patchRel(list, fixture.descriptor)
        let result = fixture.image.makeParser(constEnd: boundary,
                                               lists: ["__swift5_proto": (offset: list, count: 1)],
                                               extraSections: [tail]).parseConformancesReport()
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertNil(conformance.resilientWitnessCount)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .invalidConformanceTail })
    }

    func testGlobalActorTailIsBoundedWithoutInventedSemanticDecode() throws {
        var fixture = witnessesFixture(flags: 1 << 19)
        fixture.image.appendU32(0); fixture.image.appendU32(0)
        let result = witnessesReport(fixture.image, descriptor: fixture.descriptor)
        let conformance = try XCTUnwrap(result.conformances.first)
        XCTAssertEqual(conformance.resilientWitnessCount, 0)
        XCTAssertTrue(result.diagnostics.isEmpty)
        XCTAssertTrue(result.genericAbstentions.contains { $0.code == .unsupportedGenericMetadata })
        fixture.image.data.removeLast(4)
        let truncated = witnessesReport(fixture.image, descriptor: fixture.descriptor)
        XCTAssertTrue(truncated.diagnostics.contains { $0.code == .invalidConformanceTail })
    }

    private func witnessesFixture(flags: UInt32) ->
        (image: GenericImageBuilder, descriptor: Int, protocolDescriptor: Int,
         typeDescriptor: Int, subject: Int, code: Int, cache: Int) {
        var image = GenericImageBuilder()
        let protocolName = image.cstr("P")
        let typeName = image.cstr("Box")
        let subject = image.cstr("x")
        let code = image.count
        image.appendU8(0xc3)
        image.align(8)
        let cache = image.count
        for _ in 0..<16 { image.appendU64(0) }
        let proto = image.count
        image.appendU32(3)
        image.appendU32(0)
        let protocolNameField = image.rel()
        image.appendU32(0)
        image.appendU32(0)
        image.appendU32(0)
        image.patchRel(protocolNameField, protocolName)
        let type = image.count
        image.appendU32(17)
        image.appendU32(0)
        let typeNameField = image.rel()
        for _ in 0..<4 { image.appendU32(0) }
        image.patchRel(typeNameField, typeName)
        let descriptor = image.count
        let protocolReference = image.rel()
        let typeReference = image.rel()
        image.appendU32(0)
        image.appendU32(flags)
        image.patchRel(protocolReference, proto)
        image.patchRel(typeReference, type)
        return (image, descriptor, proto, type, subject, code, cache)
    }

    private func witnessesReport(_ source: GenericImageBuilder, descriptor: Int) ->
        (conformances: [SwiftConformance], diagnostics: [MetadataParseDiagnostic],
         genericAbstentions: [MetadataParseDiagnostic], genericDiagnosticsDropped: Int) {
        var image = source
        let list = image.rel()
        image.patchRel(list, descriptor)
        return image.makeParser(constEnd: list,
                                lists: ["__swift5_proto": (offset: list, count: 1)]).parseConformancesReport()
    }

    // CP21-NOMINAL-TESTS

    func testNominalGenericHeadersCoverAllKindsAndParameterKeyPatterns() throws {
        for kind in [UInt32(16), 17, 18] {
            for count in 0...4 {
                for keys in 0..<(1 << count) {
                    let parameters = (0..<count).map { UInt8(keys & (1 << $0) == 0 ? 0 : 0x80) }
                    let f = genericTypeFixture(kind: kind, parameters: parameters)
                    let report = f.builder.makeParser(lists: ["__swift5_types": (f.list, 1)]).parseTypesReport()
                    let signature = try XCTUnwrap(report.types.first?.genericSignature, "\(report.diagnostics)")
                    XCTAssertEqual(signature.parameters.map(\.rawValue), parameters)
                    XCTAssertEqual(signature.numKeyArguments, UInt16(keys.nonzeroBitCount))
                    XCTAssertEqual(signature.requirements, [])
                    XCTAssertEqual(signature.headerAddress, f.builder.va(f.descriptor + (kind == 16 ? 44 : 28)))
                }
            }
        }
    }

    func testNonKeyParameterRetainsSameTypeRequirement() throws {
        let f = genericTypeFixture(parameters: [0], requirementKinds: [1])
        let type = try XCTUnwrap(f.builder.makeParser(lists: ["__swift5_types": (f.list, 1)]).parseTypes().first)
        XCTAssertEqual(type.genericSignature?.parameters.first?.hasKeyArgument, false)
        XCTAssertEqual(type.genericSignature?.requirements.first?.rendered, "A == Int")
    }

    func testPackHeaderAndDescriptorsFollowAlignedRequirements() throws {
        var tail = GenericImageBuilder()
        tail.appendU16(1); tail.appendU16(1)
        tail.appendU16(0); tail.appendU16(1); tail.appendU16(0); tail.appendU16(0)
        let f = genericTypeFixture(parameters: [0x81], flags: 1, keys: 2, tail: tail.data)
        let report = f.builder.makeParser(lists: ["__swift5_types": (f.list, 1)]).parseTypesReport()
        let signature = try XCTUnwrap(report.types.first?.genericSignature, "\(report.diagnostics)")
        XCTAssertEqual(signature.numShapeClasses, 1)
        XCTAssertEqual(signature.packShapes, [.init(kind: 0, index: 1, shapeClass: 0, unused: 0)])
    }

    func testPackReaderRejectsCountShapeAndIndexMismatches() {
        for payload in [
            [UInt16(2), 1, 0, 1, 0, 0], // Count exceeds the one available descriptor.
            [1, 1, 0, 1, 1, 0],        // ShapeClass is not less than NumShapeClasses.
            [1, 1, 0, 2, 0, 0],        // Index is not less than NumKeyArguments.
            [1, 1, 0, 0, 0, 0],        // Index addresses a shape-length word, not a metadata pack.
            [1, 1, 1, 1, 0, 0]         // Metadata parameter needs a metadata descriptor.
        ] {
            var tail = GenericImageBuilder()
            payload.forEach { tail.appendU16($0) }
            let f = genericTypeFixture(parameters: [0x81], flags: 1, keys: 2, tail: tail.data)
            let report = f.builder.makeParser(lists: ["__swift5_types": (f.list, 1)]).parseTypesReport()
            XCTAssertNil(report.types.first?.genericSignature)
            XCTAssertNotNil(report.diagnostics.last?.code)
        }
    }

    func testInvertibleTailAbstainsWhenItsSetStorageIsUnspecified() {
        let f = genericTypeFixture(parameters: [0x80], flags: 2, tail: [3, 0, 0, 0, 0, 0, 0, 0])
        let report = f.builder.makeParser(lists: ["__swift5_types": (f.list, 1)]).parseTypesReport()
        XCTAssertNil(report.types.first?.genericSignature)
        XCTAssertTrue(report.diagnostics.isEmpty)
        XCTAssertEqual(report.genericAbstentions.last?.code, .unsupportedGenericMetadata)
    }

    func testValueDescriptorsRetainTheSpecifiedIntegerKind() throws {
        var tail = GenericImageBuilder()
        tail.appendU32(1); tail.appendU32(0)
        let f = genericTypeFixture(parameters: [0x82], flags: 4, tail: tail.data)
        let report = f.builder.makeParser(lists: ["__swift5_types": (f.list, 1)]).parseTypesReport()
        XCTAssertEqual(try XCTUnwrap(report.types.first?.genericSignature).valueTypes, [0])
        XCTAssertTrue(report.diagnostics.isEmpty)
    }

    func testValueReaderRejectsTruncationCountMismatchAndUnknownKind() {
        for values in [[UInt32(1)], [2, 0], [1, 1]] {
            var tail = GenericImageBuilder()
            values.forEach { tail.appendU32($0) }
            let f = genericTypeFixture(parameters: [0x82], flags: 4, tail: tail.data)
            let report = f.builder.makeParser(lists: ["__swift5_types": (f.list, 1)]).parseTypesReport()
            XCTAssertNil(report.types.first?.genericSignature)
            XCTAssertNotNil(report.diagnostics.last?.code)
        }
    }

    func testGenericHeaderFlagsAndScalarKeyCountMustMatchDescriptors() {
        for f in [
            genericTypeFixture(parameters: [0x80], keys: 0),
            genericTypeFixture(parameters: [], flags: 1, tail: [0, 0, 0, 0]),
            genericTypeFixture(parameters: [], flags: 4, tail: [0, 0, 0, 0]),
            genericTypeFixture(parameters: [0x82]),
            genericTypeFixture(parameters: [0x81])
        ] {
            let report = f.builder.makeParser(lists: ["__swift5_types": (f.list, 1)]).parseTypesReport()
            XCTAssertNil(report.types.first?.genericSignature)
            XCTAssertNotNil(report.diagnostics.last?.code)
        }
    }

    func testNominalGenericReaderRejectsTruncationsAndOversizedCounts() {
        var f = genericTypeFixture(parameters: [0x80], requirementKinds: [31])
        let header = f.descriptor + 28
        for end in [header, header + 4, header + 8, header + 15, header + 16, f.list - 1] {
            let report = f.builder.makeParser(constEnd: end, lists: ["__swift5_types": (f.list, 1)])
                .parseTypesReport()
            XCTAssertNil(report.types.first?.genericSignature)
            XCTAssertNotNil(report.diagnostics.last?.code)
        }
        f.builder.patchU32(header + 8, 0xffffffff)
        let report = f.builder.makeParser(lists: ["__swift5_types": (f.list, 1)]).parseTypesReport()
        XCTAssertNil(report.types.first?.genericSignature)
        XCTAssertNotNil(report.diagnostics.last?.code)
    }

    func testNominalGenericReaderRejectsBadRequirementPointerAndFutureFlags() {
        var f = genericTypeFixture(parameters: [0x80], requirementKinds: [31])
        let requirement = f.descriptor + 28 + 16 + 4
        f.builder.patchU32(requirement + 4, 0x80000000)
        var report = f.builder.makeParser(lists: ["__swift5_types": (f.list, 1)]).parseTypesReport()
        XCTAssertNil(report.types.first?.genericSignature)
        XCTAssertNotNil(report.diagnostics.last?.code)
        f = genericTypeFixture(parameters: [0x80], flags: 8)
        report = f.builder.makeParser(lists: ["__swift5_types": (f.list, 1)]).parseTypesReport()
        XCTAssertNil(report.types.first?.genericSignature)
        XCTAssertEqual(report.diagnostics.last?.code, .unsupportedGenericMetadata)
    }

    private func genericTypeFixture(kind: UInt32 = 17, parameters: [UInt8],
                                    requirementKinds: [UInt32] = [], flags: UInt16 = 0,
                                    keys: UInt16? = nil, tail: [UInt8] = [])
        -> (builder: GenericImageBuilder, descriptor: Int, list: Int) {
        var b = GenericImageBuilder()
        let name = b.cstr("Box"), subject = b.cstr("x"), target = b.cstr("Si")
        b.align(4)
        let descriptor = b.count
        b.appendU32(kind | 0x80); b.appendU32(0); let n = b.rel()
        let fixedSize = kind == 16 ? 44 : 28
        for _ in stride(from: 12, to: fixedSize, by: 4) { b.appendU32(0) }
        b.patchRel(n, name)
        b.appendU32(0); b.appendU32(0)
        b.appendU16(UInt16(parameters.count)); b.appendU16(UInt16(requirementKinds.count))
        b.appendU16(keys ?? UInt16(parameters.filter { $0 & 0x80 != 0 }.count)); b.appendU16(flags)
        parameters.forEach { b.appendU8($0) }
        b.align(4)
        for kind in requirementKinds {
            b.appendU32(kind); let p = b.rel(), t = b.rel()
            b.patchRel(p, subject)
            if [UInt32(1), 2, 4].contains(kind) { b.patchRel(t, target) }
        }
        b.data += tail
        let list = b.count; let entry = b.rel(); b.patchRel(entry, descriptor)
        return (b, descriptor, list)
    }

    // CP21-PROTOCOL-TESTS

    func testProtocolSignatureAndAssociatedNamesHaveDistinctCounts() throws {
        var fixture = protocolSignatureFixture(signatureCount: 1, requirementCount: 2,
                                               names: "Element Index")
        fixture.image.appendU32(0x1f)
        let subject = fixture.image.rel()
        fixture.image.appendU32(0)
        fixture.image.patchRel(subject, fixture.subject)
        for _ in 0..<2 {
            fixture.image.appendU32(7)
            fixture.image.appendU32(0)
        }
        let result = protocolSignatureReport(fixture.image, descriptor: fixture.descriptor)
        let proto = try XCTUnwrap(result.protocols.first)
        XCTAssertEqual(proto.requirementSignature?.count, 1)
        XCTAssertEqual(proto.requirementSignature?.first?.flags, 0x1f)
        XCTAssertEqual(proto.associatedTypeNames, ["Element", "Index"])
        XCTAssertTrue(result.diagnostics.isEmpty)
    }

    func testProtocolNullAssociatedNamesMeansEncodedEmptyList() throws {
        let fixture = protocolSignatureFixture(signatureCount: 0, requirementCount: 0, names: nil)
        let result = protocolSignatureReport(fixture.image, descriptor: fixture.descriptor)
        let proto = try XCTUnwrap(result.protocols.first)
        XCTAssertEqual(proto.requirementSignature, [])
        XCTAssertEqual(proto.associatedTypeNames, [])
        XCTAssertTrue(result.diagnostics.isEmpty)
    }

    func testProtocolSignatureRejectsTruncatedRequirementArray() throws {
        var fixture = protocolSignatureFixture(signatureCount: 1, requirementCount: 0, names: nil)
        fixture.image.appendU32(0x1f)
        let subject = fixture.image.rel()
        fixture.image.patchRel(subject, fixture.subject)
        let result = protocolSignatureReport(fixture.image, descriptor: fixture.descriptor)
        let proto = try XCTUnwrap(result.protocols.first)
        XCTAssertNil(proto.requirementSignature)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .truncatedGenericMetadata })
    }

    func testProtocolRequirementCountsCannotPassSectionEnd() throws {
        let fixture = protocolSignatureFixture(signatureCount: UInt32.max, requirementCount: 0, names: nil)
        let result = protocolSignatureReport(fixture.image, descriptor: fixture.descriptor)
        let proto = try XCTUnwrap(result.protocols.first)
        XCTAssertNil(proto.requirementSignature)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .invalidGenericRequirement })
    }

    func testProtocolSignatureRejectsUnsupportedContextFlags() throws {
        var fixture = protocolSignatureFixture(signatureCount: 0, requirementCount: 0, names: nil)
        fixture.image.data[fixture.descriptor + 1] = 1
        let result = protocolSignatureReport(fixture.image, descriptor: fixture.descriptor)
        let proto = try XCTUnwrap(result.protocols.first)
        XCTAssertNil(proto.requirementSignature)
        XCTAssertNil(proto.associatedTypeNames)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .unsupportedGenericMetadata })
    }

    func testProtocolSignatureRejectsMisalignedDescriptor() throws {
        var fixture = protocolSignatureFixture(signatureCount: 0, requirementCount: 0, names: nil)
        fixture.image.base += 1
        let result = protocolSignatureReport(fixture.image, descriptor: fixture.descriptor)
        let proto = try XCTUnwrap(result.protocols.first)
        XCTAssertNil(proto.requirementSignature)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .invalidGenericRequirement })
    }

    func testProtocolAssociatedNamesRejectBadRelativePointer() throws {
        var fixture = protocolSignatureFixture(signatureCount: 0, requirementCount: 0, names: nil)
        let field = fixture.descriptor + 20
        for byte in 0..<4 {
            fixture.image.data[field + byte] = UInt8(truncatingIfNeeded: UInt32(bitPattern: Int32.max) >> (byte * 8))
        }
        let result = protocolSignatureReport(fixture.image, descriptor: fixture.descriptor)
        let proto = try XCTUnwrap(result.protocols.first)
        XCTAssertNil(proto.associatedTypeNames)
        XCTAssertFalse(result.diagnostics.isEmpty)
    }

    func testProtocolAssociatedNamesRejectInvalidUTF8() throws {
        var fixture = protocolSignatureFixture(signatureCount: 0, requirementCount: 0, names: "A")
        let names = try XCTUnwrap(fixture.names)
        fixture.image.data[names] = 0xff
        let result = protocolSignatureReport(fixture.image, descriptor: fixture.descriptor)
        let proto = try XCTUnwrap(result.protocols.first)
        XCTAssertNil(proto.associatedTypeNames)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .invalidGenericRequirement })
    }

    func testProtocolAssociatedNamesCannotCrossAdjacentSection() throws {
        var fixture = protocolSignatureFixture(signatureCount: 0, requirementCount: 0, names: nil)
        let names = fixture.image.count
        fixture.image.appendU8(65)
        fixture.image.appendU8(0)
        fixture.image.patchRel(fixture.descriptor + 20, names)
        let boundary = names + 1
        let terminator = SwiftMetadataParser.Section(name: "__adjacent", address: fixture.image.va(boundary),
                                                     fileOffset: UInt64(boundary), size: 1)
        fixture.image.align(4)
        let list = fixture.image.rel()
        fixture.image.patchRel(list, fixture.descriptor)
        let result = fixture.image.makeParser(constEnd: boundary,
                                               lists: ["__swift5_protos": (offset: list, count: 1)],
                                               extraSections: [terminator]).parseProtocolsReport()
        let proto = try XCTUnwrap(result.protocols.first)
        XCTAssertNil(proto.associatedTypeNames)
        XCTAssertTrue(result.diagnostics.contains { $0.code == .unresolvedGenericReference })
    }

    private func protocolSignatureFixture(signatureCount: UInt32, requirementCount: UInt32,
                                           names: String?) ->
        (image: GenericImageBuilder, descriptor: Int, subject: Int, names: Int?) {
        var image = GenericImageBuilder()
        let name = image.cstr("Container")
        let subject = image.cstr("x")
        let namesOffset = names.map { image.cstr($0) }
        image.align(4)
        let descriptor = image.count
        image.appendU32(3)
        image.appendU32(0)
        let nameField = image.rel()
        image.appendU32(signatureCount)
        image.appendU32(requirementCount)
        let namesField = image.rel()
        image.patchRel(nameField, name)
        if let namesOffset { image.patchRel(namesField, namesOffset) }
        return (image, descriptor, subject, namesOffset)
    }

    private func protocolSignatureReport(_ source: GenericImageBuilder, descriptor: Int) ->
        (protocols: [SwiftProtocolDescriptor], diagnostics: [MetadataParseDiagnostic],
         genericAbstentions: [MetadataParseDiagnostic], genericDiagnosticsDropped: Int) {
        var image = source
        let list = image.rel()
        image.patchRel(list, descriptor)
        return image.makeParser(constEnd: list,
                                lists: ["__swift5_protos": (offset: list, count: 1)]).parseProtocolsReport()
    }

    // CP21-RULING-TESTS

    /// L1: well-formed but unsupported metadata (abstentions) leaves `diagnostics` at the pre-CP21
    /// value (empty here), so the navigator frontier and loader findings do not see it.
    func testAbstentionOnlyInputLeavesDiagnosticsEmpty() throws {
        // Global-actor conformance tail.
        var actorFixture = witnessesFixture(flags: 1 << 19)
        actorFixture.image.appendU32(0); actorFixture.image.appendU32(0)
        let actor = witnessesReport(actorFixture.image, descriptor: actorFixture.descriptor)
        XCTAssertEqual(actor.conformances.count, 1)
        XCTAssertTrue(actor.diagnostics.isEmpty)
        XCTAssertEqual(actor.genericAbstentions.map(\.code), [.unsupportedGenericMetadata])
        XCTAssertEqual(actor.genericDiagnosticsDropped, 0)

        // Generic-header flag 2 (conditional inverted-protocol storage).
        let flagTwo = genericTypeFixture(parameters: [0x80], flags: 2, tail: [3, 0, 0, 0, 0, 0, 0, 0])
        let types = flagTwo.builder.makeParser(lists: ["__swift5_types": (flagTwo.list, 1)]).parseTypesReport()
        XCTAssertEqual(types.types.count, 1)
        XCTAssertNil(types.types.first?.genericSignature)
        XCTAssertTrue(types.diagnostics.isEmpty)
        XCTAssertEqual(types.genericAbstentions.map(\.code), [.unsupportedGenericMetadata])
        XCTAssertEqual(types.genericDiagnosticsDropped, 0)
        XCTAssertTrue(types.genericAbstentions.allSatisfy { $0.grade == .labelledUnknownKind })

        // A genuine read failure still lands in `diagnostics`, not in the abstention list.
        let broken = genericTypeFixture(parameters: [0x80], keys: 0)
        let failure = broken.builder.makeParser(lists: ["__swift5_types": (broken.list, 1)]).parseTypesReport()
        XCTAssertFalse(failure.diagnostics.isEmpty)
        XCTAssertTrue(failure.genericAbstentions.isEmpty)
    }

    /// L2: generic diagnostics beyond `MetadataParseDiagnosticLog.maxEntries` are counted, not lost.
    func testGenericDiagnosticsBeyondTheCapAreCounted() {
        let single = genericTypeFixture(parameters: [0x80], keys: 0)
        let perItem = single.builder.makeParser(lists: ["__swift5_types": (single.list, 1)])
            .parseTypesReport().diagnostics.count
        XCTAssertGreaterThan(perItem, 0)

        var f = genericTypeFixture(parameters: [0x80], keys: 0)
        let entries = MetadataParseDiagnosticLog.maxEntries + 104
        for _ in 1..<entries {
            let entry = f.builder.rel()
            f.builder.patchRel(entry, f.descriptor)
        }
        let report = f.builder.makeParser(lists: ["__swift5_types": (f.list, entries)]).parseTypesReport()
        XCTAssertEqual(report.types.count, entries)
        XCTAssertEqual(report.diagnostics.count, MetadataParseDiagnosticLog.maxEntries)
        XCTAssertEqual(report.genericDiagnosticsDropped, entries * perItem - MetadataParseDiagnosticLog.maxEntries)
        XCTAssertTrue(report.genericAbstentions.isEmpty)
    }

    /// L3: the byte copies and raw payload are not persisted; old payloads still decode.
    func testRequirementByteCopiesAreNotPersisted() throws {
        let requirement = SwiftGenericRequirement(address: 0x1000, flags: 1,
            subjectMangledName: "x", subject: "A", rawPayload: 0x1234,
            subjectMangledBytes: [0x78], targetMangledName: "Si", targetMangledBytes: [0x53, 0x69], target: "Int")
        let data = try JSONEncoder().encode(requirement)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertNil(object["rawPayload"])
        XCTAssertNil(object["subjectMangledBytes"])
        XCTAssertNil(object["targetMangledBytes"])
        let decoded = try JSONDecoder().decode(SwiftGenericRequirement.self, from: data)
        XCTAssertEqual(decoded.subjectMangledName, "x")
        XCTAssertEqual(decoded.target, "Int")
        XCTAssertNil(decoded.subjectMangledBytes)
        var conformance = SwiftConformance(typeName: "Box", protocolName: "P")
        conformance.conditionalRequirements = [decoded]
        let report = SwiftMetadataFactProjection.genericMetadataReport(types: [],
            conformances: [conformance], protocols: [], diagnostics: [])
        guard case .object(let root) = report, case .array(let entries)? = root["conformances"],
              case .object(let entry)? = entries.first,
              case .array(let requirements)? = entry["conditionalRequirements"],
              case .object(let result)? = requirements.first else {
            return XCTFail("Expected requirement record")
        }
        XCTAssertEqual(result["rawPayload"], .null)
        let old = Data(#"{"address":4096,"flags":1,"rawPayload":7,"subjectMangledBytes":[120]}"#.utf8)
        XCTAssertEqual(try JSONDecoder().decode(SwiftGenericRequirement.self, from: old).address, 4096)
    }

    // CP21-REPORT-TESTS

    func testGenericReportPreservesUnknownVersusVerifiedEmpty() throws {
        let unknown = SwiftConformance(typeName: "Unknown", protocolName: "P")
        var plain = SwiftConformance(typeName: "Plain", protocolName: "P")
        plain.conditionalRequirements = []
        let report = SwiftMetadataFactProjection.genericMetadataReport(types: [],
            conformances: [unknown, plain], protocols: [], diagnostics: [])
        guard case .object(let root) = report, case .array(let entries)? = root["conformances"],
              case .object(let first) = entries[0], case .object(let second) = entries[1] else {
            return XCTFail("Expected structured generic metadata")
        }
        XCTAssertEqual(first["conditionalRequirements"], .null)
        XCTAssertEqual(second["conditionalRequirements"], .array([]))
    }

    func testGenericReportRendersOnlyResolvedOperandsAndRetainsRawIdentity() throws {
        var requirement = SwiftGenericRequirement(address: 4096, flags: 1,
            subjectMangledName: "x", subject: "A", rawPayload: 8,
            targetMangledName: "Si", target: "Int")
        var conformance = SwiftConformance(typeName: "Box", protocolName: "P")
        conformance.conditionalRequirements = [requirement]
        func record(_ value: SwiftConformance) throws -> [String: NavigatorJSONValue] {
            let report = SwiftMetadataFactProjection.genericMetadataReport(types: [],
                conformances: [value], protocols: [], diagnostics: [])
            guard case .object(let root) = report, case .array(let entries)? = root["conformances"],
                  case .object(let entry)? = entries.first,
                  case .array(let requirements)? = entry["conditionalRequirements"],
                  case .object(let result)? = requirements.first else {
                XCTFail("Expected requirement record")
                return [:]
            }
            return result
        }
        XCTAssertEqual(try record(conformance)["rendered"], .string("A == Int"))
        requirement.target = nil
        requirement.unresolvedReason = "unresolvedTargetName"
        conformance.conditionalRequirements = [requirement]
        let unresolved = try record(conformance)
        XCTAssertEqual(unresolved["rendered"], .null)
        XCTAssertEqual(unresolved["targetMangledName"], .string("Si"))
        XCTAssertEqual(unresolved["flags"], .int(1))
    }

    // CP21-CORPUS-TESTS

    /// With no environment this is an explicit skip, never a fabricated corpus pass.
    func testFixtureCorpusDifferential() throws {
        let environment = ProcessInfo.processInfo.environment
        guard let files = environment["CP21_FIXTURE_FILES"], !files.isEmpty,
              let destination = environment["CP21_OBSERVATIONS_PATH"], !destination.isEmpty else {
            throw XCTSkip("Set CP21_FIXTURE_FILES and CP21_OBSERVATIONS_PATH for the independent fixture corpus")
        }
        let observeOnly = environment["CP21_OBSERVE_ONLY"] == "1"
        let outputURL = URL(fileURLWithPath: destination)
        // Refuse to overwrite a previous raw observation receipt.
        guard !FileManager.default.fileExists(atPath: outputURL.path) else {
            return XCTFail("Observation receipt already exists")
        }
        guard FileManager.default.createFile(atPath: outputURL.path, contents: nil) else {
            return XCTFail("Cannot create observation receipt")
        }
        let handle = try FileHandle(forWritingTo: outputURL)
        defer { try? handle.close() }
        var observed = 0
        for file in files.split(separator: ":") {
            let lines = try String(contentsOfFile: String(file), encoding: .utf8).split(separator: "\n")
            for line in lines {
                let fixture = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
                let id = try XCTUnwrap(fixture["id"] as? String)
                let image = try XCTUnwrap(fixture["image"] as? [String: Any])
                let bytes = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(image["bytes_base64"] as? String)))
                let sectionRecords = try XCTUnwrap(image["sections"] as? [[String: Any]])
                let sections = try sectionRecords.map { entry -> SwiftMetadataParser.Section in
                    .init(name: try XCTUnwrap(entry["name"] as? String),
                          address: try fixtureUInt64(entry, "address"),
                          fileOffset: try fixtureUInt64(entry, "fileOffset"),
                          size: try fixtureUInt64(entry, "size"),
                          isExecutable: entry["isExecutable"] as? Bool ?? false,
                          isZeroFill: entry["isZeroFill"] as? Bool ?? false)
                }
                var rebases: [UInt64: UInt64] = [:]
                for entry in image["rebaseTargets"] as? [[String: Any]] ?? [] {
                    rebases[try fixtureUInt64(entry, "slot")] = try fixtureUInt64(entry, "target")
                }
                var binds: [UInt64: String] = [:]
                for entry in image["bindNames"] as? [[String: Any]] ?? [] {
                    binds[try fixtureUInt64(entry, "slot")] = try XCTUnwrap(entry["name"] as? String)
                }
                let parser = SwiftMetadataParser(data: bytes, sections: sections,
                                                 rebaseTargets: rebases, bindNames: binds)
                let types = parser.parseTypesReport()
                let conformances = parser.parseConformancesReport()
                let protocols = parser.parseProtocolsReport()
                let diagnostics = types.diagnostics + conformances.diagnostics + protocols.diagnostics
                    + types.genericAbstentions + conformances.genericAbstentions + protocols.genericAbstentions
                let observation = GenericCorpusObservation(id: id, sourceFile: String(file), observeOnly: observeOnly,
                    types: types.types, conformances: conformances.conformances,
                    protocols: protocols.protocols, diagnostics: diagnostics)
                var encoded = try JSONEncoder().encode(observation)
                encoded.append(10)
                try handle.write(contentsOf: encoded)
                observed += 1
                if observeOnly { continue }
                let expected = try XCTUnwrap(fixture["expected"] as? [String: Any])
                let kind = try XCTUnwrap(expected["descriptorKind"] as? String)
                let descriptorAddress = try fixtureUInt64(expected, "descriptorAddress")
                let fields = expected["fields"] as? [[String: Any]] ?? []
                let selectedType = types.types.first { $0.descriptorAddress == descriptorAddress }
                let selectedConformance = conformances.conformances.first { $0.descriptorAddress == descriptorAddress }
                let selectedProtocol = protocols.protocols.first { $0.descriptorAddress == descriptorAddress }
                if expected["diagnostic"] != nil
                    || expected["productExpectation"] as? String == "unsupported-invertible-layout"
                    || (expected["productExpectation"] as? [String: Any])?["diagnostic"] as? String == "unsupported-invertible-layout" {
                    let noValue: Bool
                    switch kind {
                    case "nominal": noValue = selectedType?.genericSignature == nil
                    case "conformance": noValue = selectedConformance == nil
                    case "protocol": noValue = selectedProtocol?.requirementSignature == nil
                    default: return XCTFail("Unknown fixture descriptor kind: \(kind)")
                    }
                    XCTAssertTrue(noValue || diagnostics.contains { $0.code != nil }, id)
                    continue
                }
                switch kind {
                case "conformance":
                    if (expected["typeReferenceKind"] as? NSNumber)?.intValue == 3 {
                        // Existing reader policy: indirect ObjC class metadata is unresolved.
                        XCTAssertNil(selectedConformance, id)
                        continue
                    }
                    let conformance = try XCTUnwrap(selectedConformance, id)
                    XCTAssertEqual(conformance.descriptorAddress, try fixtureUInt64(expected, "descriptorAddress"), id)
                    try assertFixtureRequirements(conformance.conditionalRequirements,
                        expected["conditionalRequirements"] as? [[String: Any]],
                        descriptorAddress: descriptorAddress, fields: fields, id: id)
                    XCTAssertEqual(conformance.resilientWitnessCount,
                                   (expected["resilientWitnessCount"] as? NSNumber)?.uint32Value, id)
                    try assertFixturePacks(conformance.conditionalPackShapes,
                        expected["conditionalPackShapes"] as? [[String: Any]], id: id)
                    if let table = expected["genericWitnessTable"] as? [String: Any] {
                        XCTAssertEqual(conformance.genericWitnessTable?.witnessTableSizeInWords,
                                       (table["witnessTableSizeInWords"] as? NSNumber)?.uint16Value, id)
                        XCTAssertEqual(conformance.genericWitnessTable?.privateSizeAndFlags,
                                       (table["privateSizeAndInstantiationFlag"] as? NSNumber)?.uint16Value, id)
                        XCTAssertEqual(conformance.genericWitnessTable?.instantiatorRawValue,
                                       (table["instantiator"] as? NSNumber)?.uint32Value, id)
                        if let field = fields.first(where: { $0["name"] as? String == "genericWitnessTable.privateData" }),
                           let target = field["target"] as? NSNumber {
                            XCTAssertEqual(conformance.genericWitnessTable?.privateDataAddress, target.uint64Value, id)
                        }
                    } else {
                        XCTAssertNil(conformance.genericWitnessTable, id)
                    }
                    if expected["retroactive"] as? Bool == true,
                       let field = fields.first(where: { $0["name"] as? String == "retroactiveContext" }),
                       let target = field["target"] as? NSNumber {
                        XCTAssertEqual(conformance.retroactiveContextAddress, target.uint64Value, id)
                    }
                case "nominal":
                    let type = try XCTUnwrap(selectedType, id)
                    XCTAssertEqual(type.descriptorAddress, descriptorAddress, id)
                    if expected["genericSignature"] is NSNull {
                        XCTAssertNil(type.genericSignature, id)
                        continue
                    }
                    let signature = try XCTUnwrap(type.genericSignature, id)
                    let header = try XCTUnwrap(expected["genericHeader"] as? [String: Any])
                    XCTAssertEqual(type.descriptorAddress, descriptorAddress, id)
                    XCTAssertEqual(signature.headerAddress,
                                   descriptorAddress + (try fixtureUInt64(expected, "genericHeaderOffset")), id)
                    XCTAssertEqual(signature.flags, (header["flags"] as? NSNumber)?.uint16Value, id)
                    XCTAssertEqual(signature.numKeyArguments, (header["numKeyArguments"] as? NSNumber)?.uint16Value, id)
                    let parameters = try XCTUnwrap(expected["parameters"] as? [[String: Any]])
                    XCTAssertEqual(signature.parameters.map(\.rawValue),
                                   parameters.compactMap { ($0["raw"] as? NSNumber)?.uint8Value }, id)
                    try assertFixtureRequirements(signature.requirements, expected["requirements"] as? [[String: Any]],
                                                  descriptorAddress: descriptorAddress, fields: fields, id: id)
                    for (name, actual) in [("instantiationCache", signature.instantiationCacheRelativeOffset),
                                           ("defaultInstantiationPattern", signature.defaultInstantiationPatternRelativeOffset)] {
                        if let field = fields.first(where: { $0["name"] as? String == name }),
                           let value = field["value"] as? NSNumber {
                            XCTAssertEqual(actual, Int32(truncatingIfNeeded: value.int64Value), id)
                        }
                    }
                    if let packHeader = expected["packShapeHeader"] as? [String: Any] {
                        XCTAssertEqual(signature.numShapeClasses, (packHeader["numShapeClasses"] as? NSNumber)?.uint16Value, id)
                        try assertFixturePacks(signature.packShapes, expected["packShapes"] as? [[String: Any]], id: id)
                    } else {
                        XCTAssertNil(signature.packShapes, id)
                        XCTAssertNil(signature.numShapeClasses, id)
                    }
                    if let values = expected["genericValues"] as? [String: Any] {
                        XCTAssertEqual(signature.valueTypes, (values["types"] as? [NSNumber])?.map(\.uint32Value), id)
                    } else {
                        XCTAssertNil(signature.valueTypes, id)
                    }
                case "protocol":
                    let proto = try XCTUnwrap(selectedProtocol, id)
                    XCTAssertEqual(proto.descriptorAddress, descriptorAddress, id)
                    try assertFixtureRequirements(proto.requirementSignature, expected["requirements"] as? [[String: Any]],
                                                  descriptorAddress: descriptorAddress, fields: fields, id: id)
                    XCTAssertEqual(proto.associatedTypeNames, expected["associatedTypeNames"] as? [String], id)
                default: XCTFail("Unknown fixture descriptor kind: \(kind)")
                }
            }
        }
        XCTAssertGreaterThan(observed, 0)
    }

    private struct GenericCorpusObservation: Encodable {
        var id: String
        var sourceFile: String
        var observeOnly: Bool
        var types: [SwiftTypeDescriptor]
        var conformances: [SwiftConformance]
        var protocols: [SwiftProtocolDescriptor]
        var diagnostics: [MetadataParseDiagnostic]
    }

    private func fixtureUInt64(_ value: [String: Any], _ key: String) throws -> UInt64 {
        try XCTUnwrap(value[key] as? NSNumber, "Missing numeric fixture key \(key)").uint64Value
    }

    private func assertFixtureRequirements(_ actual: [SwiftGenericRequirement]?, _ expected: [[String: Any]]?,
                                           descriptorAddress: UInt64, fields: [[String: Any]], id: String) throws {
        let actual = try XCTUnwrap(actual, id), expected = try XCTUnwrap(expected, id)
        XCTAssertEqual(actual.count, expected.count, id)
        for (record, oracle) in zip(actual, expected) {
            let offset = try fixtureUInt64(oracle, "offset")
            XCTAssertEqual(record.address, descriptorAddress + offset, id)
            XCTAssertEqual(record.flags, (oracle["flags"] as? NSNumber)?.uint32Value, id)
            XCTAssertEqual(record.kind?.rawValue, (oracle["kindRaw"] as? NSNumber)?.uint32Value, id)
            XCTAssertEqual(record.hasKeyArgument, oracle["isKeyArgument"] as? Bool, id)
            XCTAssertEqual(record.isPackRequirement, oracle["isPackRequirement"] as? Bool, id)
            XCTAssertEqual(record.isValueRequirement, oracle["isValueRequirement"] as? Bool, id)
            if let payload = oracle["rawPayload"] as? NSNumber {
                XCTAssertEqual(record.rawPayload, payload.uint32Value, id)
            } else if let payload = fields.first(where: {
                ($0["offset"] as? NSNumber)?.uint64Value == offset + 8 &&
                    ($0["size"] as? NSNumber)?.intValue == 4
            }), let value = payload["value"] as? NSNumber {
                XCTAssertEqual(record.rawPayload, UInt32(truncatingIfNeeded: value.int64Value), id)
            }
            try assertFixtureMangledName(oracle["paramMangled"], bytes: record.subjectMangledBytes,
                                         printable: record.subjectMangledName, id: id)
            try assertFixtureMangledName(oracle["rhsMangled"], bytes: record.targetMangledBytes,
                                         printable: record.targetMangledName, id: id)
            if let protocolName = oracle["protocolName"] as? String { XCTAssertEqual(record.target, protocolName, id) }
            if let target = oracle["protocolAddress"] as? NSNumber { XCTAssertEqual(record.protocolDescriptorAddress, target.uint64Value, id) }
            if let target = oracle["conformanceAddress"] as? NSNumber { XCTAssertEqual(record.conformanceDescriptorAddress, target.uint64Value, id) }
            if let layout = oracle["layoutRaw"] as? NSNumber { XCTAssertEqual(record.layout, layout.uint32Value, id) }
            if let index = oracle["genericParamIndex"] as? NSNumber { XCTAssertEqual(record.genericParameterIndex, index.uint16Value, id) }
            if let bits = oracle["invertedProtocolBits"] as? NSNumber { XCTAssertEqual(record.invertedProtocols, bits.uint16Value, id) }
        }
    }

    private func assertFixtureMangledName(_ expected: Any?, bytes: [UInt8]?, printable: String?, id: String) throws {
        if let text = expected as? String {
            XCTAssertEqual(printable, text, id)
            XCTAssertEqual(bytes, Array(text.utf8), id)
        } else if let symbolic = expected as? [String: Any], let hex = symbolic["mangledBytesHex"] as? String {
            guard hex.utf8.count == hex.count, hex.count % 2 == 0 else {
                return XCTFail("Invalid hexadecimal mangling expectation: \(id)")
            }
            var raw: [UInt8] = []
            var cursor = hex.startIndex
            while cursor < hex.endIndex {
                let end = hex.index(cursor, offsetBy: 2)
                raw.append(try XCTUnwrap(UInt8(hex[cursor..<end], radix: 16), id))
                cursor = end
            }
            XCTAssertEqual(bytes, raw, id)
        } else {
            XCTAssertNil(printable, id)
            XCTAssertNil(bytes, id)
        }
    }

    private func assertFixturePacks(_ actual: [SwiftGenericPackShape]?, _ expected: [[String: Any]]?, id: String) throws {
        let actual = try XCTUnwrap(actual, id), expected = try XCTUnwrap(expected, id)
        XCTAssertEqual(actual.count, expected.count, id)
        for (record, oracle) in zip(actual, expected) {
            XCTAssertEqual(record.kind, (oracle["kindRaw"] as? NSNumber)?.uint16Value, id)
            XCTAssertEqual(record.index, (oracle["index"] as? NSNumber)?.uint16Value, id)
            XCTAssertEqual(record.shapeClass, (oracle["shapeClass"] as? NSNumber)?.uint16Value, id)
            XCTAssertEqual(record.unused, (oracle["unused"] as? NSNumber)?.uint16Value, id)
        }
    }
}

/// Every pointer is patched relative to its own field, and every list owns a distinct section.
private struct GenericImageBuilder {
    var data: [UInt8] = []
    var base: UInt64 = 0x1000
    var count: Int { data.count }
    mutating func appendU8(_ value: UInt8) { data.append(value) }
    mutating func appendU16(_ value: UInt16) {
        for shift in stride(from: 0, to: 16, by: 8) { data.append(UInt8(truncatingIfNeeded: value >> shift)) }
    }
    mutating func appendU32(_ value: UInt32) {
        for shift in stride(from: 0, to: 32, by: 8) { data.append(UInt8(truncatingIfNeeded: value >> shift)) }
    }
    mutating func appendU64(_ value: UInt64) {
        for shift in stride(from: 0, to: 64, by: 8) { data.append(UInt8(truncatingIfNeeded: value >> shift)) }
    }
    mutating func rel() -> Int { let result = count; appendU32(0); return result }
    mutating func cstr(_ value: String) -> Int {
        let result = count; data += value.utf8; data.append(0); return result
    }
    mutating func align(_ alignment: Int) { while count % alignment != 0 { data.append(0) } }
    mutating func patchU32(_ offset: Int, _ value: UInt32) {
        for index in 0..<4 { data[offset + index] = UInt8(truncatingIfNeeded: value >> (index * 8)) }
    }
    mutating func patchRel(_ field: Int, _ target: Int, tag: Int32 = 0) {
        patchU32(field, UInt32(bitPattern: Int32(target - field) | tag))
    }
    func va(_ offset: Int) -> UInt64 { base + UInt64(offset) }
    func makeParser(constEnd: Int? = nil, lists: [String: (offset: Int, count: Int)] = [:],
                    rebases: [UInt64: UInt64] = [:], binds: [UInt64: String] = [:],
                    extraSections: [SwiftMetadataParser.Section] = []) -> SwiftMetadataParser {
        let end = constEnd ?? lists.values.map(\.offset).min() ?? count
        var sections = [SwiftMetadataParser.Section(name: "__const", address: base,
            fileOffset: 0, size: UInt64(end))]
        for (name, list) in lists {
            sections.append(.init(name: name, address: va(list.offset), fileOffset: UInt64(list.offset),
                                  size: UInt64(list.count * 4)))
        }
        return SwiftMetadataParser(data: Data(data), sections: sections + extraSections,
                                   rebaseTargets: rebases, bindNames: binds)
    }
}
