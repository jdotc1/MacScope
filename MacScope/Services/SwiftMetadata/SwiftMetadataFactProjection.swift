import Foundation

/// N1: projects `SwiftMetadataParser` output onto navigator-engine contract v1 facts and frontier
/// items (`docs/contracts/navigator-engine/v1`). Resolved metadata facts are authoritative;
/// unresolved superclass diagnostics have unknown status and a frontier item, never a guessed name.
///
/// Subjects are type descriptors by address (`type`, ref `0x…`): names are module-qualified where the
/// parent walk resolves (`Mod.Outer.Inner`, `Swift.Equatable`) and simple otherwise, but the
/// descriptor, not the name, is the identity. A conformance whose
/// conforming type has no in-image descriptor is keyed by its simple name and flagged on the frontier.
///
/// Every subject ref is built by `NavigatorSubjectRef` (the spellings are the ones this projection
/// always wrote, so subject JSON is unchanged). Rule version 2: the projection is now run by the
/// workspace producer and stamps the caller's `generation` / `dependsOn` on every record.
enum SwiftMetadataFactProjection {
    static let rule = "macscope.swift-metadata-parser"
    static let ruleVersion = "2"

    struct Output: Sendable {
        var facts: [NavigatorFact] = []
        var frontier: [NavigatorFrontierItem] = []
        /// Records the contract refused (should stay empty; reported rather than dropped silently).
        var refused: [String] = []
    }

    static func project(types: [SwiftTypeDescriptor], conformances: [SwiftConformance],
                        diagnostics: [MetadataParseDiagnostic], protocols: [SwiftProtocolDescriptor] = [],
                        image: String, toolchain: String, generation: NavigatorGeneration? = nil,
                        dependsOn: [String]? = nil) -> Output {
        var output = Output()
        var seen = Set<String>()

        /// Type and protocol subject refs: the descriptor address, else the `name:` form, else the
        /// raw `name:` spelling for a name the grammar refuses (empty, or with a control character).
        func typeRef(descriptor: UInt64?, name: String) -> String {
            if let descriptor { return NavigatorSubjectRef.type(descriptor: descriptor) }
            return NavigatorSubjectRef.named(kind: "type", qualifiedName: name) ?? "name:\(name)"
        }
        func protocolRef(name: String) -> String {
            NavigatorSubjectRef.named(kind: "protocol", qualifiedName: name) ?? "name:\(name)"
        }
        func add(_ make: () throws -> NavigatorFact) {
            do {
                let fact = try make()
                if seen.insert(fact.id).inserted { output.facts.append(fact) }
            } catch {
                output.refused.append("\(error)")
            }
        }
        func gap(_ make: () throws -> NavigatorFrontierItem) {
            do {
                let item = try make()
                if seen.insert(item.id).inserted { output.frontier.append(item) }
            } catch {
                output.refused.append("\(error)")
            }
        }
        func provenance(_ ref: String) -> [NavigatorProvenance] {
            [NavigatorProvenance(kind: "metadataRecord", ref: ref, rule: rule, ruleVersion: ruleVersion)]
        }

        for type in types {
            let ref = typeRef(descriptor: type.descriptorAddress, name: type.name)
            let subject = NavigatorSubject(kind: "type", ref: ref, image: image)
            let evidence = provenance("__swift5_types descriptor \(ref)")
            if type.kind == .unknown {
                gap { try NavigatorFrontierItem.make(subject: subject, gap: "unknownContext",
                                                     detail: "context kind \(type.rawKind.map(String.init) ?? "?")", toolchain: toolchain,
                                                     missingEvidence: [ref], generation: generation, dependsOn: dependsOn) }
                continue
            }
            add { try NavigatorFact.make(subject: subject, predicate: "hasName", value: .string(type.qualifiedName ?? type.name),
                                         status: "authoritative", provenance: evidence, toolchain: toolchain,
                                         generation: generation, dependsOn: dependsOn) }
            add { try NavigatorFact.make(subject: subject, predicate: "nominalKind", value: .string(type.kind.rawValue),
                                         status: "authoritative", provenance: evidence, toolchain: toolchain,
                                         generation: generation, dependsOn: dependsOn) }
            if let isGeneric = type.isGeneric {
                add { try NavigatorFact.make(subject: subject, predicate: "isGeneric", value: .bool(isGeneric),
                                             status: "authoritative", provenance: evidence, toolchain: toolchain,
                                             generation: generation, dependsOn: dependsOn) }
            }
            // Positive-only: absence of these two is the default, not a recorded negative.
            if type.isPrivateOrLocal == true {
                add { try NavigatorFact.make(subject: subject, predicate: "isPrivateOrLocal", value: .bool(true),
                                             status: "authoritative", provenance: evidence, toolchain: toolchain,
                                             generation: generation, dependsOn: dependsOn) }
            }
            if type.isImportedCType == true {
                add { try NavigatorFact.make(subject: subject, predicate: "isImportedCType", value: .bool(true),
                                             status: "authoritative", provenance: evidence, toolchain: toolchain,
                                             generation: generation, dependsOn: dependsOn) }
            }
            if let superclass = type.superclass {
                add { try NavigatorFact.make(subject: subject, predicate: "superclass",
                                             value: type.superclassUnresolvedReason == nil ? .string(superclass) : .null,
                                             status: type.superclassUnresolvedReason == nil ? "authoritative" : "unknown",
                                             provenance: evidence, toolchain: toolchain,
                                             generation: generation, dependsOn: dependsOn) }
            }
            if let reason = type.superclassUnresolvedReason {
                gap { try NavigatorFrontierItem.make(
                    subject: subject, gap: "unknownType",
                    detail: "superclass" + (type.superclass.map { "; mangled \($0)" } ?? "") + "; reason \(reason)",
                    toolchain: toolchain, missingEvidence: [ref],
                    primitives: [NavigatorPrimitiveRef(name: "swiftMetadata.resolveSymbolicReference", preconditions: [])],
                    generation: generation, dependsOn: dependsOn) }
            }
            for field in type.fields {
                let member: NavigatorJSONValue
                let predicate: String
                if type.kind == .enum {
                    predicate = "enumCase"
                    member = .object(["name": .string(field.name), "payload": field.typeName.map { .string($0) } ?? .null,
                                      "mangled": field.mangledTypeName.map { .string($0) } ?? .null,
                                      "indirect": .bool(field.isIndirectCase)])
                } else {
                    predicate = "storedField"
                    member = .object(["name": .string(field.name), "type": field.typeName.map { .string($0) } ?? .null,
                                      "mangled": field.mangledTypeName.map { .string($0) } ?? .null,
                                      "var": .bool(field.isVar)])
                }
                add { try NavigatorFact.make(subject: subject, predicate: predicate, value: member, status: "authoritative",
                                             provenance: evidence, toolchain: toolchain,
                                             generation: generation, dependsOn: dependsOn) }
                // A case with no payload has no type by design; anything else unnamed is a gap.
                if field.typeName == nil, field.mangledTypeName != nil {
                    let fieldRef = NavigatorSubjectRef.field(typeRef: ref, name: field.name) ?? "\(ref).\(field.name)"
                    gap { try NavigatorFrontierItem.make(
                        subject: NavigatorSubject(kind: "field", ref: fieldRef, image: image), gap: "unknownType",
                        detail: "mangled \(field.mangledTypeName!)" + (field.unresolvedReason.map { "; reason \($0)" } ?? ""), toolchain: toolchain, missingEvidence: [ref],
                        primitives: [NavigatorPrimitiveRef(name: "swiftMetadata.resolveSymbolicReference", preconditions: [])],
                        generation: generation, dependsOn: dependsOn) }
                }
            }
        }

        for descriptor in protocols {
            let ref = NavigatorSubjectRef.protocol(descriptor: descriptor.descriptorAddress)
            let subject = NavigatorSubject(kind: "protocol", ref: ref, image: image)
            let evidence = provenance("__swift5_protos descriptor \(ref)")
            add { try NavigatorFact.make(subject: subject, predicate: "hasName", value: .string(descriptor.name),
                                         status: "authoritative", provenance: evidence, toolchain: toolchain,
                                         generation: generation, dependsOn: dependsOn) }
            add { try NavigatorFact.make(subject: subject, predicate: "isProtocol", value: .bool(true),
                                         status: "authoritative", provenance: evidence, toolchain: toolchain,
                                         generation: generation, dependsOn: dependsOn) }
        }

        for conformance in conformances {
            let subject = NavigatorSubject(kind: "type", ref: typeRef(descriptor: conformance.typeDescriptorAddress,
                                                                      name: conformance.typeName), image: image)
            if conformance.typeDescriptorAddress == nil {
                gap { try NavigatorFrontierItem.make(subject: subject, gap: "unresolvedTypeReference",
                                                     detail: "conforming type has no in-image descriptor", toolchain: toolchain,
                                                     generation: generation, dependsOn: dependsOn) }
            }
            let ref = conformance.descriptorAddress.map(NavigatorSubjectRef.address) ?? "?"
            if conformance.protocolQualifiedName == nil {
                // An unresolved reference keeps its simple name; the module is never guessed.
                gap { try NavigatorFrontierItem.make(
                    subject: NavigatorSubject(kind: "protocol", ref: protocolRef(name: conformance.protocolName), image: image),
                    gap: "unresolvedProtocol", detail: "protocol reference has no module-qualified name",
                    toolchain: toolchain, generation: generation, dependsOn: dependsOn) }
            }
            add { try NavigatorFact.make(subject: subject, predicate: "conformsTo",
                                         value: .string(conformance.protocolQualifiedName ?? conformance.protocolName),
                                         status: "authoritative", provenance: provenance("__swift5_proto descriptor \(ref)"),
                                         toolchain: toolchain, generation: generation, dependsOn: dependsOn) }
        }

        for diagnostic in diagnostics {
            let gapName: String
            switch diagnostic.grade {
            case .labelledUnknownKind, .walkCapped: gapName = "unknownContext"
            case .skippedItem, .abandonedList: gapName = "malformedFieldDescriptor"
            }
            // The diagnostic carries no section name, so the ref stays the bare address this projection
            // always wrote (the canonical `<section>@<address>` form needs the section).
            gap { try NavigatorFrontierItem.make(
                subject: NavigatorSubject(kind: "metadataRecord", ref: NavigatorSubjectRef.address(diagnostic.address), image: image),
                gap: gapName, detail: "\(diagnostic.grade.rawValue): \(diagnostic.message)", toolchain: toolchain,
                generation: generation, dependsOn: dependsOn) }
        }
        return output
    }
}

extension SwiftMetadataFactProjection {
    /// A transported report is not authority: replay each witness against the supplied image.
    static func projectAsyncContinuations(_ report: SwiftAsyncContinuationReport,
                                          parser: SwiftMetadataParser, metadata: SwiftAsyncMetadata,
                                          image: String, toolchain: String,
                                          generation: NavigatorGeneration? = nil,
                                          dependsOn: [String]? = nil) -> Output {
        var output = Output()
        var linked = Set<UInt64>()
        var seen = Set<String>()
        for edge in report.edges {
            guard edge.source == edge.certificate.source, edge.resume == edge.certificate.resume,
                  edge.kind == edge.certificate.kind,
                  SwiftAsyncContinuationCertificateVerifier.verify(edge.certificate, parser: parser, metadata: metadata) else {
                output.refused.append("async continuation certificate refused")
                continue
            }
            do {
                let fact = try NavigatorFact.make(
                    subject: NavigatorSubject(kind: "function", ref: NavigatorSubjectRef.address(edge.resume), image: image),
                    predicate: "asyncContinuationOf", value: .string(NavigatorSubjectRef.address(edge.source)),
                    status: "proven",
                    provenance: [.init(kind: "proofCertificate", ref: "sha256:" + edge.certificate.digest,
                                       rule: "macscope.swift-async-continuation", ruleVersion: "1")],
                    toolchain: toolchain, generation: generation, dependsOn: dependsOn)
                if seen.insert(fact.id).inserted { output.facts.append(fact) }
                linked.insert(edge.resume)
            } catch { output.refused.append(String(describing: error)) }
        }
        let partials = Set(metadata.resumePartialAddresses + metadata.continuationPartialAddresses)
        for partial in partials.subtracting(linked).sorted() {
            let reason = report.abstentions.first { $0.source == partial }?.reason
                ?? "no verified incoming continuation edge"
            do {
                output.frontier.append(try NavigatorFrontierItem.make(
                    subject: NavigatorSubject(kind: "function", ref: NavigatorSubjectRef.address(partial), image: image),
                    gap: "unlinkedAsyncContinuation", detail: reason, toolchain: toolchain,
                    missingEvidence: [NavigatorSubjectRef.address(partial)],
                    generation: generation, dependsOn: dependsOn))
            } catch { output.refused.append(String(describing: error)) }
        }
        return output
    }
}


extension SwiftMetadataFactProjection {
    static let asyncInvocationRule = "macscope.swift-async-invocation-chain"
    static let asyncInvocationRuleVersion = "1"

    struct InvocationOutput: Sendable {
        var facts: [NavigatorFact] = []
        var frontier: [NavigatorFrontierItem] = []
        var certificates: [NavigatorProofCertificate] = []
        var refused: [String] = []
    }

    /// Retain the entire contextual witness, including return transitions, inside the certified value.
    /// JSON text keeps UInt64 addresses lossless even outside the contract's Int64 numeric range.
    static func projectAsyncInvocations(_ report: SwiftAsyncInvocationDiscoveryReport,
                                        parser: SwiftMetadataParser, metadata: SwiftAsyncMetadata,
                                        image: String, toolchain: String,
                                        generation: NavigatorGeneration? = nil,
                                        dependsOn: [String]? = nil, deadline: Date? = nil) -> InvocationOutput {
        var output = InvocationOutput()
        var seen = Set<String>()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        func gap(source: UInt64, instruction: UInt64, reason: String, caller: String?) {
            do {
                let detail = reason + " at " + NavigatorSubjectRef.address(instruction)
                    + (caller.map { "; caller sha256:" + $0 } ?? "")
                let item = try NavigatorFrontierItem.make(
                    subject: NavigatorSubject(kind: "function", ref: NavigatorSubjectRef.address(source), image: image),
                    gap: "unlinkedAsyncContinuation", detail: detail, toolchain: toolchain,
                    missingEvidence: [NavigatorSubjectRef.address(instruction)]
                        + (caller.map { ["sha256:" + $0] } ?? []),
                    generation: generation, dependsOn: dependsOn)
                if seen.insert(item.id).inserted { output.frontier.append(item) }
            } catch { output.refused.append(String(describing: error)) }
        }
        for chain in report.chains {
            guard let root = chain.frames.first else {
                output.refused.append("empty async invocation chain refused")
                continue
            }
            if Task.isCancelled || deadline.map({ Date() >= $0 }) == true {
                gap(source: root.source, instruction: root.source, reason: "invocationProjectionStopped", caller: nil)
                continue
            }
            guard SwiftAsyncContinuationCertificateVerifier.verifyInvocationChain(chain, parser: parser, metadata: metadata) else {
                output.refused.append("async invocation chain certificate refused")
                gap(source: root.source, instruction: root.transfer, reason: "invocationChainVerificationFailed", caller: nil)
                continue
            }
            do {
                let encoded = try encoder.encode(chain)
                let value = NavigatorJSONValue.object([
                    "chainDigest": .string("sha256:" + chain.digest),
                    "certificateJSON": .string(String(decoding: encoded, as: UTF8.self)),
                ])
                let subject = NavigatorSubject(kind: "function", ref: NavigatorSubjectRef.address(root.source), image: image)
                let certificate = try NavigatorProofCertificate.make(
                    rule: asyncInvocationRule, ruleVersion: asyncInvocationRuleVersion,
                    subject: subject, predicate: "asyncInvocationChain", value: value,
                    premises: [.init(kind: "rule", ref: "SwiftAsyncContinuationCertificateVerifier.verifyInvocationChain",
                                     rule: asyncInvocationRule, ruleVersion: asyncInvocationRuleVersion)],
                    assumptions: ["Invocation context is scoped to the complete ordered certificate."],
                    conclusion: "The contextual chain replays against the selected image bytes.",
                    trustedBase: ["SwiftAsyncContinuationCertificateVerifier", "SwiftMetadataParser", "ARM64Decoder"],
                    outcome: .proven, budget: .init(wallMs: 0, bytesRead: 0))
                let fact = try NavigatorFact.make(subject: subject, predicate: "asyncInvocationChain", value: value,
                    status: "proven", provenance: [certificate.reference], toolchain: toolchain,
                    generation: generation, dependsOn: dependsOn)
                if seen.insert(fact.id).inserted {
                    output.facts.append(fact)
                    output.certificates.append(certificate)
                }
            } catch { output.refused.append(String(describing: error)) }
        }
        for frontier in report.frontier {
            gap(source: frontier.source, instruction: frontier.instruction,
                reason: frontier.reason, caller: frontier.callerDigest)
        }
        return output
    }
}

extension SwiftMetadataFactProjection {
    /// Structured transport for a human/MCP consumer. This is a separate report, because the
    /// pinned navigator contract has no predicate for conditional or generic requirements.
    /// The caller must wire this report into its response; no existing fact is reinterpreted.
    static func genericMetadataReport(types: [SwiftTypeDescriptor], conformances: [SwiftConformance],
                                      protocols: [SwiftProtocolDescriptor], diagnostics: [MetadataParseDiagnostic])
        -> NavigatorJSONValue {
        func string(_ value: String?) -> NavigatorJSONValue { value.map { .string($0) } ?? .null }
        func address(_ value: UInt64?) -> NavigatorJSONValue {
            value.map { .string("0x" + String($0, radix: 16)) } ?? .null
        }
        func bytes(_ value: [UInt8]?) -> NavigatorJSONValue {
            value.map { .array($0.map { .int(Int64($0)) }) } ?? .null
        }
        func packs(_ value: [SwiftGenericPackShape]?) -> NavigatorJSONValue {
            value.map { .array($0.map { item in .object([
                "kind": .int(Int64(item.kind)), "index": .int(Int64(item.index)),
                "shapeClass": .int(Int64(item.shapeClass)), "unused": .int(Int64(item.unused))
            ]) }) } ?? .null
        }
        func requirements(_ values: [SwiftGenericRequirement]?) -> NavigatorJSONValue {
            values.map { .array($0.map { value in .object([
                "address": address(value.address), "flags": .int(Int64(value.flags)),
                "kind": value.kind.map { .int(Int64($0.rawValue)) } ?? .null,
                "rawPayload": value.rawPayload.map { .int(Int64($0)) } ?? .null,
                "subjectMangledName": string(value.subjectMangledName), "subject": string(value.subject),
                "subjectMangledBytes": bytes(value.subjectMangledBytes),
                "targetMangledName": string(value.targetMangledName), "target": string(value.target),
                "targetMangledBytes": bytes(value.targetMangledBytes),
                "protocolDescriptorAddress": address(value.protocolDescriptorAddress),
                "conformanceDescriptorAddress": address(value.conformanceDescriptorAddress),
                "layout": value.layout.map { .int(Int64($0)) } ?? .null,
                "invertedProtocolsRawStorage": value.invertedProtocols.map { .int(Int64($0)) } ?? .null,
                "genericParameterIndex": value.genericParameterIndex.map { .int(Int64($0)) } ?? .null,
                "rendered": string(value.rendered), "unresolvedReason": string(value.unresolvedReason)
            ]) }) } ?? .null
        }
        func signature(_ value: SwiftGenericSignature?) -> NavigatorJSONValue {
            guard let value else { return .null }
            return .object([
                "headerAddress": address(value.headerAddress), "flags": .int(Int64(value.flags)),
                "numKeyArguments": .int(Int64(value.numKeyArguments)),
                "parameters": .array(value.parameters.map { .object([
                    "rawValue": .int(Int64($0.rawValue)), "kind": .int(Int64($0.kind)),
                    "hasKeyArgument": .bool($0.hasKeyArgument)
                ]) }),
                "requirements": requirements(value.requirements),
                "instantiationCacheRelativeOffset": .int(Int64(value.instantiationCacheRelativeOffset)),
                "defaultInstantiationPatternRelativeOffset": .int(Int64(value.defaultInstantiationPatternRelativeOffset)),
                "numShapeClasses": value.numShapeClasses.map { .int(Int64($0)) } ?? .null,
                "packShapes": packs(value.packShapes),
                "conditionalInvertedProtocols": value.conditionalInvertedProtocols.map { .int(Int64($0)) } ?? .null,
                "conditionalInvertedRequirementCounts": value.conditionalInvertedRequirementCounts.map {
                    .array($0.map { .int(Int64($0)) })
                } ?? .null,
                "conditionalInvertedRequirements": requirements(value.conditionalInvertedRequirements),
                "valueTypes": value.valueTypes.map { .array($0.map { .int(Int64($0)) }) } ?? .null
            ])
        }
        return .object([
            "types": .array(types.map { .object([
                "name": .string($0.name), "descriptorAddress": address($0.descriptorAddress),
                "genericSignature": signature($0.genericSignature)
            ]) }),
            "conformances": .array(conformances.map { value in
                var result: [String: NavigatorJSONValue] = [
                    "typeName": .string(value.typeName), "protocolName": .string(value.protocolName),
                    "descriptorAddress": address(value.descriptorAddress),
                    "conditionalRequirements": requirements(value.conditionalRequirements),
                    "conditionalPackShapes": packs(value.conditionalPackShapes),
                    "retroactiveContextAddress": address(value.retroactiveContextAddress),
                    "resilientWitnessCount": value.resilientWitnessCount.map { .int(Int64($0)) } ?? .null,
                    "genericWitnessTable": .null
                ]
                if let table = value.genericWitnessTable {
                    result["genericWitnessTable"] = .object([
                        "witnessTableSizeInWords": .int(Int64(table.witnessTableSizeInWords)),
                        "privateSizeAndFlags": .int(Int64(table.privateSizeAndFlags)),
                        "instantiatorAddress": address(table.instantiatorAddress),
                        "instantiatorRawValue": table.instantiatorRawValue.map { .int(Int64($0)) } ?? .null,
                        "privateDataAddress": address(table.privateDataAddress)
                    ])
                }
                return .object(result)
            }),
            "protocols": .array(protocols.map { .object([
                "name": .string($0.name), "descriptorAddress": address($0.descriptorAddress),
                "requirementSignature": requirements($0.requirementSignature),
                "associatedTypeNames": $0.associatedTypeNames.map { .array($0.map { .string($0) }) } ?? .null
            ]) }),
            "diagnostics": .array(diagnostics.map { .object([
                "address": address($0.address), "grade": .string($0.grade.rawValue),
                "code": string($0.code?.rawValue), "message": .string($0.message)
            ]) })
        ])
    }
}
