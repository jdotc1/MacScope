import XCTest
@testable import MacScope

/// Registration and argument tests for the AR0 reads. Direct authority only: no worker, store or server is started.
@MainActor
final class AIRSMCPRegistrationTests: XCTestCase {
    private let both = [AIRSMCPReads.unwindCommand, AIRSMCPReads.swiftErrorCommand]
    private let fiveArguments = ["cursor", "function", "imageSlot", "limit", "model"]

    func testCatalogContainsBothReads() throws {
        for name in both {
            XCTAssertEqual(NavigatorMCPCommands.names.filter { $0 == name }.count, 1, name)
            XCTAssertEqual(NavigatorMCPCommands.catalog.filter { $0.name == name }.count, 1, name)
            XCTAssertEqual(HeadlessAutomationAuthority.availableCommands.filter { $0.name == name }.count, 1, name)
            let info = try XCTUnwrap(NavigatorMCPCommands.info(name))
            XCTAssertFalse(info.mutates, name)
            XCTAssertEqual(info.arguments.sorted(), fiveArguments, name)
        }
        XCTAssertEqual(NavigatorMCPCommands.requiredArguments(for: AIRSMCPReads.unwindCommand), ["imageSlot"])
        XCTAssertEqual(NavigatorMCPCommands.requiredArguments(for: AIRSMCPReads.swiftErrorCommand), ["imageSlot", "function"])
    }

    func testSchemasKeepSharedModelSupersetHonest() throws {
        let model = NavigatorMCPCommands.argumentSchema("model")
        XCTAssertEqual(model["enum"]?.arrayValue?.compactMap(\.stringValue), ["v1", "v4", "registerCopiesV2", "regionsV1", "outcomeWitnessV2"])
        XCTAssertEqual(model["default"]?.stringValue, "v1")
        let cursor = NavigatorMCPCommands.argumentSchema("cursor")
        XCTAssertEqual(cursor["maxLength"]?.intValue, 1024)
        XCTAssertFalse(try XCTUnwrap(cursor["description"]?.stringValue).lowercased().contains("next"))
        let unwind = try XCTUnwrap(NavigatorMCPCommands.info(AIRSMCPReads.unwindCommand)).summary
        let swift = try XCTUnwrap(NavigatorMCPCommands.info(AIRSMCPReads.swiftErrorCommand)).summary
        XCTAssertTrue(unwind.contains("v1") && unwind.contains("v4") && !unwind.contains("regionsV1") && !unwind.contains("outcomeWitnessV2"))
        XCTAssertTrue(swift.contains("registerCopiesV2") && swift.contains("regionsV1") && swift.contains("outcomeWitnessV2") && !swift.contains("v4 only"))
        XCTAssertEqual(AIRSMCPReads.defaultLimit, 100)
        XCTAssertEqual(AIRSMCPReads.maximumLimit, 256)
    }

    func testAttachAllowlistRequiresExplicitLandingLine() {
        for name in both {
            XCTAssertTrue(MCPAttachExecutor.attachCommands.contains(name), name)
            XCTAssertTrue(NavigatorMCPCommands.attachable.contains(name), name)
            XCTAssertFalse(try! XCTUnwrap(NavigatorMCPCommands.info(name)).mutates)
        }
        XCTAssertFalse(MCPAttachExecutor.attachCommands.contains("navigator-revert"))
    }

    private struct Invalid {
        var command: String
        var fields: [String: ScriptValue]
        var field: String
        var code: MCPRefusalCode
    }

    func testP1AllInvalidInputs() throws {
        let u = AIRSMCPReads.unwindCommand, s = AIRSMCPReads.swiftErrorCommand
        let slot: ScriptValue = .int(0)
        let cases: [Invalid] = [
            .init(command: u, fields: [:], field: "imageSlot", code: .malformedInput),
            .init(command: u, fields: ["imageSlot": .null], field: "imageSlot", code: .malformedInput),
            .init(command: u, fields: ["imageSlot": .double(1.0)], field: "imageSlot", code: .malformedInput),
            .init(command: u, fields: ["imageSlot": .bool(true)], field: "imageSlot", code: .malformedInput),
            .init(command: u, fields: ["imageSlot": .int(-1)], field: "imageSlot", code: .outOfBounds),
            .init(command: u, fields: ["imageSlot": .int(1 << 40)], field: "imageSlot", code: .outOfBounds),
            .init(command: u, fields: ["imageSlot": .string("")], field: "imageSlot", code: .malformedInput),
            .init(command: u, fields: ["imageSlot": .string(String(repeating: "x", count: 65))], field: "imageSlot", code: .outOfBounds),
            .init(command: u, fields: ["imageSlot": slot, "limit": .int(0)], field: "limit", code: .outOfBounds),
            .init(command: u, fields: ["imageSlot": slot, "limit": .int(-1)], field: "limit", code: .outOfBounds),
            .init(command: u, fields: ["imageSlot": slot, "limit": .int(257)], field: "limit", code: .outOfBounds),
            .init(command: u, fields: ["imageSlot": slot, "limit": .double(1.0)], field: "limit", code: .malformedInput),
            .init(command: u, fields: ["imageSlot": slot, "limit": .string("5")], field: "limit", code: .malformedInput),
            .init(command: u, fields: ["imageSlot": slot, "model": .null], field: "model", code: .malformedInput),
            .init(command: u, fields: ["imageSlot": slot, "model": .int(1)], field: "model", code: .malformedInput),
            .init(command: u, fields: ["imageSlot": slot, "model": .string("v2")], field: "model", code: .malformedInput),
            .init(command: u, fields: ["imageSlot": slot, "model": .string("v3")], field: "model", code: .malformedInput),
            .init(command: u, fields: ["imageSlot": slot, "model": .string("regionsV1")], field: "model", code: .malformedInput),
            .init(command: s, fields: ["imageSlot": slot, "function": .string("0x1000"), "model": .string("v4")], field: "model", code: .malformedInput),
            .init(command: s, fields: ["imageSlot": slot], field: "function", code: .malformedInput),
            .init(command: s, fields: ["imageSlot": slot, "function": .string("0x")], field: "function", code: .malformedInput),
            .init(command: s, fields: ["imageSlot": slot, "function": .string("1000")], field: "function", code: .malformedInput),
            .init(command: s, fields: ["imageSlot": slot, "function": .string("0x10000000000000000")], field: "function", code: .malformedInput),
            .init(command: s, fields: ["imageSlot": slot, "function": .string("0xzz")], field: "function", code: .malformedInput),
            .init(command: s, fields: ["imageSlot": slot, "function": .int(4096)], field: "function", code: .malformedInput),
            .init(command: u, fields: ["imageSlot": slot, "cursor": .int(1)], field: "cursor", code: .malformedInput),
            .init(command: u, fields: ["imageSlot": slot, "cursor": .string("!!not-base64")], field: "cursor", code: .malformedInput),
            .init(command: u, fields: ["imageSlot": slot, "cursor": .string(String(repeating: "A", count: 1025))], field: "cursor", code: .outOfBounds),
        ]
        for (index, item) in cases.enumerated() {
            XCTAssertThrowsError(try NavigatorMCPCommands.validateDiagnosed(command: item.command, fields: item.fields),
                                 "case \(index)") { error in
                guard let argument = error as? ToolArgumentError else { return XCTFail("case \(index): \(error)") }
                XCTAssertEqual(argument.refusal.field, item.field, "case \(index)")
                XCTAssertEqual(argument.refusal.code, item.code, "case \(index)")
            }
        }
        XCTAssertThrowsError(try HeadlessAutomationAuthority.validateDiagnosed(command: u, arguments: .array([]))) { error in
            XCTAssertEqual((error as? ToolArgumentError)?.refusal.field, "arguments")
        }
    }

    func testUnknownKeyPrecedesMissingImageOnWire() {
        XCTAssertThrowsError(try HeadlessAutomationAuthority.validateDiagnosed(
            command: AIRSMCPReads.unwindCommand, arguments: .object(["image": .int(0)]))) { error in
            let refusal = (error as? ToolArgumentError)?.refusal
            XCTAssertEqual(refusal?.field, "image")
            XCTAssertEqual(refusal?.code, .malformedInput)
            XCTAssertEqual(refusal?.detail, "Field 'image' is not an allowed argument.")
            XCTAssertEqual(refusal?.allowed, fiveArguments)
        }
        XCTAssertThrowsError(try NavigatorMCPCommands.validateDiagnosed(
            command: AIRSMCPReads.unwindCommand, fields: ["image": .int(0)])) { error in
            XCTAssertEqual((error as? ToolArgumentError)?.refusal.field, "imageSlot")
        }
    }

    func testOmittedModelAlwaysV1() throws {
        for command in both {
            var fields: [String: ScriptValue] = ["imageSlot": .int(0), "function": .string("0x1000")]
            let omitted = try AIRSMCPReads.parse(command: command, fields: fields)
            fields["model"] = .string("v1")
            let explicit = try AIRSMCPReads.parse(command: command, fields: fields)
            XCTAssertEqual(omitted, explicit)
            XCTAssertEqual(omitted.model, .v1)
            XCTAssertEqual(omitted.limit, 100)
            XCTAssertEqual(omitted.model.modelID(for: command),
                           command == AIRSMCPReads.unwindCommand ? "arm64-bounded-loops-cfa-register-v1"
                                                                 : "macscope-swift-error-flow-native-v1")
        }
    }

    func testRegisterCopiesRequiresExplicitSelection() throws {
        let fields: [String: ScriptValue] = ["imageSlot": .int(0), "function": .string("0x1000")]
        XCTAssertEqual(try AIRSMCPReads.parse(command: AIRSMCPReads.swiftErrorCommand, fields: fields).model, .v1)
        var explicit = fields
        explicit["model"] = .string("registerCopiesV2")
        let parsed = try AIRSMCPReads.parse(command: AIRSMCPReads.swiftErrorCommand, fields: explicit)
        XCTAssertEqual(parsed.model, .registerCopiesV2)
        XCTAssertEqual(parsed.model.modelID(for: AIRSMCPReads.swiftErrorCommand), SwiftErrorFlowModel.registerCopiesV2.rawValue)
        // The authored window decides: v1 abstains, v2 recovers the register-copy edge.
        let request = AIRSReadFixtures.swiftRequest(window: [0xaa1503f3, 0xb4000073])
        let v1 = try XCTUnwrap(AIRSReadFixtures.builtReport(AIRSReadBuilder.swift(
            raw: AIRSReadFixtures.rawEdges(request, model: .v1),
            context: AIRSReadFixtures.context(command: AIRSMCPReads.swiftErrorCommand, model: .v1, function: 0x1000))))
        XCTAssertEqual(v1.rows.count, 0)
        XCTAssertEqual(v1.denominators.fields["selectedAbstentionsByCode"]?["intervening_instruction_or_test_unsupported"]?.intValue, 1)
        let v2 = try XCTUnwrap(AIRSReadFixtures.builtReport(AIRSReadBuilder.swift(
            raw: AIRSReadFixtures.rawEdges(request, model: .registerCopiesV2),
            context: AIRSReadFixtures.context(command: AIRSMCPReads.swiftErrorCommand, model: .registerCopiesV2, function: 0x1000))))
        XCTAssertEqual(v2.rows.count, 1)
        XCTAssertEqual(v2.rows[0]["edge"]?["testedRegister"]?.intValue, 19)
        XCTAssertEqual(v2.header["analysisModelVersion"]?.stringValue, SwiftErrorFlowModel.registerCopiesV2.rawValue)
    }

    func testRegionsRequiresExplicitSelection() throws {
        let command = AIRSMCPReads.swiftErrorCommand
        let request = AIRSReadFixtures.regionRequest()
        let plain = try XCTUnwrap(AIRSReadFixtures.builtReport(AIRSReadBuilder.swift(
            raw: AIRSReadFixtures.rawEdges(request), context: AIRSReadFixtures.context(command: command, function: 0x1000))))
        XCTAssertFalse(plain.rows.isEmpty)
        for row in plain.rows {
            XCTAssertEqual(row["region"], .null)
            XCTAssertEqual(row["regionAvailability"]?.stringValue, "notRequested")
        }
        let regions = try XCTUnwrap(AIRSReadFixtures.builtReport(AIRSReadBuilder.swift(
            raw: AIRSReadFixtures.rawRegions(request),
            context: AIRSReadFixtures.context(command: command, model: .regionsV1, function: 0x1000))))
        XCTAssertFalse(regions.rows.isEmpty)
        for row in regions.rows {
            XCTAssertEqual(row["regionAvailability"]?.stringValue, "present")
            let region = try XCTUnwrap(row["region"])
            XCTAssertEqual(region["callReturnProven"]?.boolValue, false)
            XCTAssertEqual(region["joinReachabilityProven"]?.boolValue, false)
            XCTAssertEqual(region["sourceReconstructionAllowed"]?.boolValue, false)
            XCTAssertEqual(region["runtimeReachabilityProven"]?.boolValue, false)
        }
    }

    func testServiceOnlyUnwindModelsRejected() {
        for model in ["v2", "v3", "arm64-bounded-loop-calls-cfa-register-v2"] {
            XCTAssertThrowsError(try AIRSMCPReads.parse(
                command: AIRSMCPReads.unwindCommand, fields: ["imageSlot": .int(0), "model": .string(model)])) { error in
                let refusal = (error as? ToolArgumentError)?.refusal
                XCTAssertEqual(refusal?.field, "model", model)
                XCTAssertEqual(refusal?.code, .malformedInput, model)
                XCTAssertEqual(refusal?.allowed, ["v1", "v4"], model)
            }
        }
    }
}
