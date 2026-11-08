import Foundation
import XCTest
#if canImport(MacScope)
@testable import MacScope

final class SwiftOutcomeBroadDeclarationTests: XCTestCase {
    private func identity(_ symbol: String, file: StaticString = #filePath, line: UInt = #line) throws -> SwiftBroadCallableIdentity {
        let result = parseBroadSwiftDeclaration(symbol)
        XCTAssertTrue(result.supported, symbol, file: file, line: line)
        return try XCTUnwrap(result.identity, file: file, line: line)
    }
    func testUC23_free_function_ast() throws {
        let result = try identity("$s4Test3fooyS2iKF")
        XCTAssertEqual(result.parameterTypes[0].name, "Swift.Int")
        XCTAssertEqual(result.resultType.name, "Swift.Int"); XCTAssertTrue(result.throwsFlag)
        XCTAssertNil(result.json.object?["error_register"])
        // Swift identities expose immutable let fields; Python FrozenInstanceError has no runtime equivalent.
        XCTAssertEqual(result.functionName, "foo")
    }
    func testUC23_nominal_contexts_and_static() throws {
        for (code, kind) in [("V", "struct_instance_method"), ("O", "enum_instance_method"), ("C", "class_instance_method")] {
            let value = try identity("_$s4Test5OuterV5Inner\(code)3fooyS2iKF")
            XCTAssertEqual(value.callableKind, kind); XCTAssertEqual(value.context.map(\.name), ["Outer", "Inner"])
            XCTAssertEqual(try identity("$s4Test5Owner\(code)3fooyS2iKFZ").callableKind, "static_method")
        }
    }
    func testUC23_types_parameters_and_labels() throws {
        let cases: [(String, [String], String)] = [
            ("$s4Test3fooyyKF", [], "Swift.Void"), ("$s4Test3fooSiyKF", [], "Swift.Int"),
            ("$s4Test3foo1a1bSiSi_SdtKF", ["Swift.Int", "Swift.Double"], "Swift.Int"),
            ("$s4Test3fooyySiSgzKF", ["Optional"], "Swift.Void"),
            ("$s4Test3fooyySf_SbtKF", ["Swift.Float", "Swift.Bool"], "Swift.Void"),
            ("$s4Test3fooyys4Int8V_s6UInt64VtKF", ["Swift.Int8", "Swift.UInt64"], "Swift.Void")]
        for (symbol, parameters, result) in cases {
            let value = try identity(symbol)
            XCTAssertEqual(value.parameterTypes.map(\.name), parameters); XCTAssertEqual(value.resultType.name, result)
        }
        XCTAssertEqual(try identity("$s4Test3foo1a1bSiSi_SdtKF").parameterLabels, ["a", "b"])
        XCTAssertTrue(try identity("$s4Test3fooyySiSgzKF").parameterTypes[0].isInout)
    }
    func testUC23_generics_and_known_substitutions() throws {
        XCTAssertEqual(try identity("$s4Test3fooyxxlF").genericParameterCounts, [1])
        XCTAssertFalse(parseBroadSwiftDeclaration("$s4Test5OwnerV3fooyA2ZKF").supported)
        XCTAssertEqual(try identity("$s4Test5OwnerV3fooyA2CKF").resultType.name, "Test.Owner")
    }
    func testUC23_explicit_family_refusals() {
        let cases = [("$s4Test3fooyyYaKF", "async_context"), ("$s4Test3fooyyAA5ErrorOYKF", "typed_throws"),
            ("$s4Test3fooyyKFTj", "thunk_or_specialization"), ("$s4Test3fooyyKFTg5", "thunk_or_specialization"),
            ("$s4Test3fooyyKFTW", "thunk_or_specialization"), ("$s4Test3fooyS2iKcKF", "closure_type"),
            ("$s4Test3fooyS2iKXEKF", "closure_type"), ("$s4Test3fooyyKFAA", "unconsumed_suffix"),
            ("$s4Test0012vergenza_JFayyF", "unicode_identifier"), ("$s4Test5OwnerV3fooyxxs13BinaryIntegerRzlF", "generic_requirements"),
            ("$s4Test5ActorC3fooyyYaKF", "async_context"), ("$s4Test5ProtoP3fooyyKF", "protocol_context")]
        for (symbol, reason) in cases {
            let result = parseBroadSwiftDeclaration(symbol)
            XCTAssertFalse(result.supported, symbol); XCTAssertEqual(result.unsupportedReason, reason); XCTAssertNil(result.identity)
        }
    }
    func testUC23_bounds_and_malformed_input() {
        // The donor None case maps to the empty String at this typed String API.
        for symbol in ["", "$s", "$s9999999999999999999999999Test", "$s4Test3fooyAZKF", "$s4Test3fooyyKFjunk", "$s4Test3fooyyKF\u{01}"] { XCTAssertFalse(parseBroadSwiftDeclaration(symbol).supported, symbol) }
        XCTAssertEqual(parseBroadSwiftDeclaration("$s4Test3fooyS2iKF", limits: .init(maxSymbolLength: 4)).unsupportedReason, "resource_limit")
        XCTAssertEqual(parseBroadSwiftDeclaration("$s4Test5OwnerV3fooyyKF", limits: .init(maxSubstitutions: 1)).unsupportedReason, "resource_limit")
    }
    func testUC23_annotation_order_and_full_type_tree() throws {
        for symbol in ["$s4Test3fooKyS2iF", "$s4Test3fooyS2iKSiF", "$s4Test3fooyS2illF", "$s4Test3fooyS2iKlKF"] { XCTAssertFalse(parseBroadSwiftDeclaration(symbol).supported, symbol) }
        let array = try identity("$s4Test3fooyySaySiGKF").parameterTypes[0]
        XCTAssertEqual(array.name, "Swift.Array"); XCTAssertEqual(array.arguments[0].name, "Swift.Int")
        let nested = try identity("$s4Test3fooyySi_Sd_SbttKF").parameterTypes[1]
        XCTAssertEqual(nested.name, "Tuple"); XCTAssertEqual(nested.arguments.map(\.name), ["Swift.Double", "Swift.Bool"])
    }
    func testUC23_labels_are_not_types_and_generic_bindings_are_required() {
        for symbol in ["$s4Test3fooyAAKF", "$s4Test3fooyxxF", "$s4Test3fooyxq_lF", "$s4Test3fooyyKFZ", "$s4Test3foo1a1bS2iKF"] { XCTAssertFalse(parseBroadSwiftDeclaration(symbol).supported, symbol) }
    }
    func testUC23_type_depth_budget_and_mixed_labels() throws {
        XCTAssertEqual(parseBroadSwiftDeclaration("$s4Test3fooyySiSgSgKF", limits: .init(maxTypeDepth: 2)).unsupportedReason, "resource_limit")
        XCTAssertEqual(try identity("$s4Test3foo_1bSiSi_SdtKF").parameterLabels, [nil, "b"])
    }
    func testUC23_recorded_owned_word_substituted_contexts() throws {
        let cases = [
            ("_$s10BroadOwned0A9Owner0099V15broad_case_0099ySis6UInt64V_Sis5Int32VtKF", "struct_instance_method", "BroadOwner0099"),
            ("_$s10BroadOwned0A9Owner0180O15broad_case_0180ySis5Int32V_SbSdtKF", "enum_instance_method", "BroadOwner0180"),
            ("_$s10BroadOwned0A9Owner0235C15broad_case_0235yS2i_SSSitKF", "class_instance_method", "BroadOwner0235")]
        for (symbol, kind, owner) in cases {
            let value = try identity(symbol); XCTAssertEqual(value.context[0].name, owner); XCTAssertEqual(value.callableKind, kind)
        }
        XCTAssertEqual(parseBroadSwiftDeclaration("$s10BroadOwned0Z9Owner0099V3fooyyF").unsupportedReason, "unknown_substitution")
        for symbol in ["_$s10BroadOwned15broad_case_0001yS2i_Sis5Int32VtKF", "_$s10BroadOwned0A9Owner0295V15broad_case_0295ySis5Int32V_SaySiGSbtKFZ", "_$s10BroadOwned0A9Owner0340V15broad_case_0340yS2i_S2SxtKSzRzlFZ", "_$s10BroadOwned0A9Owner0375V15broad_case_0375ySis5Int32V_SdSStKF"] { _ = try identity(symbol) }
        XCTAssertEqual(parseBroadSwiftDeclaration("_$s10BroadOwned0A9Owner0084V15broad_case_0084ySis5Int32V_SSSitAA0A5ErrorOYKF").unsupportedReason, "typed_throws")
    }
    func testUC23_recorded_generic_requirement_and_specialized_refusal() throws {
        let base = "_$s10BroadOwned0A9Owner0363V15broad_case_0363ySis5Int32V_s6UInt64VSixtKSzRzlFZ"
        let value = try identity(base)
        XCTAssertEqual(value.genericRequirements[0].protocol, "Swift.BinaryInteger"); XCTAssertEqual(value.genericRequirements[0].parameterIndex, 0)
        XCTAssertEqual(try identity(base + "Si_Tt3g5").specialization?.droppedArgumentOrdinals, [4])
    }
    func testUC23_word_reference_terminators_and_literal_word_boundaries() throws {
        for symbol in ["$s10BroadOwned0AV3fooyyF", "$s10BroadOwned0z9Owner0099V3fooyyF"] { XCTAssertFalse(parseBroadSwiftDeclaration(symbol).supported, symbol) }
        XCTAssertEqual(try identity("$s10BroadOwned0A4_009V3fooyyF").context[0].name, "Broad_009")
    }
    func testUC23_review_duplicate_generic_signature_refuses() {
        for symbol in ["$s4Test3fooyxxlrlF", "$s4Test3fooyxxr_lr_lF"] {
            let result = parseBroadSwiftDeclaration(symbol); XCTAssertFalse(result.supported, symbol); XCTAssertEqual(result.unsupportedReason, "invalid_grammar")
        }
    }
    func testUC23_review_requirement_binding_refuses_zero_count() {
        let result = parseBroadSwiftDeclaration("$s4Test3fooyySzRzrzlF")
        XCTAssertFalse(result.supported); XCTAssertEqual(result.unsupportedReason, "generic_requirements")
    }
    func testUC23_review_nominal_context_preserves_type_role() throws {
        for symbol in ["$s4Test3fooySi_Sdt3BadVyF", "$s4Test3fooyx3BadVylF", "$s4Test3fooySaySiG3BadVyF"] {
            let result = parseBroadSwiftDeclaration(symbol); XCTAssertFalse(result.supported, symbol); XCTAssertEqual(result.unsupportedReason, "invalid_grammar")
        }
        XCTAssertEqual(try identity("$s4Test5OwnerV3fooyAC3SubVyF").resultType.name, "Test.Owner.Sub")
    }
    func testUC23_specialization_recorded_concrete_binding_preserves_template() throws {
        let base = "_$s10BroadOwned0A9Owner0363V15broad_case_0363ySis5Int32V_s6UInt64VSixtKSzRzlFZ"
        let value = try identity(base + "Si_Tt3g5")
        XCTAssertEqual(value.callableKind, "generic_specialization"); XCTAssertEqual(value.originalCallableKind, "static_method")
        XCTAssertEqual(value.parameterTypes.last?.name, "GenericParameter")
        let spec = try XCTUnwrap(value.specialization)
        XCTAssertEqual(spec.kind, "generic_reabstracted"); XCTAssertEqual(spec.passID, 5)
        XCTAssertEqual(spec.droppedArgumentOrdinals, [4]); XCTAssertEqual(spec.bindings[0].replacement.name, "Swift.Int")
        XCTAssertEqual(spec.substitutedParameterTypes.last?.name, "Swift.Int"); XCTAssertEqual(spec.substitutedParameterTypes.count, 4)
        XCTAssertEqual(spec.templateSymbol, base)
    }
    func testUC23_specialization_pure_flags_and_nested_source_types() throws {
        let spec = try XCTUnwrap(identity("$s4Test3fooyxxlFSi_Tgq5").specialization)
        XCTAssertTrue(spec.serialized); XCTAssertEqual(spec.droppedArgumentOrdinals, [])
        let nested = try XCTUnwrap(identity("$s4Test3fooyxSgxlFSi_TG5").specialization)
        XCTAssertEqual(nested.substitutedResultType.arguments[0].name, "Swift.Int")
    }
    func testUC23_specialization_malformed_and_abi_changing_refusals() {
        let base = "$s4Test3fooyxxlF"
        for suffix in ["Si_Tg", "Si_Tg55", "Si_TgX5", "Si_Tt3g5junk", "Si_Tt3t3g5", "Si_SdTg5", "x_Tg5", "SiTg5", "Si_SgTg5"] {
            let result = parseBroadSwiftDeclaration(base + suffix); XCTAssertFalse(result.supported, suffix); XCTAssertNil(result.identity)
        }
        for suffix in ["Tf4nnnd_n", "Tf4nnn_n", "TA", "Tp5"] {
            let result = parseBroadSwiftDeclaration(base + suffix); XCTAssertFalse(result.supported, suffix); XCTAssertEqual(result.unsupportedReason, "thunk_or_specialization")
        }
    }
    func testUC23_specialization_attributes_and_binding_scope() throws {
        let spec = try XCTUnwrap(identity("$s4Test3fooyxxlFSi_Ttt1gqar5").specialization)
        XCTAssertTrue(spec.serialized); XCTAssertTrue(spec.asyncRemoved); XCTAssertTrue(spec.representationChanged)
        XCTAssertEqual(spec.droppedArgumentOrdinals, [0, 2])
        XCTAssertEqual(try identity("$s4Test3fooyxxlFs5Int32V_TB5").specialization?.bindings[0].replacement.name, "Swift.Int32")
        for symbol in ["$s4Test3fooyyFSi_Tg5", "$s4Test3fooyxxr__lFSi_Tg5"] {
            let result = parseBroadSwiftDeclaration(symbol); XCTAssertFalse(result.supported, symbol); XCTAssertEqual(result.unsupportedReason, "generic_requirements")
        }
    }
}
#endif
