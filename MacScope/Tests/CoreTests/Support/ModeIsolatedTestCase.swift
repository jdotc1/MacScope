import Foundation


#if canImport(XCTest) && (canImport(MacScope) || canImport(RenderAll)) && !NATIVE_DECOMPILER_XPC_CLIENT_FOCUSED_MAIN
import XCTest
import MacScopeTestSupport
#if canImport(MacScope)
@testable import MacScope
#if canImport(MacScopeAnalysisCore)
import MacScopeAnalysisCore
#endif
#elseif canImport(RenderAll)
@testable import RenderAll
#endif

/// All test cases in each importing test module resolve this local alias. The
/// immutable baseline is installed before XCTest schedules the test body;
/// async/detached work does not depend on inheriting an invocation task-local.
class ModeIsolatedTestCase: PlatformXCTestCase {
    override func invokeTest() {
        let environment = ProcessInfo.processInfo.environment
        let installed = MacIRConfiguration.installTestBaseline(.init(
            ssa: environment["MACSCOPE_SSA_LIFTER"] == "1",
            explicitCFG: environment["MACSCOPE_EXPLICIT_CFG"] == "1",
            returnContract: environment["MACSCOPE_RETURN_CONTRACT_TABLE"] == "1"))
        guard installed else {
            XCTFail("A different immutable test mode baseline was already installed")
            return
        }
        #if canImport(MacScope)
        DSThemeStore.installNonpersistingTestSharedStore()
        #endif
        super.invokeTest()
    }
}

typealias XCTestCase = ModeIsolatedTestCase

/// Explicit resolver inputs bypass the immutable runner baseline without resetting it.
final class MacIRPreferenceIsolationTests: XCTestCase {
    private func values(_ preferences: UserDefaults, overrideValue: Bool? = nil,
                        baseline: MacIRConfiguration.TestBaseline? = nil,
                        environment: [String: String] = [:]) -> [Bool] {
        [MacIRConfiguration.resolveSSA(overrideValue: overrideValue, baseline: baseline,
                                      environment: environment, preferences: preferences),
         MacIRConfiguration.resolveExplicitCFG(overrideValue: overrideValue, baseline: baseline,
                                              environment: environment, preferences: preferences),
         MacIRConfiguration.resolveReturnContract(overrideValue: overrideValue, baseline: baseline,
                                                 environment: environment, preferences: preferences)]
    }

    func testResolversUseOnlyExplicitSuiteWithIndependentLiteralExpectations() throws {
        let name = "MacIRPreferenceIsolationTests.\(UUID().uuidString)"
        let preferences = try XCTUnwrap(UserDefaults(suiteName: name))
        defer { preferences.removePersistentDomain(forName: name) }
        let keys = ["MacScopeSSALifter", "MacScopeExplicitCFG", "MacScopeReturnContractTable"]
        let before = keys.map { UserDefaults.standard.persistentDomain(forName: "com.jeff.machscope")?[$0] as? NSObject }
        // One-hot inputs also detect accidentally swapped preference keys.
        let expected = [[true, false, false], [false, true, false], [false, false, true]]
        for index in keys.indices {
            for key in keys { preferences.set(false, forKey: key) }
            preferences.set(true, forKey: keys[index])
            XCTAssertEqual(values(preferences), expected[index])
        }
        XCTAssertEqual(before, keys.map { UserDefaults.standard.persistentDomain(forName: "com.jeff.machscope")?[$0] as? NSObject })
    }

    func testResolverPrecedenceHasIndependentLiteralExpectations() throws {
        let name = "MacIRPreferenceIsolationTests.\(UUID().uuidString)"
        let preferences = try XCTUnwrap(UserDefaults(suiteName: name))
        defer { preferences.removePersistentDomain(forName: name) }
        let keys = ["MacScopeSSALifter", "MacScopeExplicitCFG", "MacScopeReturnContractTable"]
        let on = ["MACSCOPE_SSA_LIFTER": "1", "MACSCOPE_EXPLICIT_CFG": "1",
                  "MACSCOPE_RETURN_CONTRACT_TABLE": "1"]
        let off = ["MACSCOPE_SSA_LIFTER": "0", "MACSCOPE_EXPLICIT_CFG": "0",
                   "MACSCOPE_RETURN_CONTRACT_TABLE": "0"]
        for key in keys { preferences.set(false, forKey: key) }
        XCTAssertEqual(values(preferences), [false, false, false])
        XCTAssertEqual(values(preferences, environment: on), [true, true, false])
        XCTAssertEqual(values(preferences, overrideValue: true), [true, true, true])
        XCTAssertEqual(values(preferences, baseline: .init(ssa: true, explicitCFG: true,
                                                         returnContract: true), environment: off),
                       [true, true, true])
        for key in keys { preferences.set(true, forKey: key) }
        XCTAssertEqual(values(preferences), [true, true, true])
        XCTAssertEqual(values(preferences, environment: off), [true, true, true])
        XCTAssertEqual(values(preferences, environment: ["MACSCOPE_SSA_LIFTER": "true",
                                                        "MACSCOPE_EXPLICIT_CFG": "2"]),
                       [true, true, true])
        XCTAssertEqual(values(preferences, baseline: .init(ssa: false, explicitCFG: false,
                                                         returnContract: false), environment: on),
                       [false, false, false])
        XCTAssertEqual(values(preferences, overrideValue: false,
                              baseline: .init(ssa: true, explicitCFG: true, returnContract: true),
                              environment: on), [false, false, false])
        XCTAssertEqual(values(preferences, baseline: .init(ssa: true, explicitCFG: false,
                                                         returnContract: true), environment: on),
                       [true, false, true])
        XCTAssertEqual(values(preferences, overrideValue: true,
                              baseline: .init(ssa: false, explicitCFG: false, returnContract: false),
                              environment: off), [true, true, true])
        for key in keys { preferences.set(false, forKey: key) }
        XCTAssertEqual(values(preferences, environment: off), [false, false, false])
        XCTAssertEqual(values(preferences, environment: ["MACSCOPE_SSA_LIFTER": "true",
                                                        "MACSCOPE_EXPLICIT_CFG": "2"]),
                       [false, false, false])
    }

    // Conservative source guard, not a Swift parser. It follows simple local
    // bindings (including alias chains), not values returned by helper functions.
    private func modeWrites(in source: String) throws -> [String] {
        func matches(_ pattern: String, in text: String) throws -> [[String]] {
            let regex = try NSRegularExpression(pattern: pattern)
            let ns = text as NSString
            return regex.matches(in: text, range: NSRange(location: 0, length: ns.length)).map { match in
                (0..<match.numberOfRanges).map { index in
                    let range = match.range(at: index)
                    return range.location == NSNotFound ? "" : ns.substring(with: range)
                }
            }
        }
        let bindings = try matches(#"\b(?:let|var)\s+(\w+)\s*(?::\s*[\w.]+\??\s*)?=\s*(UserDefaults\s*\.\s*standard|\w+|"MacScope(?:SSALifter|ExplicitCFG|ReturnContractTable|OwnReturnAuthority)")"#, in: source)
        var stores: Set<String> = []
        var keys: Set<String> = []
        var changed = true
        while changed {
            changed = false
            for binding in bindings {
                let value = binding[2].filter { !$0.isWhitespace }
                if value == "UserDefaults.standard" || stores.contains(value) {
                    changed = stores.insert(binding[1]).inserted || changed
                }
                if value.hasPrefix("\"MacScope") || keys.contains(value) {
                    changed = keys.insert(binding[1]).inserted || changed
                }
            }
        }
        let receivers = ([#"UserDefaults\s*\.\s*standard"#] + stores.sorted().map {
            #"\b"# + NSRegularExpression.escapedPattern(for: $0) + #"\b"#
        }).joined(separator: "|")
        let ns = source as NSString
        var findings: [String] = []
        // Find each complete argument list, including nested value expressions.
        let callRegex = try NSRegularExpression(pattern:
            "(?:\(receivers))\\s*\\.\\s*(set|setValue|removeObject|register)\\s*\\(")
        for match in callRegex.matches(in: source, range: NSRange(location: 0, length: ns.length)) {
            var end = NSMaxRange(match.range)
            var depth = 1
            var quoted = false
            var escaped = false
            while end < ns.length && depth > 0 {
                let character = ns.substring(with: NSRange(location: end, length: 1))
                if escaped { escaped = false }
                else if character == "\\" && quoted { escaped = true }
                else if character == "\"" { quoted.toggle() }
                else if !quoted && character == "(" { depth += 1 }
                else if !quoted && character == ")" { depth -= 1 }
                end += 1
            }
            let arguments = ns.substring(with: NSRange(location: NSMaxRange(match.range),
                                                       length: end - NSMaxRange(match.range)))
            let literal = #""MacScope(?:SSALifter|ExplicitCFG|ReturnContractTable|OwnReturnAuthority)""#
            let keyPatterns = ([literal] + keys.sorted().map {
                #"\b"# + NSRegularExpression.escapedPattern(for: $0) + #"\b"#
            }).joined(separator: "|")
            if !(try matches(keyPatterns, in: arguments)).isEmpty {
                findings.append(ns.substring(with: NSRange(location: match.range.location,
                                                           length: end - match.range.location)))
            }
        }
        return findings
    }

    func testSourceGuardRecognizesWritesButNotReadsOrArguments() throws {
        let writes = [
            #"UserDefaults.standard.set(true, forKey: "MacScopeSSALifter")"#,
            #"let d = UserDefaults.standard; let e = d; let k = "MacScopeExplicitCFG"; e.setValue(false, forKey: k)"#,
            #"let d = UserDefaults.standard; d.removeObject(forKey: "MacScopeReturnContractTable")"#,
            #"UserDefaults.standard.register(defaults: ["MacScopeSSALifter": true])"#,
            #"UserDefaults.standard.set(makeValue(), forKey: "MacScopeExplicitCFG")"#
        ]
        for source in writes { XCTAssertEqual(try modeWrites(in: source).count, 1, source) }
        let reads = [
            #"UserDefaults.standard.bool(forKey: "MacScopeSSALifter")"#,
            #"UserDefaults.standard.persistentDomain(forName: "com.jeff.machscope")"#,
            #"let defaults = UserDefaults.standard; DecompilerOptions(userDefaults: defaults)"#,
            #"let defaults = UserDefaults(suiteName: name); defaults.set(true, forKey: "MacScopeSSALifter")"#
        ]
        for source in reads { XCTAssertEqual(try modeWrites(in: source).count, 0, source) }
    }

    func testCoreTestsDoNotWriteModeKeysToStandardPreferences() throws {
        let ownFile = TestSourceRoot.fileURL(#filePath)
        let coreTests = ownFile.deletingLastPathComponent().deletingLastPathComponent()
        let enumerator = try XCTUnwrap(FileManager.default.enumerator(at: coreTests,
            includingPropertiesForKeys: nil))
        var scanned = 0
        for case let url as URL in enumerator {
            guard url.pathExtension == "swift", url.lastPathComponent != ownFile.lastPathComponent else { continue }
            let source = try String(contentsOf: url, encoding: .utf8)
            XCTAssertEqual(try modeWrites(in: source), [], url.path)
            scanned += 1
        }
        XCTAssertGreaterThan(scanned, 0)
    }
}
#endif
