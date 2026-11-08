import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore
@testable import MacScopeDebuggerCore

final class NativeFunctionProtocolChecks: XCTestCase {
 func testNewNativeExecutionContracts() throws {
  let id = UUID(), token = String(repeating: "a", count: 64)
  let base: [String: Any] = ["schema": 1, "sequence": 1, "token": token, "requestID": id.uuidString.lowercased(), "phase": "begin", "ok": true, "error": NSNull()]
  var cases = 0
  func encoded(_ fields: [String: Any]) throws -> String { "MACSCOPE_NATIVE_V1 " + String(decoding: try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys]), as: UTF8.self) }
  func decode(_ record: String) throws { _ = try NativeLLDBCallDecoder.phase(record, requestID: id, token: token, sequence: 1, expectedPhase: "begin") }
  func rejected(_ record: String) { do { try decode(record); fatalError("malformed packet accepted") } catch { cases += 1 } }
  try decode(encoded(base)); cases += 1
  for (field, value) in [("schema", 2 as Any), ("sequence", 2 as Any), ("token", "stale" as Any), ("requestID", UUID().uuidString as Any), ("unknown", true as Any), ("phase", "call" as Any)] {
   var modified = base; modified[field] = value; rejected(try encoded(modified))
  }
  let valid = try encoded(base)
  rejected(valid.replacingOccurrences(of: "\"schema\":1", with: "\"schema\":1,\"schema\":1"))
  rejected(valid.replacingOccurrences(of: "\"schema\":1", with: "\"schema\":1.0"))
  rejected(valid + "\nextra")
  rejected(valid + String(repeating: " ", count: 49152))
  var failed = base; failed["ok"] = false; failed["error"] = "bounded failure"; rejected(try encoded(failed))
  print("\(cases) new production protocol framing and identity cases passed")
 }
}
