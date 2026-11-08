import Foundation
import XCTest
@testable import MacScopeAnalysisCore
@testable import MacScopeDebuggerCore

final class NativeFunctionAdmissionChecks: XCTestCase {
 func testNewNativeExecutionContracts() throws {
  var count = 0
  func check(_ value: Bool) { precondition(value); count += 1 }
  func node(_ tag: UInt64, _ offset: Int, _ attributes: [UInt64: DWARFAttributeValue] = [:], _ children: [DWARFDIENode] = []) -> DWARFDIENode {
   DWARFDIENode(tag: tag, attributes: attributes, cuOffset: offset, children: children)
  }
  let integer = node(0x24, 1, [0x0b: .uint(4), 0x3e: .uint(5)])
  let typedef = node(0x16, 2, [0x49: .uint(1)])
  let qualified = node(0x26, 3, [0x49: .uint(2)])
  let pointer = node(0x0f, 4, [0x0b: .uint(8)])
  let parameter = node(0x05, 6, [0x49: .uint(3)])
  let function = node(0x2e, 7, [0x11: .address(4096), 0x49: .uint(4), 0x27: .uint(1)], [parameter])
  func evidence(_ function: DWARFDIENode, types: [DWARFDIENode] = [integer, typedef, qualified, pointer], language: UInt64 = 2) -> NativeFunctionPrototypeEvidence {
   NativeFunctionPrototypeResolver(roots: [node(0x11, 0, [0x13: .uint(language)], types + [function])]).resolve()[4096]!
  }
  if case .authoritative(let prototype) = evidence(function) {
   check(prototype.returnType == .pointer && prototype.parameterTypes == [.int32])
  } else { fatalError("supported DIE declaration rejected") }
  func ineligible(_ value: NativeFunctionPrototypeEvidence) -> Bool { if case .ineligible = value { true } else { false } }
  var altered = function; altered.children.append(node(0x18, 8))
  check(ineligible(evidence(altered)))
  altered = function; altered.children[0].attributes[0x34] = .uint(1)
  check(ineligible(evidence(altered)))
  altered = function; altered.attributes[0x36] = .uint(3)
  check(ineligible(evidence(altered)))
  check(ineligible(evidence(function, language: 0x1e)))
  let impostor = node(0x13, 1, [0x03: .string("int"), 0x0b: .uint(4)])
  check(ineligible(evidence(function, types: [impostor, typedef, qualified, pointer])))
  let float = node(0x24, 1, [0x0b: .uint(4), 0x3e: .uint(4)])
  check(ineligible(evidence(function, types: [float, typedef, qualified, pointer])))
  let cycle = node(0x16, 1, [0x49: .uint(3)])
  check(ineligible(evidence(function, types: [cycle, typedef, qualified, pointer])))
  altered = function; altered.children = []
  check({ if case .authoritative(let value) = evidence(altered) { value.parameterTypes.isEmpty } else { false } }())
  altered.attributes[0x27] = nil
  check({ if case .needsExplicitSignature = evidence(altered) { true } else { false } }())
  print("\(count) new DWARF ABI admission cases passed")
 }
}
