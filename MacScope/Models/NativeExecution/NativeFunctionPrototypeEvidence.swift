import Foundation

enum NativeFunctionPrototypeEvidence: Equatable, Sendable {
    case authoritative(NativeFunctionPrototype)
    case needsExplicitSignature(String)
    case ineligible(String)
}
