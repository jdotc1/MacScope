import Foundation

public struct CodeSigningFacts: Sendable, Equatable {
    public var signingIdentifier: String?
    public var teamIdentifier: String?
    public var cdhash: String?
    public var hardenedRuntime: Bool
    public var isAdHoc: Bool
    public var requirementSatisfied: Bool

    public init(signingIdentifier: String?, teamIdentifier: String?, cdhash: String?,
                hardenedRuntime: Bool, isAdHoc: Bool, requirementSatisfied: Bool) {
        self.signingIdentifier = signingIdentifier
        self.teamIdentifier = teamIdentifier
        self.cdhash = cdhash
        self.hardenedRuntime = hardenedRuntime
        self.isAdHoc = isAdHoc
        self.requirementSatisfied = requirementSatisfied
    }
}

public protocol CodeRequirementEvaluating: Sendable {
    func evaluate(codeAt url: URL, requirement: String) throws -> CodeSigningFacts
}
