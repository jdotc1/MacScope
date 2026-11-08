import Foundation
import Security

public struct SecurityFrameworkRequirementEvaluator: CodeRequirementEvaluating {
    public init() {}

    public func evaluate(codeAt url: URL, requirement: String) throws -> CodeSigningFacts {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess,
              let code else { throw ProxymanInstallationError.invalidSignature }
        var compiled: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &compiled) == errSecSuccess,
              let compiled else { throw ProxymanInstallationError.invalidSignature }
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures)
        // Check integrity separately so a requirement mismatch cannot mask a broken seal.
        guard SecStaticCodeCheckValidity(code, flags, nil) == errSecSuccess else {
            throw ProxymanInstallationError.invalidSignature
        }
        let status = SecStaticCodeCheckValidity(code, flags, compiled)
        guard status == errSecSuccess || status == errSecCSReqFailed else {
            throw ProxymanInstallationError.invalidSignature
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let dictionary = information as? [String: Any] else {
            throw ProxymanInstallationError.invalidSignature
        }
        let signingFlags = (dictionary[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let hash = (dictionary[kSecCodeInfoUnique as String] as? Data)?.map {
            String(format: "%02x", $0)
        }.joined()
        return CodeSigningFacts(
            signingIdentifier: dictionary[kSecCodeInfoIdentifier as String] as? String,
            teamIdentifier: dictionary[kSecCodeInfoTeamIdentifier as String] as? String,
            cdhash: hash,
            hardenedRuntime: signingFlags & 0x10000 != 0,
            isAdHoc: signingFlags & 0x2 != 0,
            requirementSatisfied: status == errSecSuccess
        )
    }
}
