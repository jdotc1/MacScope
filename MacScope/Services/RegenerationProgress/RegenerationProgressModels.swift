import Foundation

// Reader-side value types for the frozen regeneration contracts (REGEN-MANIFEST v1/v2,
// DEPENDENCIES v1, STRUCTURE-REPORT v1). They are decoded from untrusted export folders and
// never written back; the writers' own types live under Services/RegenerationExport.

extension RegenerationFunctionState: CaseIterable {
    /// Display order of the five-state bar. Codable raw values are unchanged.
    static var allCases: [RegenerationFunctionState] { [.stub, .external, .filled, .compiles, .accepted] }
}

extension RegenerationLanguage: CaseIterable {
    /// The three languages the manifest contract allows; `.unknown` is never a contract value.
    static var allCases: [RegenerationLanguage] { [.objc, .swift, .c] }
}

enum RegenerationResourceStatus: String, CaseIterable, Sendable { case copied, converted, partial, refused }
enum RegenerationResourceEquivalence: String, CaseIterable, Sendable { case equal, different, notChecked }
enum RegenerationDependencyConfidence: String, CaseIterable, Sendable { case confirmed, probable, candidate }
enum RegenerationDependencyKind: String, Sendable {
    case embeddedFramework, systemFramework, staticLibrary, swiftPackage, unknownThirdParty
}
enum RegenerationDependencyEmission: String, Sendable { case swiftPackage, frameworkReference, systemSDK, none }
enum RegenerationDimensionStatus: String, Sendable { case measured, notMeasured }
enum RegenerationItemOutcome: String, Sendable { case missingInRebuilt, extraInRebuilt, differing }

/// Declaration order is the contract's dimension order.
enum RegenerationDimensionName: String, CaseIterable, Sendable {
    case linkedDylibs, rpaths, exports, imports, objcClasses, objcCategories, objcProtocols, objcMethods
    case objcIvars, objcProperties, swiftTypes, swiftConformances, swiftRequirements, swiftFieldRecords
    case swiftEnumCases, functions
}

/// Outcome of reading one export file. Each file carries its own state so a missing or broken
/// optional file never hides the others.
enum RegenerationFileState: Equatable, Sendable {
    case notProducedYet
    case loaded
    case unsupportedVersion(file: String, field: String, value: String)
    case unsupportedValue(file: String, field: String, value: String)
    case malformed(file: String, path: String, message: String)
    case refusedSymlink(file: String, target: String)
    case refusedOversize(file: String, bytes: Int, limit: Int)
    case unreadable(file: String, message: String)

    var isLoaded: Bool { self == .loaded }

    var summary: String {
        switch self {
        case .notProducedYet: "Not produced yet"
        case .loaded: "Loaded"
        case let .unsupportedVersion(_, field, value): "Unsupported version at \(field): \(value)"
        case let .unsupportedValue(_, field, value): "Unsupported value at \(field): \(value)"
        case let .malformed(_, path, message): "Malformed at \(path): \(message)"
        case let .refusedSymlink(_, target): "Refused: symbolic link leaves the folder (\(target))"
        case let .refusedOversize(_, bytes, limit): "Refused: \(bytes) bytes exceeds the \(limit)-byte limit"
        case let .unreadable(_, message): "Unreadable: \(message)"
        }
    }
}

struct RegenerationExportFile: Equatable, Sendable {
    let name: String
    let state: RegenerationFileState
}

struct RegenerationProgressImage: Equatable, Sendable {
    let imageName: String
    let uuid: String
    let architecture: String
    let sha256: String
}

struct RegenerationProgressFunction: Equatable, Sendable, Identifiable {
    let imageQualifiedAddress: String
    let functionUUID: String
    let name: String?
    let language: RegenerationLanguage
    let stubFile: String?
    let stubLine: Int?
    let state: RegenerationFunctionState
    let dependencyId: String?
    /// True when the record carries a `dependencyId` key at all, null included (a v1 violation).
    let hasDependencyIdKey: Bool

    var id: String { imageQualifiedAddress + "#" + functionUUID }

    /// The image name is everything before the first colon, matching the contract's pattern.
    var imageName: String { RegenerationProgressFunction.imageName(ofAddress: imageQualifiedAddress) }

    static func imageName(ofAddress address: String) -> String {
        address.firstIndex(of: ":").map { String(address[..<$0]) } ?? address
    }
}

struct RegenerationProgressResource: Equatable, Sendable {
    let compiledPath: String
    let sourcePath: String?
    let converter: String?
    let status: RegenerationResourceStatus
    /// nil = no equivalence check was attempted.
    let equivalence: RegenerationResourceEquivalence?
    let receiptPath: String?
}

struct RegenerationProgressManifest: Equatable, Sendable {
    let schemaVersion: Int
    let appName: String
    let images: [RegenerationProgressImage]
    let functions: [RegenerationProgressFunction]
    let resources: [RegenerationProgressResource]
}

struct RegenerationProgressDependency: Equatable, Sendable {
    let id: String
    let name: String
    let kind: RegenerationDependencyKind
    let version: String?
    let confidence: RegenerationDependencyConfidence
    let functions: [String]
    let emitAs: RegenerationDependencyEmission
}

struct RegenerationProgressDependencies: Equatable, Sendable {
    let dependencies: [RegenerationProgressDependency]
}

struct RegenerationProgressReportInput: Equatable, Sendable {
    let path: String
    let sliceSha256: String
    let architecture: String
    let uuid: String
}

struct RegenerationDimensionResult: Equatable, Sendable {
    let dimension: RegenerationDimensionName
    let status: RegenerationDimensionStatus
    let notMeasuredReason: String?
    let matched: Int
    let missingInRebuilt: Int
    let extraInRebuilt: Int
    let differing: Int
    let score: Double?
    /// Per-outcome counts of the listed `items`, kept for the README's rule 1.
    let listedMissing: Int
    let listedExtra: Int
    let listedDiffering: Int
}

struct RegenerationProgressStructureReport: Equatable, Sendable {
    let original: RegenerationProgressReportInput
    let rebuilt: RegenerationProgressReportInput
    let dimensions: [RegenerationDimensionResult]
    let functionStates: [String: Int]?
}

/// Everything one export folder yielded. A payload is present exactly when its file is `.loaded`.
struct RegenerationLoadedExport: Equatable, Sendable {
    static let manifestFileName = "REGEN-MANIFEST.json"
    static let dependenciesFileName = "DEPENDENCIES.json"
    static let reportFileName = "Equivalence/STRUCTURE-REPORT.json"

    var files: [RegenerationExportFile]
    var manifest: RegenerationProgressManifest?
    var dependencies: RegenerationProgressDependencies?
    var report: RegenerationProgressStructureReport?

    static let empty = RegenerationLoadedExport(
        files: [manifestFileName, dependenciesFileName, reportFileName].map {
            RegenerationExportFile(name: $0, state: .notProducedYet)
        },
        manifest: nil, dependencies: nil, report: nil
    )
}

/// An image of the open analysis, supplied by the host as plain values.
struct RegenerationOpenImage: Equatable, Sendable {
    let imageName: String
    let uuid: String
    let sliceSha256: String?
}
