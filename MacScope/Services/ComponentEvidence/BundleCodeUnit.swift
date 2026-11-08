// Adapted from the AIRS component evidence core at donor commit fa5a2f3128da9134969055cebea145e2ca144214.
// Original relative path: native/Sources/AIRSCore/BundleCodeUnit.swift.
// License: MIT, Copyright (c) 2026 Jeffrey D. Cooney; the notice is in ThirdParty/AIRS/LICENSE.
// Adaptations: declaration locations derived from the retained relative path bytes (no URL resolution), exact
// executable binding, descriptor-relative preflight against the active session.

import Darwin
import Foundation

extension ComponentEvidence {
    /// Where a code unit declares its Info.plist, resources and executable directory, as retained relative paths.
    struct CodeUnitDeclarationLocations: Sendable, Equatable {
        let container: RelativePath?
        let kind: ExactUTF8Key
        let infoPath: RelativePath
        let resourcePath: RelativePath
        let executablePrefix: RelativePath
        var privacyPath: RelativePath { RelativePath(unchecked: resourcePath.components + [ExactUTF8Key("PrivacyInfo.xcprivacy")]) }

        private static let containerKinds: [String: String] = [
            "app": "app", "xpc": "xpc", "appex": "extension", "framework": "framework", "bundle": "bundle",
        ]

        static func extensionOf(_ key: ExactUTF8Key) -> String? {
            guard let dot = key.bytes.lastIndex(of: 0x2e), dot > 0, dot < key.bytes.count - 1 else { return nil }
            let tail = Array(key.bytes[(dot + 1)...])
            guard tail.allSatisfy({ $0 < 0x80 }) else { return nil }
            return String(decoding: tail, as: UTF8.self).lowercased()
        }

        /// Locations for a component at `path`; nil when the path cannot name a component.
        static func locations(for path: RelativePath) -> CodeUnitDeclarationLocations? {
            let parts = path.components
            guard parts.count >= 2 else { return nil }
            var containerIndex: Int?
            var containerExtension: String?
            for index in stride(from: parts.count - 2, through: 0, by: -1) {
                if let ext = extensionOf(parts[index]), containerKinds[ext] != nil { containerIndex = index; containerExtension = ext; break }
            }
            let rootInfo = RelativePath(unchecked: ["Contents", "Info.plist"].map { ExactUTF8Key($0) })
            let rootResources = RelativePath(unchecked: ["Contents", "Resources"].map { ExactUTF8Key($0) })
            let rootMacOS = RelativePath(unchecked: ["Contents", "MacOS"].map { ExactUTF8Key($0) })
            guard let containerIndex, let containerExtension, let kind = containerKinds[containerExtension] else {
                let helper = parts.count >= 3 && (parts[1] == ExactUTF8Key("Helpers") || parts[1] == ExactUTF8Key("LoginItems"))
                let principal = parts.count == 3 && parts[0] == ExactUTF8Key("Contents") && parts[1] == ExactUTF8Key("MacOS")
                return CodeUnitDeclarationLocations(container: nil, kind: ExactUTF8Key(principal ? "app" : helper ? "helper" : "image"),
                                                    infoPath: rootInfo, resourcePath: rootResources, executablePrefix: rootMacOS)
            }
            let container = path.prefix(containerIndex + 1)
            let base = container.components
            func make(_ tail: [String]) -> RelativePath { RelativePath(unchecked: base + tail.map { ExactUTF8Key($0) }) }
            if kind == "framework" {
                let after = parts.count - containerIndex - 1
                if after >= 3, parts[containerIndex + 1] == ExactUTF8Key("Versions") {
                    let version = parts[containerIndex + 2].text ?? ""
                    return CodeUnitDeclarationLocations(
                        container: container, kind: ExactUTF8Key(kind), infoPath: make(["Versions", version, "Resources", "Info.plist"]),
                        resourcePath: make(["Versions", version, "Resources"]), executablePrefix: make(["Versions", version]))
                }
                return CodeUnitDeclarationLocations(container: container, kind: ExactUTF8Key(kind),
                    infoPath: make(["Resources", "Info.plist"]), resourcePath: make(["Resources"]), executablePrefix: container)
            }
            return CodeUnitDeclarationLocations(container: container, kind: ExactUTF8Key(kind),
                infoPath: make(["Contents", "Info.plist"]), resourcePath: make(["Contents", "Resources"]),
                executablePrefix: make(["Contents", "MacOS"]))
        }
    }

    /// Re-validates one provenance record against the retained root. No pathname is reopened.
    struct CodeUnitPreflight {
        static func revalidate(_ provenance: BundleImageProvenance, session: ActiveSession) throws {
            guard provenance.session == session.id else { throw EvidenceError.staleCapability }
            let range = PathRange.leaf(provenance.path)
            guard UInt64(UInt32(bitPattern: session.rootStat.st_dev)) == provenance.rootDevice,
                  session.rootStat.st_ino == provenance.rootInode else { throw EvidenceError.changedInput(range) }
            let handle = try session.ops.openRelative(session.root, provenance.path, directory: false)
            defer { session.ops.close(handle) }
            let info = try session.ops.stat(handle, range)
            guard provenance.fileIdentity.matches(info) else { throw EvidenceError.changedInput(range) }
        }

        /// The component must resolve its executable by the exact declared path binding.
        static func bindExecutable(_ locations: CodeUnitDeclarationLocations, executable: ExactUTF8Key, path: RelativePath) throws {
            guard let bound = try? RelativePath(components: locations.executablePrefix.components + [executable]), bound == path else {
                throw EvidenceError.malformedMetadata(.info, .leaf(locations.infoPath), .executablePathMismatch)
            }
        }
    }
}
