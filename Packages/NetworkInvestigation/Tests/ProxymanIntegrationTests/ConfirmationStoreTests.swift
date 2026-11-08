import Foundation
import Testing
@testable import ProxymanIntegration
@testable import ProxymanInstallation

private let firstConfirmationHash = "7377bdde652ac52e878dab48880cefd3d2ac19fa"
private let secondConfirmationHash = "b217149f42a4941b289e5959d3de3dee99a8136e"
private let oneConfirmationJSON = "{\"cdhashes\":[\"7377bdde652ac52e878dab48880cefd3d2ac19fa\"],\"version\":1}"

private struct StoredConfirmations: Decodable {
    let cdhashes: [String]
    let version: Int
}

private func writeConfirmationFixture(_ text: String, to url: URL) throws {
    try Data(text.utf8).write(to: url)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
}

private func confirmationMode(at url: URL) throws -> Int {
    let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
    return try #require(attributes[.posixPermissions] as? NSNumber).intValue
}

private func confirmationText(at url: URL) throws -> String {
    try String(contentsOf: url, encoding: .utf8)
}

private func confirmationHash(_ value: Int) -> String {
    String(format: "%040llx", Int64(value))
}

private func confirmationDocument(_ hashes: [String]) throws -> String {
    struct Document: Encodable {
        let cdhashes: [String]
        let version = 1
    }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return String(decoding: try encoder.encode(Document(cdhashes: hashes)), as: UTF8.self)
}

@Suite(.serialized)
struct ConfirmationStoreTests {
    @Test func readingMissingFileCreatesNothing() async throws {
        let directory = try TemporaryDirectory(); defer { directory.remove() }
        let parent = directory.url.appendingPathComponent("missing")
        let file = parent.appendingPathComponent("confirmations.json")
        let store = FileProxymanBuildConfirmationStore(fileURL: file)
        #expect(await store.isConfirmed(cdhash: firstConfirmationHash) == false)
        #expect(FileManager.default.fileExists(atPath: file.path) == false)
        #expect(FileManager.default.fileExists(atPath: parent.path) == false)
    }

    @Test func confirmationCreatesCanonicalPrivateFileAndDirectory() async throws {
        let directory = try TemporaryDirectory(); defer { directory.remove() }
        let parent = directory.url.appendingPathComponent("missing")
        let file = parent.appendingPathComponent("confirmations.json")
        let store = FileProxymanBuildConfirmationStore(fileURL: file)
        await store.confirm(cdhash: firstConfirmationHash)
        #expect(await store.isConfirmed(cdhash: firstConfirmationHash) == true)
        #expect(await store.isConfirmed(cdhash: secondConfirmationHash) == false)
        #expect(try confirmationText(at: file) == oneConfirmationJSON)
        #expect(try Data(contentsOf: file).count == 69)
        #expect(try confirmationMode(at: file) == 384)
        #expect(try confirmationMode(at: parent) == 448)
        #expect(try FileManager.default.contentsOfDirectory(atPath: parent.path).count == 1)
    }

    @Test func confirmationsPersistOnlyAtTheirOwnURL() async throws {
        let directory = try TemporaryDirectory(); defer { directory.remove() }
        let file = directory.url.appendingPathComponent("confirmations.json")
        await FileProxymanBuildConfirmationStore(fileURL: file).confirm(cdhash: firstConfirmationHash)
        let reloaded = FileProxymanBuildConfirmationStore(fileURL: file)
        let unrelated = FileProxymanBuildConfirmationStore(fileURL: directory.url.appendingPathComponent("other.json"))
        #expect(await reloaded.isConfirmed(cdhash: firstConfirmationHash) == true)
        #expect(await unrelated.isConfirmed(cdhash: firstConfirmationHash) == false)
        try writeConfirmationFixture("{\"cdhashes\":[],\"version\":1}", to: file)
        #expect(await reloaded.isConfirmed(cdhash: firstConfirmationHash) == true)
        #expect(await FileProxymanBuildConfirmationStore(fileURL: file).isConfirmed(cdhash: firstConfirmationHash) == false)
    }

    @Test func repeatedConfirmationDoesNotDuplicateReorderOrRewrite() async throws {
        let directory = try TemporaryDirectory(); defer { directory.remove() }
        let file = directory.url.appendingPathComponent("confirmations.json")
        let store = FileProxymanBuildConfirmationStore(fileURL: file)
        await store.confirm(cdhash: firstConfirmationHash)
        await store.confirm(cdhash: secondConfirmationHash)
        let before = try FileManager.default.attributesOfItem(atPath: file.path)
        let inode = try #require(before[.systemFileNumber] as? NSNumber)
        await store.confirm(cdhash: firstConfirmationHash)
        #expect(try confirmationText(at: file) == "{\"cdhashes\":[\"7377bdde652ac52e878dab48880cefd3d2ac19fa\",\"b217149f42a4941b289e5959d3de3dee99a8136e\"],\"version\":1}")
        #expect(await store.isConfirmed(cdhash: firstConfirmationHash) == true)
        #expect(await store.isConfirmed(cdhash: secondConfirmationHash) == true)
        let after = try FileManager.default.attributesOfItem(atPath: file.path)
        #expect((after[.systemFileNumber] as? NSNumber) == inode)
    }

    @Test func invalidHashesNeverCreatePersistentOrMemoryConsent() async throws {
        let directory = try TemporaryDirectory(); defer { directory.remove() }
        let file = directory.url.appendingPathComponent("confirmations.json")
        let store = FileProxymanBuildConfirmationStore(fileURL: file)
        let invalid = [String(repeating: "a", count: 39), String(repeating: "a", count: 41),
                       String(repeating: "A", count: 40), "", String(repeating: "g", count: 40)]
        for value in invalid { await store.confirm(cdhash: value) }
        for value in invalid { #expect(await store.isConfirmed(cdhash: value) == false) }
        #expect(await store.isConfirmed(cdhash: String(repeating: "a", count: 40)) == false)
        #expect(FileManager.default.fileExists(atPath: file.path) == false)
    }

    @Test func malformedFileReadsEmptyAndCanBeReplacedByConsent() async throws {
        let directory = try TemporaryDirectory(); defer { directory.remove() }
        let file = directory.url.appendingPathComponent("confirmations.json")
        try writeConfirmationFixture("not json", to: file)
        #expect(try Data(contentsOf: file).count == 8)
        let store = FileProxymanBuildConfirmationStore(fileURL: file)
        #expect(await store.isConfirmed(cdhash: firstConfirmationHash) == false)
        await store.confirm(cdhash: firstConfirmationHash)
        #expect(try confirmationText(at: file) == oneConfirmationJSON)
        #expect(await FileProxymanBuildConfirmationStore(fileURL: file).isConfirmed(cdhash: firstConfirmationHash) == true)
    }

    @Test func invalidDocumentShapesRejectTheWholeFile() async throws {
        let directory = try TemporaryDirectory(); defer { directory.remove() }
        let documents = [
            "{\"cdhashes\":[\"7377bdde652ac52e878dab48880cefd3d2ac19fa\"],\"version\":2}",
            "{\"cdhashes\":[\"7377BDDE652AC52E878DAB48880CEFD3D2AC19FA\"],\"version\":1}",
            "{\"cdhashes\":[\"7377bdde652ac52e878dab48880cefd3d2ac19fa\",\"short\"],\"version\":1}",
            "{\"cdhashes\":[],\"version\":1}",
            "{\"cdhashes\":[\"7377bdde652ac52e878dab48880cefd3d2ac19fa\"],\"version\":1,\"extra\":true}",
            "{\"cdhashes\":[\"7377bdde652ac52e878dab48880cefd3d2ac19fa\"]}",
            "{\"cdhashes\":[\"7377bdde652ac52e878dab48880cefd3d2ac19fa\"],\"version\":true}",
            "{\"cdhashes\":[\"7377bdde652ac52e878dab48880cefd3d2ac19fa\"],\"version\":1.0}",
            "{\"cdhashes\":[\"7377bdde652ac52e878dab48880cefd3d2ac19fa\"],\"version\":1e0}",
            "{\"cdhashes\":[\"7377bdde652ac52e878dab48880cefd3d2ac19fa\",1],\"version\":1}",
            "{\"version\":1}",
            "{\"cdhashes\":[\"7377bdde652ac52e878dab48880cefd3d2ac19fa\"],\"version\":1,\"version\":1}"
        ]
        for (index, document) in documents.enumerated() {
            let file = directory.url.appendingPathComponent("shape-\(index).json")
            try writeConfirmationFixture(document, to: file)
            let store = FileProxymanBuildConfirmationStore(fileURL: file)
            #expect(await store.isConfirmed(cdhash: firstConfirmationHash) == false)
            #expect(await store.isConfirmed(cdhash: firstConfirmationHash.uppercased()) == false)
        }
    }

    @Test func readByteLimitIncludesTrailingWhitespace() async throws {
        let directory = try TemporaryDirectory(); defer { directory.remove() }
        let exact = directory.url.appendingPathComponent("exact.json")
        let oversized = directory.url.appendingPathComponent("oversized.json")
        try writeConfirmationFixture(oneConfirmationJSON + String(repeating: " ", count: 65_467), to: exact)
        try writeConfirmationFixture(oneConfirmationJSON + String(repeating: " ", count: 65_468), to: oversized)
        #expect(try Data(contentsOf: exact).count == 65_536)
        #expect(try Data(contentsOf: oversized).count == 65_537)
        #expect(await FileProxymanBuildConfirmationStore(fileURL: exact).isConfirmed(cdhash: firstConfirmationHash) == true)
        #expect(await FileProxymanBuildConfirmationStore(fileURL: oversized).isConfirmed(cdhash: firstConfirmationHash) == false)
    }

    @Test func capacityEvictsOldestWithoutRefreshingRepeatedHashes() async throws {
        let directory = try TemporaryDirectory(); defer { directory.remove() }
        let file = directory.url.appendingPathComponent("confirmations.json")
        let store = FileProxymanBuildConfirmationStore(fileURL: file)
        for value in 0...256 { await store.confirm(cdhash: confirmationHash(value)) }
        await store.confirm(cdhash: confirmationHash(1))
        let reloaded = FileProxymanBuildConfirmationStore(fileURL: file)
        for instance in [store, reloaded] {
            #expect(await instance.isConfirmed(cdhash: "0000000000000000000000000000000000000000") == false)
            #expect(await instance.isConfirmed(cdhash: "0000000000000000000000000000000000000001") == true)
            #expect(await instance.isConfirmed(cdhash: "0000000000000000000000000000000000000100") == true)
        }
        let document = try JSONDecoder().decode(StoredConfirmations.self, from: Data(contentsOf: file))
        #expect(document.version == 1)
        #expect(document.cdhashes.count == 256)
        #expect(document.cdhashes.first == "0000000000000000000000000000000000000001")
        #expect(document.cdhashes.last == "0000000000000000000000000000000000000100")
    }

    @Test func symbolicLinkIsNeitherTrustedNorOverwritten() async throws {
        let directory = try TemporaryDirectory(); defer { directory.remove() }
        let target = directory.url.appendingPathComponent("target.json")
        let file = directory.url.appendingPathComponent("link.json")
        try writeConfirmationFixture(oneConfirmationJSON, to: target)
        try FileManager.default.createSymbolicLink(at: file, withDestinationURL: target)
        let store = FileProxymanBuildConfirmationStore(fileURL: file)
        #expect(await store.isConfirmed(cdhash: firstConfirmationHash) == false)
        await store.confirm(cdhash: secondConfirmationHash)
        #expect(await store.isConfirmed(cdhash: secondConfirmationHash) == true)
        #expect(await FileProxymanBuildConfirmationStore(fileURL: file).isConfirmed(cdhash: secondConfirmationHash) == false)
        #expect(try confirmationText(at: target) == oneConfirmationJSON)
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: file.path) == target.path)
        let realParent = directory.url.appendingPathComponent("real-parent")
        try FileManager.default.createDirectory(at: realParent, withIntermediateDirectories: false)
        let linkedParent = directory.url.appendingPathComponent("linked-parent")
        try FileManager.default.createSymbolicLink(at: linkedParent, withDestinationURL: realParent)
        let nested = linkedParent.appendingPathComponent("missing/confirmations.json")
        let nestedStore = FileProxymanBuildConfirmationStore(fileURL: nested)
        await nestedStore.confirm(cdhash: firstConfirmationHash)
        #expect(await nestedStore.isConfirmed(cdhash: firstConfirmationHash) == true)
        #expect(try FileManager.default.contentsOfDirectory(atPath: realParent.path).count == 0)
        #expect(try FileManager.default.destinationOfSymbolicLink(atPath: linkedParent.path) == realParent.path)
    }

    @Test func concurrentConfirmationsProduceOneCompleteDocument() async throws {
        let directory = try TemporaryDirectory(); defer { directory.remove() }
        let file = directory.url.appendingPathComponent("confirmations.json")
        let store = FileProxymanBuildConfirmationStore(fileURL: file)
        await withTaskGroup(of: Void.self) { group in
            for value in 10...17 {
                group.addTask { await store.confirm(cdhash: confirmationHash(value)) }
            }
        }
        for value in 10...17 { #expect(await store.isConfirmed(cdhash: confirmationHash(value)) == true) }
        let document = try JSONDecoder().decode(StoredConfirmations.self, from: Data(contentsOf: file))
        #expect(document.version == 1)
        #expect(document.cdhashes.count == 8)
    }

    @Test func existingParentPermissionsArePreserved() async throws {
        let directory = try TemporaryDirectory(); defer { directory.remove() }
        let parent = directory.url.appendingPathComponent("existing")
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o755])
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: parent.path)
        let file = parent.appendingPathComponent("confirmations.json")
        await FileProxymanBuildConfirmationStore(fileURL: file).confirm(cdhash: firstConfirmationHash)
        #expect(try confirmationMode(at: parent) == 493)
        #expect(try confirmationMode(at: file) == 384)
    }

    @Test func installationTrustPersistsPerBridgeBuild() async throws {
        let app = try FakeApplication(); defer { app.remove() }
        let directory = try TemporaryDirectory(); defer { directory.remove() }
        let file = directory.url.appendingPathComponent("confirmations.json")
        let evaluator = RecordingEvaluator()
        let first = makeService(evaluator, store: FileProxymanBuildConfirmationStore(fileURL: file))
        let firstReview = try await first.inspect(applicationURL: app.application)
        #expect(firstReview.applicationCDHash == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        #expect(firstReview.bridgeCDHash == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        #expect(firstReview.trust == .confirmationRequired)
        _ = try await first.confirmAndApprove(reviewID: firstReview.id)
        #expect(try confirmationText(at: file) == "{\"cdhashes\":[\"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\"],\"version\":1}")
        let second = makeService(evaluator, store: FileProxymanBuildConfirmationStore(fileURL: file))
        let secondReview = try await second.inspect(applicationURL: app.application)
        #expect(secondReview.trust == .trusted)
        _ = try await second.approve(reviewID: secondReview.id)
        evaluator.change {
            $0.bridge = CodeSigningFacts(signingIdentifier: "mcp-server", teamIdentifier: "3X57WP8E8V",
                cdhash: "cccccccccccccccccccccccccccccccccccccccc", hardenedRuntime: true,
                isAdHoc: false, requirementSatisfied: true)
        }
        let third = makeService(evaluator, store: FileProxymanBuildConfirmationStore(fileURL: file))
        let thirdReview = try await third.inspect(applicationURL: app.application)
        #expect(thirdReview.trust == .confirmationRequired)
        await #expect(throws: ProxymanInstallationError.confirmationRequired) {
            _ = try await third.approve(reviewID: thirdReview.id)
        }
    }

    @Test func entryLimitsDeduplicationAndDirectoryRefusalFailClosed() async throws {
        let directory = try TemporaryDirectory(); defer { directory.remove() }
        let tooMany = directory.url.appendingPathComponent("too-many.json")
        try writeConfirmationFixture(try confirmationDocument((0...256).map(confirmationHash)), to: tooMany)
        let oversized = FileProxymanBuildConfirmationStore(fileURL: tooMany)
        #expect(await oversized.isConfirmed(cdhash: "0000000000000000000000000000000000000000") == false)
        #expect(await oversized.isConfirmed(cdhash: "0000000000000000000000000000000000000100") == false)
        let full = directory.url.appendingPathComponent("full.json")
        try writeConfirmationFixture(try confirmationDocument((0...255).map(confirmationHash)), to: full)
        let exact = FileProxymanBuildConfirmationStore(fileURL: full)
        #expect(await exact.isConfirmed(cdhash: "0000000000000000000000000000000000000000") == true)
        #expect(await exact.isConfirmed(cdhash: "00000000000000000000000000000000000000ff") == true)
        let duplicates = directory.url.appendingPathComponent("duplicates.json")
        try writeConfirmationFixture(try confirmationDocument(Array(repeating: firstConfirmationHash, count: 257)), to: duplicates)
        #expect(await FileProxymanBuildConfirmationStore(fileURL: duplicates).isConfirmed(cdhash: firstConfirmationHash) == false)
        let deduplicated = directory.url.appendingPathComponent("deduplicated.json")
        try writeConfirmationFixture("{\"cdhashes\":[\"7377bdde652ac52e878dab48880cefd3d2ac19fa\",\"b217149f42a4941b289e5959d3de3dee99a8136e\",\"7377bdde652ac52e878dab48880cefd3d2ac19fa\"],\"version\":1}", to: deduplicated)
        let deduplicating = FileProxymanBuildConfirmationStore(fileURL: deduplicated)
        #expect(await deduplicating.isConfirmed(cdhash: firstConfirmationHash) == true)
        #expect(await deduplicating.isConfirmed(cdhash: secondConfirmationHash) == true)
        await deduplicating.confirm(cdhash: "0000000000000000000000000000000000000003")
        #expect(try confirmationText(at: deduplicated) == "{\"cdhashes\":[\"7377bdde652ac52e878dab48880cefd3d2ac19fa\",\"b217149f42a4941b289e5959d3de3dee99a8136e\",\"0000000000000000000000000000000000000003\"],\"version\":1}")
        let isolated = try TemporaryDirectory(); defer { isolated.remove() }
        let directoryTarget = isolated.url.appendingPathComponent("target")
        try FileManager.default.createDirectory(at: directoryTarget, withIntermediateDirectories: false)
        let refused = FileProxymanBuildConfirmationStore(fileURL: directoryTarget)
        #expect(await refused.isConfirmed(cdhash: firstConfirmationHash) == false)
        await refused.confirm(cdhash: firstConfirmationHash)
        #expect(await refused.isConfirmed(cdhash: firstConfirmationHash) == true)
        #expect(await FileProxymanBuildConfirmationStore(fileURL: directoryTarget).isConfirmed(cdhash: firstConfirmationHash) == false)
        var isDirectory: ObjCBool = false
        #expect(FileManager.default.fileExists(atPath: directoryTarget.path, isDirectory: &isDirectory) == true)
        #expect(isDirectory.boolValue == true)
        #expect(try FileManager.default.contentsOfDirectory(atPath: directoryTarget.path).count == 0)
        #expect(try FileManager.default.contentsOfDirectory(atPath: isolated.url.path).count == 1)
    }

    @Test func onlyRootOwnedTopLevelSymlinksAreExempt() {
        #expect(FileProxymanBuildConfirmationStore.isTrustedSystemLink(path: "/var", ownerID: 0) == true)
        #expect(FileProxymanBuildConfirmationStore.isTrustedSystemLink(path: "/var", ownerID: 501) == false)
        #expect(FileProxymanBuildConfirmationStore.isTrustedSystemLink(path: "/var", ownerID: nil) == false)
        #expect(FileProxymanBuildConfirmationStore.isTrustedSystemLink(path: "/var/folders", ownerID: 0) == false)
        #expect(FileProxymanBuildConfirmationStore.isTrustedSystemLink(path: "/home/x/link", ownerID: 0) == false)
        #expect(FileProxymanBuildConfirmationStore.isTrustedSystemLink(path: "/", ownerID: 0) == false)
    }
}
