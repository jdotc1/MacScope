import CryptoKit
import Foundation
import XCTest
// MacScopeApp product/module is MacScope; CoreTests separately receives the
// current implicit testable import of MacScopeAnalysisCore from project.yml.
@testable import MacScope

/// Synthetic bundle fixtures establish no shipped-corpus provenance.
final class FunctionSignatureBundleConsumerTests: XCTestCase {
    private let commit = String(repeating: "a", count: 40)
    private let functionBytes = Array(UInt8(0)...UInt8(15))
    private func u16(_ value: UInt16) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value), UInt8(truncatingIfNeeded: value >> 8)]
    }
    private func u32(_ value: UInt32) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: value >> ($0 * 8)) }
    }
    private func text(_ value: String) -> [UInt8] { u16(UInt16(value.utf8.count)) + Array(value.utf8) }
    private func row(_ name: String = "one", mask: [UInt8]? = nil, tailCount: UInt8 = 0,
                     referenceCount: UInt8 = 0) -> [UInt8] {
        var result = text(name)
        result += text("synthetic")
        result += u32(16)
        result += [16]
        result += functionBytes
        result += mask ?? Array(repeating: 255, count: 16)
        result += u32(16)
        result += u32(0)
        result += u32(0)
        result += [tailCount, referenceCount]
        return result
    }
    private func payload(_ rows: [[UInt8]]) -> Data {
        Data([0x46, 0x53, 0x49, 0x47, 1, 0, 1, 0] + u32(UInt32(rows.count)) + rows.flatMap { $0 })
    }
    private func digest(_ bytes: Data) -> String {
        SHA256.hash(data: bytes).map { String(format: "%02x", $0) }.joined()
    }
    private func manifest(_ bytes: Data, producer: String = "synthetic-test",
                          commit: String? = nil, sha: String? = nil, schema: Int = 1,
                          architecture: String = "arm64", length: Int? = nil) -> FunctionSignatureBundleManifest {
        .init(schemaVersion: schema, architecture: architecture, producer: producer,
              sourceCommit: commit ?? self.commit, payloadSHA256: sha ?? digest(bytes),
              payloadBytes: length ?? bytes.count)
    }
    private func policy(_ bytes: Data) -> FunctionSignatureBundleConsumer {
        // This local fixture policy is assembled separately from untrusted manifest decoding.
        // It establishes no production trust or provenance.
        .init(independentTrustedPins: [.init(producer: "synthetic-test", sourceCommit: commit,
                                             payloadSHA256: digest(bytes))])
    }
    private func candidate() -> FunctionSignatureCandidate {
        .init(architecture: .arm64, bytes: functionBytes, importedReferences: [:])
    }

    func testFreshPinnedPayloadUsesExistingModelsAndMatcher() throws {
        let bytes = payload([row()])
        let receipt = try policy(bytes).admitNewPayload(bytes, manifest: manifest(bytes))
        XCTAssertEqual(receipt.database.schemaVersion, FunctionSignatureDatabase.currentSchemaVersion)
        XCTAssertEqual(receipt.matcher.validatedSignatureCount, 1)
        XCTAssertEqual(receipt.matcher.match(candidate()), .unique(.init(name: "one", libraryName: "synthetic")))
    }
    func testProductionWithoutIndependentPinRejectsSelfDescribedManifest() {
        let bytes = payload([row()])
        XCTAssertFalse(FunctionSignatureBundleConsumer.production.isAvailable)
        XCTAssertThrowsError(try FunctionSignatureBundleConsumer.production.admitNewPayload(bytes, manifest: manifest(bytes))) {
            XCTAssertEqual($0 as? FunctionSignatureBundleError, .productionPinUnavailable)
        }
    }
    func testWrongProducerCommitAndDigestCannotBorrowConfiguredPin() {
        let bytes = payload([row()]), consumer = policy(payload([row()]))
        for value in [manifest(bytes, producer: "other"), manifest(bytes, commit: String(repeating: "b", count: 40)),
                      manifest(bytes, sha: String(repeating: "0", count: 64))] {
            XCTAssertThrowsError(try consumer.admitNewPayload(bytes, manifest: value)) {
                XCTAssertEqual($0 as? FunctionSignatureBundleError, .authorityMismatch)
            }
        }
    }
    func testPinnedButWrongDigestRefusesChangedPayload() {
        let original = payload([row()])
        var changed = original
        changed[changed.count - 3] ^= 1
        XCTAssertThrowsError(try policy(original).admitNewPayload(changed, manifest: manifest(original))) {
            XCTAssertEqual($0 as? FunctionSignatureBundleError, .digestMismatch)
        }
    }
    func testManifestSchemaArchitectureLengthAndHexRefuse() {
        let bytes = payload([row()]), consumer = policy(payload([row()]))
        for value in [manifest(bytes, schema: 2), manifest(bytes, architecture: "x86_64"),
                      manifest(bytes, commit: String(repeating: "A", count: 40)),
                      manifest(bytes, length: bytes.count + 1)] {
            XCTAssertThrowsError(try consumer.admitNewPayload(bytes, manifest: value))
        }
    }
    func testWireHeaderAndTrailingBytesRefuseWholePayload() {
        let base = payload([row()])
        for index in [0, 4, 6, 7] {
            var bytes = base; bytes[index] = 0xff
            XCTAssertThrowsError(try policy(bytes).admitNewPayload(bytes, manifest: manifest(bytes))) {
                XCTAssertEqual($0 as? FunctionSignatureBundleError, .wireHeader)
            }
        }
        var trailing = base; trailing.append(0)
        XCTAssertThrowsError(try policy(trailing).admitNewPayload(trailing, manifest: manifest(trailing))) {
            XCTAssertEqual($0 as? FunctionSignatureBundleError, .trailingBytes)
        }
    }
    func testTruncatedPayloadNeverPublishesValidPrefixSubset() {
        var bytes = payload([row(), row("second")]); bytes.removeLast()
        XCTAssertThrowsError(try policy(bytes).admitNewPayload(bytes, manifest: manifest(bytes))) {
            XCTAssertEqual($0 as? FunctionSignatureBundleError, .truncatedPayload)
        }
    }
    func testInvalidNestedCountsRefuseBeforeAllocatingDeclaredArrays() {
        for bytes in [payload([row(tailCount: 9)]), payload([row(referenceCount: 9)]),
                      Data([0x46, 0x53, 0x49, 0x47, 1, 0, 1, 0] + u32(UInt32.max))] {
            XCTAssertThrowsError(try policy(bytes).admitNewPayload(bytes, manifest: manifest(bytes))) {
                XCTAssertEqual($0 as? FunctionSignatureBundleError, .countLimit)
            }
        }
    }
    func testNestedByteAndTextLengthsAndUTF8AreBounded() {
        let header: [UInt8] = [0x46, 0x53, 0x49, 0x47, 1, 0, 1, 0] + u32(1)
        let prefix33 = text("one") + text("synthetic") + u32(16) + [33]
        var run = row(); run.removeLast(2); run += [1] + u32(16) + u32(UInt32.max)
        for bytes in [Data(header + prefix33), Data(header + run),
                      Data(header + u16(4097))] {
            XCTAssertThrowsError(try policy(bytes).admitNewPayload(bytes, manifest: manifest(bytes))) {
                XCTAssertEqual($0 as? FunctionSignatureBundleError, .countLimit)
            }
        }
        let invalidText = Data(header + u16(1) + [0xff])
        XCTAssertThrowsError(try policy(invalidText).admitNewPayload(invalidText, manifest: manifest(invalidText))) {
            XCTAssertEqual($0 as? FunctionSignatureBundleError, .invalidUTF8)
        }
    }
    func testOversizedInputRefusesBeforeAdmissionDigest() {
        // The declared size limit is checked before the admission digest.
        let bytes = Data(repeating: 0, count: FunctionSignatureBundleCodec.maximumPayloadBytes + 1)
        let value = manifest(Data(), sha: String(repeating: "0", count: 64), length: bytes.count)
        let consumer = FunctionSignatureBundleConsumer(independentTrustedPins: [
            .init(producer: value.producer, sourceCommit: value.sourceCommit, payloadSHA256: value.payloadSHA256)])
        XCTAssertThrowsError(try consumer.admitNewPayload(bytes, manifest: value)) {
            XCTAssertEqual($0 as? FunctionSignatureBundleError, .authorityMismatch)
        }
    }
    func testRealMatcherPredicateFailureRejectsEntireBundle() {
        var mask = Array(repeating: UInt8(255), count: 16); mask[5] = 127
        let bytes = payload([row(), row("bad", mask: mask)])
        XCTAssertThrowsError(try policy(bytes).admitNewPayload(bytes, manifest: manifest(bytes))) { error in
            guard let bundleError = error as? FunctionSignatureBundleError,
                  case .invalidPredicates(let issues) = bundleError else {
                return XCTFail("Expected real matcher issues")
            }
            XCTAssertTrue(issues.contains { $0.reason == .invalidPrefixMask })
        }
    }
    func testDuplicateIdentityRetainsMatcherDeduplicationAndDifferentIdentityAmbiguity() throws {
        let bytes = payload([row(), row(), row("two")])
        let receipt = try policy(bytes).admitNewPayload(bytes, manifest: manifest(bytes))
        XCTAssertEqual(receipt.matcher.validationIssues.map(\.reason), [.duplicatePredicate])
        XCTAssertEqual(receipt.matcher.validatedSignatureCount, 2)
        XCTAssertEqual(receipt.matcher.match(candidate()), .ambiguous([
            .init(name: "one", libraryName: "synthetic"), .init(name: "two", libraryName: "synthetic")]))
    }
    func testReceiptReuseReturnsSameValidatedObjectWithoutNewPayloadOrHashPath() throws {
        let bytes = payload([row()]), consumer = policy(payload([row()]))
        let receipt = try consumer.admitNewPayload(bytes, manifest: manifest(bytes))
        let reused = try consumer.reuse(receipt)
        XCTAssertTrue(receipt === reused)
        XCTAssertEqual(reused.matcher.match(candidate()), .unique(.init(name: "one", libraryName: "synthetic")))
        // reuse has no new payload input and never reads or hashes retained private bytes.
    }
    func testCallerMutationCannotReplaceRetainedAdmittedValue() throws {
        var bytes = payload([row()])
        let consumer = policy(bytes)
        let receipt = try consumer.admitNewPayload(bytes, manifest: manifest(bytes))
        bytes[0] = 0
        let reused = try consumer.reuse(receipt)
        XCTAssertTrue(receipt === reused)
        XCTAssertEqual(reused.matcher.match(candidate()), .unique(.init(name: "one", libraryName: "synthetic")))
    }
    func testRevokedPolicyDoesNotFallBackToRehashOrReAdmission() throws {
        let bytes = payload([row()])
        let receipt = try policy(bytes).admitNewPayload(bytes, manifest: manifest(bytes))
        XCTAssertThrowsError(try FunctionSignatureBundleConsumer.production.reuse(receipt)) {
            XCTAssertEqual($0 as? FunctionSignatureBundleError, .productionPinUnavailable)
        }
    }
}
