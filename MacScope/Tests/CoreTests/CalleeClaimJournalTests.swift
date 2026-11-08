import Foundation
import XCTest
import CryptoKit
@testable import MacScope

/// Authored, unrun. Synthetic journal fixtures only.
final class CalleeClaimJournalTests: XCTestCase {
    private enum Injected: Error { case failure }
    private let image = EditJournalImageIdentity(slot: 0, name: "synthetic", kind: "test",
        architecture: "test", selectedSliceIndex: nil, uuid: nil, elfGNUBuildID: nil,
        imageByteCount: 0, imageSHA256: String(repeating: "0", count: 64))

    private func file() throws -> URL {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: directory) }
        return directory.appendingPathComponent("claims.journal")
    }

    private func events() throws -> [VACalleeClaimEvent] {
        let inventory = VACalleeInventory(function: VAAddress64(4096), callees: [],
            inventoryDigest: String(repeating: "a", count: 64))
        let binding = VACalleeClaimBinding(imageOwner: UUID(), slot: 0, function: inventory.function,
            analysisGeneration: UUID(), inventoryDigest: inventory.inventoryDigest)
        var ledger = CalleeClaimLedger()
        try ledger.open(claimID: UUID(), inventory: inventory, binding: binding, atMilliseconds: 1)
        try ledger.rebind(claimID: ledger.claimIDs[0], observed: VACalleeClaimObservation(
            imageOwner: binding.imageOwner, generation: UUID(), inventory: inventory), atMilliseconds: 2)
        return ledger.events
    }

    private func writer(_ url: URL) throws -> EditJournalWriter {
        try EditJournalWriter(url: url, header: EditJournalHeader(base: [], images: [image]),
                              sequence: 0, createHeader: true)
    }

    private func claims(_ contents: EditJournalContents) -> [VACalleeClaimEvent] {
        contents.records.compactMap {
            guard case .calleeClaim(_, let event) = $0 else { return nil }
            return event
        }
    }

    // Models the pin's version gate and unknown-kind switch; bypassing the version check
    // independently demonstrates the new record kind is also refused by the old decoder.
    private func oldReader(_ bytes: Data, bypassVersion: Bool = false) throws {
        let lines = bytes.split(separator: 10)
        let header = try JSONDecoder().decode(EditJournalHeader.self, from: Data(lines[0].dropFirst(17)))
        if !bypassVersion && header.version != 1 { throw EditJournalError.corrupt(line: 1) }
        for (index, line) in lines.dropFirst().enumerated() {
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(line.dropFirst(17))) as? [String: Any])
            guard let kind = object["kind"] as? String,
                  ["override", "slotOverrides", "verifiedAnnotation"].contains(kind) else {
                throw EditJournalError.corrupt(line: index + 2)
            }
        }
    }

    func testOldReaderRefusesNewRecordKindAndVersionBeforeRotation() throws {
        let url = try file(), journal = try writer(url), history = try events()
        defer { journal.close() }
        journal.appendCalleeClaim(history[0], priorEvents: [])
        let bytes = try Data(contentsOf: url)
        XCTAssertThrowsError(try oldReader(bytes)) {
            XCTAssertEqual($0 as? EditJournalError, .corrupt(line: 1))
        }
        XCTAssertThrowsError(try oldReader(bytes, bypassVersion: true)) {
            XCTAssertEqual($0 as? EditJournalError, .corrupt(line: 2))
        }
        XCTAssertEqual(try EditJournalReader.read(bytes).header?.version, 2)
    }

    /// R2(b): the leaf Core types ignore unknown members, so the journal reader refuses a claim line
    /// that is not the canonical encoding of the event it decodes to (journal-attach boundary).
    func testOpaqueProjectionUnknownKeyRejectsAtJournalBoundary() throws {
        let first = try XCTUnwrap(events().first)
        let old = try XCTUnwrap(first.binding)
        let epoch = VAProjectionStamp(workspaceID: UUID(), documentID: UUID(), installationID: UUID(),
            revision: 1, digest: String(repeating: "b", count: 64))
        let binding = VACalleeClaimBinding(imageOwner: old.imageOwner, slot: old.slot, function: old.function,
            analysisGeneration: old.analysisGeneration, projectionEpoch: epoch, inventoryDigest: old.inventoryDigest)
        let event = VACalleeClaimEvent(sequence: 1, atMilliseconds: 1, claimID: first.claimID,
            kind: .claimOpened, revision: 1, binding: binding, inventory: first.inventory)
        var header = EditJournalHeader(base: [], images: [image])
        header.version = 2
        let good = try EditJournalCodec.encode(EditJournalRecord.calleeClaim(seq: 1, event: event))
        var bytes = try EditJournalCodec.line(header)
        bytes.append(try EditJournalCodec.line(EditJournalRecord.calleeClaim(seq: 1, event: event)))
        XCTAssertEqual(claims(try EditJournalReader.read(bytes)), [event])
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: good) as? [String: Any])
        var inner = try XCTUnwrap(object["event"] as? [String: Any])
        var bound = try XCTUnwrap(inner["binding"] as? [String: Any])
        var projection = try XCTUnwrap(bound["projectionEpoch"] as? [String: Any])
        projection["unexpected"] = true
        bound["projectionEpoch"] = projection
        inner["binding"] = bound
        object["event"] = inner
        let json = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        var line = Data((EditJournalCodec.hex(SHA256.hash(data: json).prefix(8)) + " ").utf8)
        line.append(json)
        line.append(10)
        var tampered = try EditJournalCodec.line(header)
        tampered.append(line)
        XCTAssertThrowsError(try EditJournalReader.read(tampered)) {
            XCTAssertEqual($0 as? EditJournalError, .corrupt(line: 2))
        }
    }

    func testFirstClaimUpgradePreservesOriginalBaseAndRawUnsavedRecords() throws {
        let url = try file(), journal = try writer(url), history = try events()
        defer { journal.close() }
        journal.appendSlotOverrides(ImageSlot(rawValue: 0), [:])
        let before = try Data(contentsOf: url)
        let oldBody = before.suffix(from: try XCTUnwrap(before.firstIndex(of: 10)) + 1)
        journal.appendCalleeClaim(history[1], priorEvents: [history[0]])
        XCTAssertEqual(journal.observedHealth, .healthy)
        let after = try Data(contentsOf: url)
        let body = after.suffix(from: try XCTUnwrap(after.firstIndex(of: 10)) + 1)
        XCTAssertEqual(Data(body.prefix(oldBody.count)), Data(oldBody))
        let contents = try EditJournalReader.read(after)
        XCTAssertEqual(contents.header?.base, [])
        XCTAssertEqual(contents.records.map(\.seq), [1, 2, 3])
        XCTAssertEqual(claims(contents), history)
    }

    func testRotationKeepsFullLedgerAndOldReaderCannotRotateItAway() throws {
        let url = try file(), journal = try writer(url), history = try events()
        defer { journal.close() }
        journal.appendCalleeClaim(history[0], priorEvents: [])
        journal.appendCalleeClaim(history[1], priorEvents: [history[0]])
        journal.rotate(images: [image], base: [:], calleeClaims: history)
        XCTAssertEqual(journal.observedHealth, .healthy)
        let bytes = try Data(contentsOf: url), contents = try EditJournalReader.read(bytes)
        XCTAssertEqual(claims(contents), history)
        XCTAssertEqual(contents.records.map(\.seq), [1, 2])
        XCTAssertEqual(journal.appendedSequence, 2)
        XCTAssertThrowsError(try oldReader(bytes)) {
            XCTAssertEqual($0 as? EditJournalError, .corrupt(line: 1))
        }
    }

    func testEmptyLedgerJournalAndRotationAreByteIdentical() throws {
        let url = try file(), journal = try writer(url)
        defer { journal.close() }
        let original = try Data(contentsOf: url)
        XCTAssertEqual(original, try EditJournalCodec.line(EditJournalHeader(base: [], images: [image])))
        XCTAssertTrue(String(decoding: original, as: UTF8.self).contains("\"version\":1"))
        journal.rotate(images: [image], base: [:], calleeClaims: [])
        XCTAssertEqual(try Data(contentsOf: url), original)
        XCTAssertEqual(journal.appendedSequence, 0)
    }

    func testTornCalleeClaimTailIsDroppedButMiddleIsCorrupt() throws {
        let history = try events()
        var header = EditJournalHeader(base: [], images: [image])
        header.version = 2
        var bytes = try EditJournalCodec.line(header)
        bytes.append(try EditJournalCodec.line(EditJournalRecord.calleeClaim(seq: 1, event: history[0])))
        let complete = bytes.count
        let last = try EditJournalCodec.line(EditJournalRecord.calleeClaim(seq: 2, event: history[1]))
        bytes.append(last.prefix(40))
        let read = try EditJournalReader.read(bytes)
        XCTAssertEqual(claims(read), [history[0]])
        XCTAssertEqual(read.tornTail?.offset, complete)
        XCTAssertEqual(read.tornTail?.length, 40)
        bytes.append(10)
        bytes.append(last)
        XCTAssertThrowsError(try EditJournalReader.read(bytes)) {
            XCTAssertEqual($0 as? EditJournalError, .corrupt(line: 3))
        }
    }

    func testClaimSlotMustBeMinusOneAndVersionMustBeTwo() throws {
        let history = try events()
        let record = EditJournalRecord.calleeClaim(seq: 1, event: history[0])
        var v1 = try EditJournalCodec.line(EditJournalHeader(base: [], images: [image]))
        v1.append(try EditJournalCodec.line(record))
        XCTAssertThrowsError(try EditJournalReader.read(v1)) {
            XCTAssertEqual($0 as? EditJournalError, .corrupt(line: 2))
        }
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: EditJournalCodec.encode(record)) as? [String: Any])
        object["slot"] = 0
        XCTAssertThrowsError(try JSONDecoder().decode(EditJournalRecord.self,
            from: JSONSerialization.data(withJSONObject: object)))
    }

    func testFailedFirstAppendAndFailedRotationAreSticky() throws {
        let history = try events()
        for phase in ["append", "rotation"] {
            let url = try file(), journal = try writer(url)
            defer { journal.close() }
            if phase == "append" {
                journal.appendHook = { _ in throw Injected.failure }
                journal.appendCalleeClaim(history[0], priorEvents: [])
            } else {
                journal.appendCalleeClaim(history[0], priorEvents: [])
                journal.rotateHook = { if $0 == "rename" { throw Injected.failure } }
                journal.rotate(images: [image], base: [:], calleeClaims: history)
            }
            XCTAssertEqual(journal.observedHealth, .stickyFailed)
            let bytes = try Data(contentsOf: url)
            journal.appendHook = nil
            journal.rotateHook = nil
            journal.appendCalleeClaim(history[1], priorEvents: [history[0]])
            journal.rotate(images: [image], base: [:], calleeClaims: history)
            XCTAssertEqual(try Data(contentsOf: url), bytes)
        }
    }

    func testInterruptedRotationRetainsCompleteOldJournal() throws {
        let url = try file(), journal = try writer(url), history = try events()
        journal.appendCalleeClaim(history[0], priorEvents: [])
        let bytes = try Data(contentsOf: url)
        journal.rotateHook = { if $0 == "rename" { throw Injected.failure } }
        journal.rotate(images: [image], base: [:], calleeClaims: history)
        journal.close()
        XCTAssertEqual(try Data(contentsOf: url), bytes)
        let contents = try EditJournalReader.read(Data(contentsOf: url))
        let reopened = try EditJournalWriter(url: url, header: try XCTUnwrap(contents.header),
            sequence: contents.records.last?.seq ?? 0, createHeader: false,
            expectedContents: bytes)
        defer { reopened.close() }
        reopened.rotate(images: [image], base: [:], calleeClaims: history)
        XCTAssertEqual(reopened.observedHealth, .healthy)
        XCTAssertEqual(claims(try EditJournalReader.read(Data(contentsOf: url))), history)
    }

    func testValidOverLimitClaimRefusesAppendAndRotationBeforeWriting() throws {
        let url = try file(), journal = try writer(url)
        defer { journal.close() }
        let original = try Data(contentsOf: url)
        let entries = (0..<VACalleeClaimLimits.maximumCallees).map { index in
            VACalleeInventoryEntry(callee: VAAddress64(UInt64(index + 8192)), kind: .function,
                name: String(repeating: "x", count: VACalleeClaimLimits.maximumNameBytes),
                callSiteCount: 1, callSites: [VAAddress64(UInt64(index + 65536))], callSitesTruncated: false)
        }
        let inventory = VACalleeInventory(function: VAAddress64(4096), callees: entries,
            inventoryDigest: String(repeating: "a", count: 64))
        let binding = VACalleeClaimBinding(imageOwner: UUID(), slot: 0, function: inventory.function,
            analysisGeneration: UUID(), inventoryDigest: inventory.inventoryDigest)
        var ledger = CalleeClaimLedger()
        try ledger.open(claimID: UUID(), inventory: inventory, binding: binding, atMilliseconds: 1)
        let event = try XCTUnwrap(ledger.events.first)
        XCTAssertThrowsError(try EditJournalCodec.line(EditJournalRecord.calleeClaim(seq: 1, event: event))) {
            XCTAssertEqual($0 as? EditJournalError, .lineTooLarge(maximumBytes: EditJournalCodec.maximumLineBytes))
        }
        journal.appendCalleeClaim(event, priorEvents: [])
        XCTAssertEqual(journal.observedHealth, .stickyFailed)
        XCTAssertEqual(try Data(contentsOf: url), original)
        let rotateURL = try file(), rotation = try writer(rotateURL)
        defer { rotation.close() }
        rotation.rotate(images: [image], base: [:], calleeClaims: ledger.events)
        XCTAssertEqual(rotation.observedHealth, .stickyFailed)
        XCTAssertEqual(try Data(contentsOf: rotateURL), original)
    }

    func testOversizedLineHasTypedRefusalBeforeAnyWrite() throws {
        XCTAssertThrowsError(try EditJournalCodec.line(String(repeating: "x", count: EditJournalCodec.maximumLineBytes))) {
            XCTAssertEqual($0 as? EditJournalError, .lineTooLarge(maximumBytes: 8 * 1_024 * 1_024))
        }
    }

    func testLegalMediumEventsExceedAggregateBudgetWithoutTruncation() throws {
        let url = try file(), journal = try writer(url)
        defer { journal.close() }
        let original = try Data(contentsOf: url)
        let entries = (0..<1024).map { index in
            VACalleeInventoryEntry(callee: VAAddress64(UInt64(index + 8192)), kind: .function,
                name: String(repeating: "x", count: 1024), callSiteCount: 1,
                callSites: [VAAddress64(UInt64(index + 65536))], callSitesTruncated: false)
        }
        let inventory = VACalleeInventory(function: VAAddress64(4096), callees: entries,
            inventoryDigest: String(repeating: "a", count: 64))
        let binding = VACalleeClaimBinding(imageOwner: UUID(), slot: 0, function: inventory.function,
            analysisGeneration: UUID(), inventoryDigest: inventory.inventoryDigest)
        let id = UUID()
        var ledger = CalleeClaimLedger()
        try ledger.open(claimID: id, inventory: inventory, binding: binding, atMilliseconds: 1)
        for tick in 2...32 {
            try ledger.supersede(claimID: id, inventory: inventory, binding: binding, atMilliseconds: UInt64(tick))
        }
        let last = try XCTUnwrap(ledger.events.last)
        XCTAssertLessThan(try EditJournalCodec.line(EditJournalRecord.calleeClaim(seq: UInt64.max, event: last)).count,
                          EditJournalCodec.maximumLineBytes)
        XCTAssertThrowsError(try EditJournalCodec.validateClaimHistorySize(ledger.events)) {
            XCTAssertEqual($0 as? EditJournalError, .claimHistoryTooLarge(maximumBytes: 24 * 1024 * 1024))
        }
        journal.appendCalleeClaim(last, priorEvents: Array(ledger.events.dropLast()))
        XCTAssertEqual(journal.observedHealth, .stickyFailed)
        XCTAssertEqual(try Data(contentsOf: url), original)
        let otherURL = try file(), rotation = try writer(otherURL)
        defer { rotation.close() }
        rotation.rotate(images: [image], base: [:], calleeClaims: ledger.events)
        XCTAssertEqual(rotation.observedHealth, .stickyFailed)
        XCTAssertEqual(try Data(contentsOf: otherURL), original)
        var header = EditJournalHeader(base: [], images: [image])
        header.version = 2
        var bytes = try EditJournalCodec.line(header)
        for (index, event) in ledger.events.enumerated() {
            bytes.append(try EditJournalCodec.line(EditJournalRecord.calleeClaim(seq: UInt64(index + 1), event: event)))
        }
        XCTAssertThrowsError(try EditJournalReader.read(bytes)) {
            XCTAssertEqual($0 as? EditJournalError, .claimHistoryTooLarge(maximumBytes: 24 * 1024 * 1024))
        }
        XCTAssertEqual(ledger.events.count, 32)
    }
}
