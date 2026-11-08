import Foundation
import AppKit
import SwiftUI
import LumenTokens
import LumenUI
import XCTest
@testable import MacScope

final class CrashReportImportTests: XCTestCase {
    private let uuid = "12345678-1234-1234-1234-123456789ABC"
    private func report(state: String = "", secondState: String = "") throws -> CrashReport {
        let body = """
        {"faultingThread":0,"threads":[{"frames":[{"imageIndex":0,"imageOffset":32}]\(state)},
        {"frames":[]\(secondState)}],"usedImages":[{"uuid":"\(uuid)","base":4294967296,"size":4096}]}
        """
        return try CrashReport.parse(Data(body.utf8))
    }
    private func context(_ id: String, base: UInt64 = 0x2000) -> CrashReportImageContext {
        CrashReportImageContext(uuid: id, preferredBase: base,
            mappedRanges: [base..<(base + 4096)], symbols: [])
    }
    func testARM64RegistersRetainFullUnsignedValuesAndThreadOwnership() throws {
        let value = try report(state: #", "threadState":{"flavor":"ARM_THREAD_STATE64","x":[{"value":18446744073709551615},{"value":0}],"pc":{"value":4294967328},"sp":{"value":42},"esr":{"value":1,"description":"fault"}}"#,
            secondState: #", "threadState":{"flavor":"ARM_THREAD_STATE64","x":[{"value":7}]}"#)
        XCTAssertEqual(value.threads[0].registers.first { $0.name == "x0" }?.value, UInt64.max)
        XCTAssertEqual(value.threads[0].registers.first { $0.name == "pc" }?.value, 4294967328)
        XCTAssertEqual(value.threads[0].registerFlavor, "ARM_THREAD_STATE64")
        XCTAssertEqual(value.threads[1].registers.first { $0.name == "x0" }?.value, 7)
    }
    func testIntelRegistersAndMissingState() throws {
        let value = try report(state: #", "threadState":{"flavor":"x86_THREAD_STATE","rax":{"value":99},"rip":{"value":4294967328},"rflags":{"value":582},"matchesCrashFrame":1}"#)
        XCTAssertEqual(value.threads[0].registers.first { $0.name == "rax" }?.value, 99)
        XCTAssertEqual(value.threads[0].registers.first { $0.name == "rip" }?.value, 4294967328)
        XCTAssertTrue(value.threads[1].registers.isEmpty)
    }
    func testMalformedRegisterValuesRefuseRatherThanInventZero() {
        for value in ["-1", "true", "1.5", "\"42\"", "18446744073709551616"] {
            XCTAssertThrowsError(try report(state: ",\"threadState\":{\"pc\":{\"value\":\(value)}}"))
        }
    }
    func testCrossImageUUIDMatchIgnoresContextOrderAndRefusesAmbiguity() throws {
        let value = try report()
        let frame = value.threads[0].frames[0]
        let contexts = [context("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF"), context(uuid)]
        let match = value.match(frame, contexts: contexts)
        XCTAssertEqual(match.contextIndex, 1)
        XCTAssertEqual(match.resolved.address, 0x2020)
        XCTAssertNil(value.match(frame, contexts: [context(uuid), context(uuid.lowercased())]).resolved.address)
        XCTAssertNil(value.match(frame, contexts: []).contextIndex)
    }
    func testRuntimeAddressUsesReportedLoadBase() throws {
        let value = try report()
        XCTAssertEqual(value.runtimeAddress(of: value.threads[0].frames[0]), 0x100000020)
        let invalid = CrashReportFrame(id: 1, imageIndex: 0, imageOffset: 4096, reportedSymbol: nil)
        XCTAssertNil(value.runtimeAddress(of: invalid))
    }
}

@MainActor
final class CrashReportNavigationTests: XCTestCase {
    func testCrashNavigationFocusesExactOwnerAndRejectsReplacedImage() {
        let slot = ImageSlot(rawValue: 1)
        let a = BinaryImage(id: UUID(), name: "a", path: "/synthetic/a", kind: "executable", architecture: "arm64")
        let b = BinaryImage(id: UUID(), name: "b", path: "/synthetic/b", kind: "executable", architecture: "arm64", slot: slot)
        var analysis = ImageAnalysis()
        analysis.instructions = [InstructionRow(address: 0x1004, bytes: "1f 20 03 d5", mnemonic: "nop", operands: "", hasBreakpoint: false, comment: nil)]
        analysis.sections = [SectionSummary(id: UUID(), name: "__text", address: 0x1000, size: 16, fileOffset: 0, isExecutable: true)]
        analysis.functions = [FunctionSummary(id: UUID(), name: "crashing", startAddress: 0x1000, endAddress: 0x1010, confidence: 1)]
        var snapshot = WorkspaceSnapshot(binaries: [], analysisBySlot: [:])
        snapshot.insertImage(binary: a, analysis: analysis)
        snapshot.insertImage(binary: b, analysis: analysis)
        let store = WorkspaceStore(workspaceName: "Crash test", snapshot: snapshot, engine: AnalysisEngine(), autosaveScheduler: nil)
        XCTAssertTrue(CrashReportWindowPresenter.navigate(0x1004, binary: b, in: store))
        XCTAssertEqual(store.focusedImageSlot, slot)
        XCTAssertEqual(store.selectedAddress, 0x1004)
        XCTAssertEqual(store.editorMode, .pseudocode)
        XCTAssertFalse(CrashReportWindowPresenter.navigate(0x1005, binary: a, in: store))
        XCTAssertEqual(store.focusedImageSlot, slot)
        store.snapshot.mutateAnalysis(in: slot) { analysis in
            analysis.functions.append(FunctionSummary(id: UUID(), name: "overlap", startAddress: 0x1004, endAddress: 0x1008, confidence: 1))
        }
        XCTAssertFalse(CrashReportWindowPresenter.navigate(0x1004, binary: b, in: store))
        store.snapshot.binaries[1] = BinaryImage(id: UUID(), name: "replacement", path: "/synthetic/b", kind: "executable", architecture: "arm64", slot: slot)
        XCTAssertFalse(CrashReportWindowPresenter.navigate(0x1004, binary: b, in: store))
    }

    func testNativeSourceSelectionUsesUTF16AndRejectsWrongImageOrAmbiguousLines() {
        let text = "😀 first();\nsecond();"
        func run(_ id: String, _ offset: Int, _ image: String = "image") -> NativeDecompilerDocumentTokenRun {
            .init(tokenID: id, scalarOffset: offset, scalarLength: 5, kind: .keyword,
                sourceRanges: [.init(imageID: image, startAddress: .init(0x1000), endAddressExclusive: .init(0x1004))], entityReferences: [])
        }
        let document = NativeDecompilerDocumentProjection(text: text, isComplete: true, isTruncated: false,
            mappingState: .verified, tokenRuns: [run("first", 2)])
        let selection = NativePseudocodeSourceLocation(imageID: "image", address: 0x1000)
        XCTAssertEqual(selection.textRange(in: document), NSRange(location: 3, length: 5))
        XCTAssertNil(NativePseudocodeSourceLocation(imageID: "other", address: 0x1000).textRange(in: document))
        let ambiguous = NativeDecompilerDocumentProjection(text: text, isComplete: true, isTruncated: false,
            mappingState: .verified, tokenRuns: [run("first", 2), run("second", 11)])
        XCTAssertNil(selection.textRange(in: ambiguous))
        let degraded = NativeDecompilerDocumentProjection(text: text, isComplete: true, isTruncated: false,
            mappingState: .degraded(.ambiguousRange), tokenRuns: document.tokenRuns)
        XCTAssertNil(selection.textRange(in: degraded))
    }
}

@MainActor
final class CrashReportLineAdmissionTests: XCTestCase {
    func testMacScopeLineSelectionRefusesSwitchAndConditionalAmbiguity() {
        let source = MacIRSourceSpan(address: 0x1000, byteText: "", mnemonic: "br", operands: "")
        let header = PseudocodeLine(lineNumber: 1, text: "switch (x0) {", source: source)
        let branch = PseudocodeLine(lineNumber: 2, text: "case 0:", source: source)
        XCTAssertNil(PseudocodeView.uniqueSourceLine(in: [header, branch], address: 0x1000))
        XCTAssertEqual(PseudocodeView.uniqueSourceLine(in: [header], address: 0x1000)?.id, 1)
        XCTAssertNil(PseudocodeView.uniqueSourceLine(in: [header], address: 0x1004))
        XCTAssertNil(PseudocodeView.uniqueSourceLine(in: [header], address: nil))
    }
}

@MainActor
final class CrashReportRegisterRenderingTests: XCTestCase {
    func testRenderCrashRegistersAndUUIDNavigation() throws {
        let uuid = "11111111-2222-3333-4444-555555555555"
        let report = CrashReport(processName: "Crash Import Example", exceptionSummary: "EXC_BAD_ACCESS · SIGSEGV",
            threads: [CrashReportThread(id: 0, name: "Main thread", triggered: true,
                frames: [CrashReportFrame(id: 0, imageIndex: 0, imageOffset: 0x104, reportedSymbol: nil)],
                registers: [CrashReportRegister(name: "x0", value: UInt64.max), CrashReportRegister(name: "pc", value: 0x102000104), CrashReportRegister(name: "sp", value: 0x16ff00000)], registerFlavor: "ARM_THREAD_STATE64")],
            images: [CrashReportImage(name: "Example", uuid: uuid, base: 0x102000000, size: 0x4000)])
        let context = CrashReportImageContext(uuid: uuid, preferredBase: 0x100000000,
            mappedRanges: [0x100000000..<0x100004000], symbols: [CrashReportSymbol(name: "readDocument", address: 0x100000100, endAddress: 0x100000180)])
        let theme = DSThemeStore(themes: DSBuiltInThemes.all, selectedID: DSBuiltInThemes.scope.id, persistsSelection: false)
        let rendered: Data? = DSThemeStore.withActiveStore(theme) {
            let content = CrashReportView(report: report, context: nil, imageName: nil, onNavigate: { _ in false },
                rendersOffscreen: true, imageContexts: [context], onNavigateImage: { _, _ in true })
                .lumenRendersOffscreen(true)
                .frame(width: 1040, height: 700)
                .environment(\.colorScheme, .dark)
                .environment(\.dsPalette, theme.resolvedPalette())
            let renderer = ImageRenderer(content: content)
            renderer.scale = 1
            guard let cg = renderer.cgImage else { return nil }
            return NSBitmapImageRep(cgImage: cg).representation(using: .png, properties: [:])
        }
        let png = try XCTUnwrap(rendered)
        let output = TestWorkRoot.scratchURL("crash-import-registers.png")
        try png.write(to: output)
        print("Crash register rendering: \(output.path)")
    }
}
