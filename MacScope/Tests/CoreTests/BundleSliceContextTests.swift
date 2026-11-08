import Foundation
import XCTest
@testable import MacScope

@MainActor
final class BundleSliceContextTests: XCTestCase {
    private let arm: Int32 = 0x0100000c
    private let x86: Int32 = 0x01000007

    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("bundle-slices-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        addTeardownBlock { try? FileManager.default.removeItem(at: url) }
        return url
    }

    private func file(_ data: Data, name: String = "Fixture") throws -> URL {
        let url = try directory().appendingPathComponent(name)
        try data.write(to: url)
        return url
    }

    private func fact(_ kind: MachOSelectedSliceFact.ContainerKind = .universal, count: Int = 2,
                      index: Int = 1, cpu: Int32 = 0x0100000c, subtype: Int32 = 0) throws -> MachOSelectedSliceFact {
        try MachOSelectedSliceFact(containerKind: kind, sliceCount: count, selectedSliceIndex: index,
                                   cpuType: cpu, cpuSubtype: subtype)
    }

    private func store(_ snapshot: WorkspaceSnapshot) -> WorkspaceStore {
        WorkspaceStore(workspaceName: "bundle-context", snapshot: snapshot,
                       engine: AnalysisEngine(), autosaveScheduler: nil)
    }

    private func refusal(_ code: MCPRefusalCode, _ body: () throws -> ScriptValue,
                         file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            guard case ScriptingError.structuredRefusal(let value) = error else {
                return XCTFail("expected structured refusal, got \(error)", file: file, line: line)
            }
            XCTAssertEqual(value.code, code, file: file, line: line)
            XCTAssertFalse(value.retryable, file: file, line: line)
        }
    }

    private func bundle() throws -> (executable: URL, plist: URL, types: ScriptValue) {
        let root = try directory().appendingPathComponent("Fixture.app")
        let macOS = root.appendingPathComponent("Contents/MacOS")
        try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)
        let executable = macOS.appendingPathComponent("FixtureExecutable")
        try MachOFixture.makeExecutableWithLinkedLibraryMetadata().bytes.write(to: executable)
        let types: [[String: Any]] = [
            ["CFBundleTypeName": "Text", "CFBundleTypeRole": "Editor", "LSItemContentTypes": ["public.text"]],
            ["CFBundleTypeName": "Rich", "CFBundleTypeRole": "Viewer", "LSItemContentTypes": ["public.rtf"],
             "fixtureBoolean": true, "fixtureInteger": 7, "fixtureFraction": 1.5],
        ]
        let plist = root.appendingPathComponent("Contents/Info.plist")
        try PropertyListSerialization.data(fromPropertyList: ["CFBundleExecutable": "FixtureExecutable",
            "CFBundleIdentifier": "com.example.fixture", "CFBundleDocumentTypes": types,
            "CFBundleName": "Fixture", "CFBundleShortVersionString": "1.2", "CFBundleVersion": "3",
            "CFBundlePackageType": "APPL", "LSMinimumSystemVersion": "13.0"], format: .xml, options: 0).write(to: plist)
        let expected: ScriptValue = .array([
            .object(["CFBundleTypeName": .string("Text"), "CFBundleTypeRole": .string("Editor"),
                     "LSItemContentTypes": .array([.string("public.text")])]),
            .object(["CFBundleTypeName": .string("Rich"), "CFBundleTypeRole": .string("Viewer"),
                     "LSItemContentTypes": .array([.string("public.rtf")]), "fixtureBoolean": .bool(true),
                     "fixtureInteger": .int(7), "fixtureFraction": .double(1.5)]),
        ])
        return (executable, plist, expected)
    }

    func testF1DualSlicesAndProvenance() throws {
        let fixture = MachOFixture.makeUniversalDualExecutable()
        let url = try file(fixture.bytes)
        let loaded = try MCPLauncher.makeStore(binaryURL: url)
        let reply = try WorkspaceScriptingAPI(store: loaded).execute("slices")
        let rows = try XCTUnwrap(reply["slices"]?.arrayValue)
        XCTAssertEqual(rows.count, 2)
        XCTAssertEqual(rows.map { $0["architecture"] }, [.string("x86_64"), .string("arm64")])
        XCTAssertEqual(rows.map { $0["index"] }, [.int(0), .int(1)])
        XCTAssertEqual(rows.map { $0["cpuType"] }, [.int(Int64(x86)), .int(Int64(arm))])
        XCTAssertEqual(rows.map { $0["cpuSubtype"] }, [.int(3), .int(0)])
        XCTAssertEqual(rows.map { $0["selected"] }, [.bool(false), .bool(true)])
        XCTAssertEqual(rows.filter { $0["selected"] == .bool(true) }.count, 1)
        XCTAssertEqual(rows[0]["offset"], .hex(0x30))
        XCTAssertEqual(rows[1]["offset"], .hex(UInt64(fixture.arm64SliceOffset)))
        XCTAssertEqual(rows[1]["size"], .hex(UInt64(fixture.arm64SliceSize)))
        XCTAssertEqual(rows[1]["alignment"], .int(4))
        XCTAssertEqual(reply["containerKind"], .string("universal"))
        XCTAssertEqual(reply["sliceCount"], .int(2))
        XCTAssertEqual(reply["selectedSliceIndex"], .int(1))
        XCTAssertEqual(reply["imageSlot"], .int(0))
        XCTAssertEqual(reply["imageOwner"], loaded.snapshot.binaries.first.map { .string($0.id.uuidString) })
        XCTAssertEqual(reply["path"], .string(url.path))
    }

    func testF2SubtypeNamesAndSignedRawValues() throws {
        let data = MachOFixture.makeFatContainer([
            (arm, 0x80000002, MachOFixture.makeExecutable(cpuSubtype: 2).bytes),
            (arm, 0x8000000c, MachOFixture.makeExecutable(cpuSubtype: 12).bytes),
        ])
        let value = try WorkspaceScriptingAPI.sliceListing(data: data,
            fact: fact(index: 0, subtype: Int32(bitPattern: 0x80000002)))
        let rows = try XCTUnwrap(value["slices"]?.arrayValue)
        XCTAssertEqual(rows.map { $0["architecture"] }, [.string("arm64e"), .string("arm64e.x1")])
        XCTAssertEqual(rows.map { $0["cpuSubtype"] }, [.int(-2147483646), .int(-2147483636)])
        XCTAssertEqual(rows.map { $0["selected"] }, [.bool(true), .bool(false)])
    }

    func testF3ThinUnknownMalformedAndChangedContainers() throws {
        let thin = MachOFixture.makeExecutable(cpuSubtype: 2).bytes
        let thinFact = try fact(.thin, count: 1, index: 0, subtype: 2)
        let reply = try WorkspaceScriptingAPI.sliceListing(data: thin, fact: thinFact)
        XCTAssertEqual(reply["containerKind"], .string("thin"))
        XCTAssertEqual(reply["sliceCount"], .int(1))
        XCTAssertEqual(reply["selectedSliceIndex"], .int(0))
        XCTAssertEqual(reply["slices"], .array([.object(["index": .int(0), "architecture": .string("arm64e"),
            "cpuType": .int(Int64(arm)), "cpuSubtype": .int(2), "offset": .hex(0),
            "size": .hex(UInt64(thin.count)), "alignment": .null, "selected": .bool(true)])]))
        let unknown = try WorkspaceScriptingAPI.sliceListing(data: thin, fact: nil)
        XCTAssertEqual(unknown["containerKind"], .null)
        XCTAssertEqual(unknown["slices"], .array([]))
        XCTAssertEqual(unknown["reason"], .string("the image is not a Mach-O file or has no slice record"))
        let dual = MachOFixture.makeUniversalDualExecutable().bytes
        let noFact = try WorkspaceScriptingAPI.sliceListing(data: dual, fact: nil)
        XCTAssertEqual(noFact["selectedSliceIndex"], .null)
        XCTAssertEqual(noFact["slices"]?.arrayValue?.map { $0["selected"] }, [.bool(false), .bool(false)])
        for wrong in [try fact(cpu: x86), try fact(count: 3), try fact(count: 3, index: 2), thinFact] {
            refusal(.preconditionFailed) { try WorkspaceScriptingAPI.sliceListing(data: dual, fact: wrong) }
        }
        refusal(.preconditionFailed) { try WorkspaceScriptingAPI.sliceListing(data: thin, fact: fact()) }
        let duplicate = MachOFixture.makeFatContainer([(arm, 0, thin), (arm, 0, thin)])
        refusal(.malformedInput) { try WorkspaceScriptingAPI.sliceListing(data: duplicate, fact: nil) }
    }

    func testF4BundleDiscoveryAndCompleteDocumentTypes() throws {
        let fixture = try bundle()
        let loaded = try MCPLauncher.makeStore(binaryURL: fixture.executable)
        let reply = try WorkspaceScriptingAPI(store: loaded).execute("bundle-info")
        XCTAssertEqual(reply["bundle"]?["bundleIdentifier"], .string("com.example.fixture"))
        XCTAssertEqual(reply["bundle"]?["executable"], .string("FixtureExecutable"))
        XCTAssertEqual(reply["bundle"]?["documentTypes"], fixture.types)
        XCTAssertEqual(reply["bundle"]?["documentTypeCount"], .int(2))
        XCTAssertEqual(reply["bundle"]?["minimumSystemVersion"], .string("13.0"))
        XCTAssertEqual(reply["bundle"]?["shortVersion"], .string("1.2"))
        XCTAssertEqual(reply["bundle"]?["infoPlistPath"], .string(fixture.plist.path))
        let helper = fixture.executable.deletingLastPathComponent().appendingPathComponent("Helper")
        try MachOFixture.makeExecutable().bytes.write(to: helper)
        let bare = try file(MachOFixture.makeExecutable().bytes)
        for url in [bare, helper] {
            let value = try WorkspaceScriptingAPI(store: MCPLauncher.makeStore(binaryURL: url)).execute("bundle-info")
            XCTAssertEqual(value["bundle"], .null)
            XCTAssertEqual(value["bundleReason"], .string("the image is not inside an app bundle"))
            XCTAssertNotNil(value["uuid"])
        }
    }

    func testF5BoundedReaderAndBundleFailureReasons() throws {
        let oversized = try file(Data(repeating: 0x20, count: 4_194_305), name: "Info.plist")
        XCTAssertThrowsError(try WorkspaceScriptingAPI.boundedPlist(at: oversized)) { error in
            XCTAssertEqual(error.localizedDescription, "Info.plist exceeds 4194304 bytes")
        }
        let notDictionary = try file(PropertyListSerialization.data(fromPropertyList: ["item"], format: .xml, options: 0))
        XCTAssertThrowsError(try WorkspaceScriptingAPI.boundedPlist(at: notDictionary)) { error in
            XCTAssertEqual(error.localizedDescription, "Info.plist is not a dictionary")
        }
        let fixture = try bundle()
        var snapshot = try MCPLauncher.makeStore(binaryURL: fixture.executable).snapshot
        snapshot.binaries[0].kind = "app bundle"
        snapshot.binaries[0].path = fixture.executable.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().path
        snapshot.binaries[0].resolvedExecutablePath = fixture.executable.path
        for (data, reason) in [(Data(repeating: 0x20, count: 4_194_305), "Info.plist exceeds 4194304 bytes"),
                              (try Data(contentsOf: notDictionary), "Info.plist is not a dictionary")] {
            try data.write(to: fixture.plist)
            let reply = try WorkspaceScriptingAPI.bundleInfo(.object([:]), snapshot: snapshot)
            XCTAssertEqual(reply["bundle"], .null)
            XCTAssertEqual(reply["bundleReason"], .string(reason))
        }
        // This targets the bundle metadata reader.
        XCTAssertThrowsError(try WorkspaceScriptingAPI.boundedPlist(at: directory()))
    }

    func testResolverF7BundleInfoFailureContracts() throws {
        let fixture = try bundle()
        var snapshot = try MCPLauncher.makeStore(binaryURL: fixture.executable).snapshot
        let app = fixture.executable.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let flat = app.appendingPathComponent("Info.plist")
        try Data(repeating: 0x20, count: 4_194_305).write(to: flat)

        snapshot.binaries[0].kind = "app bundle"
        snapshot.binaries[0].path = app.path
        snapshot.binaries[0].resolvedExecutablePath = nil
        refusal(.preconditionFailed) { try WorkspaceScriptingAPI.bundleInfo(.object([:]), snapshot: snapshot) }

        snapshot.binaries[0].kind = "executable"
        snapshot.binaries[0].path = fixture.executable.path
        let ancestorFailure = try WorkspaceScriptingAPI.bundleInfo(.object([:]), snapshot: snapshot)
        XCTAssertEqual(ancestorFailure["bundle"], .null)
        XCTAssertEqual(ancestorFailure["bundleReason"], .string("the image is not inside an app bundle"))

        snapshot.binaries[0].kind = "app bundle"
        snapshot.binaries[0].path = app.path
        snapshot.binaries[0].resolvedExecutablePath = fixture.executable.path
        let readerFailure = try WorkspaceScriptingAPI.bundleInfo(.object([:]), snapshot: snapshot)
        XCTAssertEqual(readerFailure["bundle"], .null)
        XCTAssertEqual(readerFailure["bundleReason"], .string("Info.plist exceeds 4194304 bytes"))
    }

    func testF6LoadMetadataSigningAndReloadDisclosure() throws {
        let fixture = try bundle()
        var snapshot = try MCPLauncher.makeStore(binaryURL: fixture.executable).snapshot
        let metadata = try XCTUnwrap(snapshot.machOMetadata)
        let initial = try WorkspaceScriptingAPI.bundleInfo(.object([:]), snapshot: snapshot)
        XCTAssertFalse(metadata.dependentDylibs.isEmpty)
        XCTAssertEqual(initial["linkedDylibs"], .array(metadata.dependentDylibs.map {
            .object(["path": .string($0.path), "kind": .string($0.kind), "currentVersion": .string($0.currentVersion),
                     "compatibilityVersion": .string($0.compatibilityVersion), "ordinal": .int(Int64($0.ordinal))])
        }))
        snapshot.machOMetadata?.codeSignature = .init(teamIdentifier: "TEAM", identifier: "fixture.id", hashTypeName: "SHA-256",
            codeSignatureFlags: 0x10000, entitlementsFormat: "XML", entitlementsXML: "SECRET-XML",
            entitlementsDER: true, entitlementsKeyCount: 1, entitlementsKeys: ["SECRET-KEY"], entitlementsParsed: true)
        let signed = try WorkspaceScriptingAPI.bundleInfo(.object([:]), snapshot: snapshot)
        XCTAssertEqual(signed["signing"]?["flags"], .string("0x10000"))
        XCTAssertEqual(signed["signing"]?["present"], .bool(true))
        XCTAssertEqual(signed["signing"]?["identifier"], .string("fixture.id"))
        XCTAssertEqual(signed["signing"]?["teamIdentifier"], .string("TEAM"))
        XCTAssertEqual(signed["signing"]?["hashType"], .string("SHA-256"))
        let text = String(decoding: try signed.jsonData(), as: UTF8.self)
        XCTAssertFalse(text.lowercased().contains("entitlement")) // This fixture is thin.
        XCTAssertFalse(text.contains("SECRET"))
        snapshot.machOMetadata = nil
        let reloaded = try WorkspaceScriptingAPI.bundleInfo(.object([:]), snapshot: snapshot)
        XCTAssertEqual(reloaded["linkedDylibs"], .null)
        XCTAssertEqual(reloaded["signing"], .null)
        XCTAssertEqual(reloaded["metadataReason"], .string("load metadata is derived at analysis and is not kept in a reloaded workspace; re-analyse to see dylibs and signing"))
    }

    func testF7LaunchFormsDoNotStealExistingModes() {
        for arguments in [["app", "--mcp", "/tmp/binary", "--slice", "x86_64"],
                          ["app", "--mcp=/tmp/binary", "--slice=x86_64"]] {
            XCTAssertEqual(MCPLauncher.requestedSliceLaunch(from: arguments)?.architecture, "x86_64")
            XCTAssertEqual(MCPLauncher.requestedSliceLaunch(from: arguments)?.binary.path,
                           MCPLauncher.canonicalURL(forPath: "/tmp/binary")?.path)
            XCTAssertNil(MCPLauncher.requestedBinary(from: arguments))
            XCTAssertNil(MCPLauncher.requestedJournalLaunch(from: arguments))
        }
        for arguments in [["app"], ["app", "--mcp", "/tmp/binary"], ["app", "--mcp=/tmp/binary"],
            ["app", "--mcp", "/tmp/binary", "--journal", "/tmp/journal"],
            ["app", "--mcp=/tmp/binary", "--journal=/tmp/journal"],
            ["app", "--mcp=/tmp/binary", "--slice="], ["app", "--mcp=/tmp/binary", "--slice=arm\0"],
            ["app", "--slice", "arm64", "--mcp", "/tmp/binary"],
            ["app", "--mcp", "/tmp/binary", "--slice", "arm64", "extra"],
            ["app", "--run-script", "--mcp=/tmp/binary", "/tmp/script"]] {
            XCTAssertNil(MCPLauncher.requestedSliceLaunch(from: arguments), "\(arguments)")
        }
    }

    func testF8ExplicitIndexAndExactNameRefusals() throws {
        let bytes = MachOFixture.makeUniversalDualExecutable().bytes
        let url = try file(bytes)
        let provider = SliceRecordingProvider()
        let bound = try MCPLauncher.makeBoundStore(binaryURL: url, engine: provider, sliceArchitecture: "x86_64")
        XCTAssertEqual(provider.requests, [0])
        XCTAssertEqual(bound.store.snapshot.binaries.first?.machOSelectedSliceFact?.selectedSliceIndex, 0)
        let api = WorkspaceScriptingAPI(store: bound.store)
        XCTAssertEqual(try api.execute("info")["slice"]?["architecture"], .string("x86_64"))
        let listing = try api.execute("slices")
        XCTAssertEqual(listing["selectedSliceIndex"], .int(0))
        XCTAssertEqual(listing["slices"]?.arrayValue?.first?["cpuSubtype"], .int(3))
        let x86Row = try XCTUnwrap(listing["slices"]?.arrayValue?.first { $0["architecture"] == .string("x86_64") })
        XCTAssertEqual(listing["selectedSliceIndex"], x86Row["index"])
        XCTAssertEqual(x86Row["selected"], .bool(true))
        XCTAssertEqual(listing["slices"]?.arrayValue?.filter { $0["selected"] == .bool(true) }.count, 1)
        let table = try MachOParser().strictUniversalSlices(in: bytes)
        XCTAssertThrowsError(try MCPLauncher.sliceIndex(forArchitecture: "ppc", in: table)) { error in
            guard case MCPLauncherError.unknownSliceArchitecture(let requested, let available) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(requested, "ppc"); XCTAssertEqual(available, ["x86_64", "arm64"])
        }
        let ambiguous = [0, 1].map { MachOUniversalSlice(index: $0, cpuType: arm,
            cpuSubtype: Int32($0), offset: 0, size: 0, alignment: 0) }
        XCTAssertThrowsError(try MCPLauncher.sliceIndex(forArchitecture: "arm64", in: ambiguous)) { error in
            guard case MCPLauncherError.ambiguousSliceArchitecture(let requested, let indices) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(requested, "arm64"); XCTAssertEqual(indices, [0, 1])
        }
        XCTAssertThrowsError(try MCPLauncher.sliceIndex(forArchitecture: "arm64", in: nil)) { error in
            guard case MCPLauncherError.sliceRequiresUniversal(let requested) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(requested, "arm64")
        }
    }

    func testF9RejectsLyingSelection() throws {
        let url = try file(MachOFixture.makeUniversalDualExecutable().bytes)
        XCTAssertThrowsError(try MCPLauncher.makeBoundStore(binaryURL: url,
            engine: SliceRecordingProvider(lie: true), sliceArchitecture: "x86_64")) { error in
            guard case MCPLauncherError.sliceSelectionMismatch = error else { return XCTFail("\(error)") }
        }
    }

    private func response(_ server: MCPServer, method: String, params: ScriptValue = .object([:]),
                          asynchronous: Bool) async throws -> ScriptValue {
        let request = try ScriptValue.object(["jsonrpc": .string("2.0"), "id": .int(1),
            "method": .string(method), "params": params]).jsonData()
        let data: Data?
        if asynchronous { data = await server.handleMessageAsync(request) }
        else { data = server.handleMessage(request) }
        return try ScriptValue.decode(try XCTUnwrap(data))
    }

    func testF10InfoRoutesCatalogsAndAttachedExclusion() async throws {
        let url = try file(MachOFixture.makeExecutable().bytes)
        var snapshot = try MCPLauncher.makeStore(binaryURL: url).snapshot
        let oldArchitecture = snapshot.binaries[0].architecture
        snapshot.binaries[0].machOSelectedSliceFact = try fact(subtype: Int32(bitPattern: 0x80000002))
        let loaded = store(snapshot)
        let api = WorkspaceScriptingAPI(store: loaded)
        let inline = try api.execute("info")
        let asynchronous = try await api.executeAsync("info")
        let executor = MCPAttachExecutor(store: loaded, api: { WorkspaceScriptingAPI(store: $0) })
        executor.setConsent(.allowed)
        let attached = try await executor.execute("info", .object([:]))
        XCTAssertEqual(inline, asynchronous)
        XCTAssertEqual(inline, attached)
        XCTAssertEqual(inline["architecture"], .string(oldArchitecture))
        XCTAssertEqual(inline["slice"], .object(["containerKind": .string("universal"), "index": .int(1),
            "count": .int(2), "architecture": .string("arm64e"), "cpuType": .int(Int64(arm)),
            "cpuSubtype": .int(-2147483646)]))
        let server = MCPServer(api: api)
        let attachedServer = MCPServer(api: api, configuration: .attached, allowedCommands: MCPAttachExecutor.attachCommands)
        for isAsync in [false, true] {
            let catalog = try await response(server, method: "tools/list", asynchronous: isAsync)
            let attachedCatalog = try await response(attachedServer, method: "tools/list", asynchronous: isAsync)
            for name in ["bundle-info", "slices"] {
                let tool = try XCTUnwrap(catalog["result"]?["tools"]?.arrayValue?.first { $0["name"] == .string(name) })
                guard case .object(let properties) = try XCTUnwrap(tool["inputSchema"]?["properties"]) else {
                    return XCTFail("missing schema")
                }
                XCTAssertEqual(Set(properties.keys), ["image"])
                XCTAssertFalse(attachedCatalog["result"]?["tools"]?.arrayValue?.contains { $0["name"] == .string(name) } ?? true)
            }
            let infoReply = try await response(server, method: "tools/call",
                params: .object(["name": .string("info"), "arguments": .object([:])]), asynchronous: isAsync)
            let infoText = try XCTUnwrap(infoReply["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
            XCTAssertEqual(try ScriptValue.decode(Data(infoText.utf8)), inline)
        }
        for name in ["bundle-info", "slices"] {
            do { _ = try await executor.execute(name, .object([:])); XCTFail("attached admitted \(name)") }
            catch { XCTAssertEqual(error as? MCPAttachExecutor.Failure, .unavailableWhenAttached) }
        }
    }

    func testF11BackgroundSelectionAndStartupFailure() async throws {
        let url = try file(MachOFixture.makeUniversalDualExecutable().bytes)
        let provider = SliceRecordingProvider()
        let bound = try await MCPLauncher.makeBoundStoreInBackground(binaryURL: url, engine: provider,
            status: MCPStartupStatus(), onLaunchState: { _ in }, sliceArchitecture: "x86_64")
        XCTAssertEqual(provider.requests, [0])
        XCTAssertEqual(bound.store.snapshot.binaries.first?.machOSelectedSliceFact?.selectedSliceIndex, 0)
        let failed = MCPLauncher.startHeadlessSession(binaryURL: url, engine: provider,
            log: { _ in }, onLaunchState: { _ in }, sliceArchitecture: "ppc")
        await failed.analysis.value
        XCTAssertEqual(failed.gate.exitStatus, 1)
        XCTAssertEqual(provider.requests, [0], "unknown architecture must fail before analyze")
        let reply = try await response(failed.server, method: "tools/call",
            params: .object(["name": .string("info"), "arguments": .object([:])]), asynchronous: true)
        XCTAssertTrue(String(decoding: try reply.jsonData(), as: UTF8.self).contains("No slice named"))
    }

    func testF12RunScriptAdmissionAndImageSchemaValidation() async throws {
        let url = try file(MachOFixture.makeUniversalDualExecutable().bytes)
        let loaded = try MCPLauncher.makeStore(binaryURL: url)
        let api = WorkspaceScriptingAPI(store: loaded)
        let server = MCPServer(api: api)
        for name in ["bundle-info", "slices"] {
            let script = ScriptValue.array([.object(["command": .string(name), "arguments": .object([:])])])
            XCTAssertEqual(try HeadlessAutomationAuthority.scriptSteps(from: script).count, 1)
            XCTAssertNoThrow(try HeadlessAutomationAuthority.validate(command: name, arguments: .object([:])))
            let inline = try api.execute(name)
            let asyncValue = try await api.executeAsync(name)
            XCTAssertEqual(inline, asyncValue)
            for asynchronous in [false, true] {
                let result = try await response(server, method: "tools/call",
                    params: .object(["name": .string(name), "arguments": .object([:])]), asynchronous: asynchronous)
                XCTAssertEqual(result["result"]?["isError"], .bool(false))
                let text = try XCTUnwrap(result["result"]?["content"]?.arrayValue?.first?["text"]?.stringValue)
                XCTAssertEqual(try ScriptValue.decode(Data(text.utf8)), inline)
                let bad = try await response(server, method: "tools/call", params: .object([
                    "name": .string(name), "arguments": .object(["image": .bool(true)])]), asynchronous: asynchronous)
                assertMCPToolArgumentError(bad, field: "image", code: "malformedInput")
            }
        }
    }

    func testF13MissingFileAndNoImageAreTyped() throws {
        let url = try file(MachOFixture.makeExecutable().bytes)
        var snapshot = try MCPLauncher.makeStore(binaryURL: url).snapshot
        try FileManager.default.removeItem(at: url)
        refusal(.preconditionFailed) { try WorkspaceScriptingAPI.imageSlices(.object([:]), snapshot: snapshot) }
        snapshot.binaries = []
        refusal(.unknownSubject) { try WorkspaceScriptingAPI.imageSlices(.object([:]), snapshot: snapshot) }
        refusal(.unknownSubject) { try WorkspaceScriptingAPI.bundleInfo(.object([:]), snapshot: snapshot) }
        XCTAssertEqual(WorkspaceScriptingAPI.selectedSliceValue(nil), .null)
    }

    func testF14SiblingSelectionUsesItsFileAndMetadata() throws {
        let primaryURL = try file(MachOFixture.makeUniversalDualExecutable().bytes)
        let siblingFixture = try bundle()
        var snapshot = try MCPLauncher.makeStore(binaryURL: primaryURL).snapshot
        let other = try MCPLauncher.makeStore(binaryURL: siblingFixture.executable).snapshot
        var image = try XCTUnwrap(other.binaries.first)
        image.slot = ImageSlot(rawValue: 1)
        snapshot.binaries.append(image)
        snapshot.analysisBySlot[image.slot] = other.analysis(in: other.primarySlot)
        let api = WorkspaceScriptingAPI(store: store(snapshot))
        for selector in [ScriptValue.int(1), .string(image.id.uuidString)] {
            let arguments = ScriptValue.object(["image": selector])
            let slices = try api.execute("slices", arguments: arguments)
            XCTAssertEqual(slices["containerKind"], .string("thin"))
            XCTAssertEqual(slices["imageSlot"], .int(1))
            XCTAssertEqual(slices["imageOwner"], .string(image.id.uuidString))
            XCTAssertEqual(slices["path"], .string(siblingFixture.executable.path))
            let context = try api.execute("bundle-info", arguments: arguments)
            XCTAssertEqual(context["bundle"]?["documentTypes"], siblingFixture.types)
            XCTAssertEqual(context["imageOwner"], .string(image.id.uuidString))
            XCTAssertEqual(context["linkedDylibs"]?.arrayValue?.count, other.machOMetadata?.dependentDylibs.count)
        }
        XCTAssertEqual(try api.execute("bundle-info")["bundle"], .null)
    }

    func testF15FactCountTypeAndMissingFactAreRejectedAtLaunch() throws {
        let url = try file(MachOFixture.makeUniversalDualExecutable().bytes)
        let wrong: [MachOSelectedSliceFact?] = [nil,
            try fact(count: 3, index: 0, cpu: x86), try fact(index: 0, cpu: arm),
            try fact(.thin, count: 1, index: 0, cpu: x86)]
        for value in wrong {
            let provider = SliceRecordingProvider(replaceFact: true, forcedFact: value)
            XCTAssertThrowsError(try MCPLauncher.makeBoundStore(binaryURL: url, engine: provider,
                                                               sliceArchitecture: "x86_64")) { error in
                guard case MCPLauncherError.sliceSelectionMismatch = error else { return XCTFail("\(error)") }
            }
        }
        let provider = SliceRecordingProvider(replaceFact: true, forcedFact: try fact(index: 0, cpu: x86, subtype: 8))
        let bound = try MCPLauncher.makeBoundStore(binaryURL: url, engine: provider, sliceArchitecture: "x86_64")
        XCTAssertEqual(bound.store.snapshot.binaries.first?.machOSelectedSliceFact?.cpuSubtype, 8,
                       "header subtype is deliberately not compared with fat subtype 3")
    }

    func testF16FlatPlistPrecedenceAndUnsupportedPlistValues() throws {
        let fixture = try bundle()
        var snapshot = try MCPLauncher.makeStore(binaryURL: fixture.executable).snapshot
        let root = fixture.plist.deletingLastPathComponent().deletingLastPathComponent()
        snapshot.binaries[0].kind = "app bundle"
        snapshot.binaries[0].path = root.path
        snapshot.binaries[0].resolvedExecutablePath = fixture.executable.path
        let flat = root.appendingPathComponent("Info.plist")
        let bytes = try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": "flat.id",
            "CFBundleDocumentTypes": [["opaque": Data([1, 2]), "date": Date(timeIntervalSince1970: 0), "flag": true]]],
            format: .binary, options: 0)
        try bytes.write(to: flat)
        XCTAssertNoThrow(try WorkspaceScriptingAPI.boundedPlist(at: flat, maximum: bytes.count))
        XCTAssertThrowsError(try WorkspaceScriptingAPI.boundedPlist(at: flat, maximum: bytes.count - 1))
        let reply = try WorkspaceScriptingAPI.bundleInfo(.object([:]), snapshot: snapshot)
        XCTAssertEqual(reply["bundle"]?["bundleIdentifier"], .string("flat.id"))
        XCTAssertEqual(reply["bundle"]?["infoPlistPath"], .string(flat.path))
        XCTAssertEqual(reply["bundle"]?["documentTypes"], .array([.object(["opaque": .null, "date": .null, "flag": .bool(true)])]))
        XCTAssertEqual(reply["bundle"]?["documentTypeCount"], .int(1))
        XCTAssertEqual(reply["uuid"], snapshot.binaries[0].metadata.uuid.map(ScriptValue.string) ?? .null)
        XCTAssertEqual(reply["platform"], snapshot.binaries[0].metadata.platformName.map(ScriptValue.string) ?? .null)
        XCTAssertEqual(reply["minimumOSVersion"], snapshot.binaries[0].metadata.minimumOSVersion.map(ScriptValue.string) ?? .null)
        XCTAssertEqual(reply["sdkVersion"], snapshot.binaries[0].metadata.sdkVersion.map(ScriptValue.string) ?? .null)
        XCTAssertEqual(reply["buildTools"], .array(snapshot.binaries[0].metadata.buildTools.map(ScriptValue.string)))
    }

    func testC1DefaultLaunchStillPassesNilAndOldFormsParse() throws {
        let url = try file(MachOFixture.makeUniversalDualExecutable().bytes)
        let provider = SliceRecordingProvider()
        _ = try MCPLauncher.makeBoundStore(binaryURL: url, engine: provider)
        XCTAssertEqual(provider.requests.count, 1)
        XCTAssertNil(provider.requests[0])
        XCTAssertNotNil(MCPLauncher.requestedBinary(from: ["app", "--mcp", url.path]))
        XCTAssertNotNil(MCPLauncher.requestedBinary(from: ["app", "--mcp=\(url.path)"]))
        XCTAssertNotNil(MCPLauncher.requestedJournalLaunch(from: ["app", "--mcp", url.path, "--journal", "/tmp/journal"]))
    }

    // Item 1244 controls are authored only. NOT RUN; real-app assertion values are NOT CONFIRMED.
    func testF17LiveBundleDisclosureDoesNotChangeExistingBundleKeys() throws {
        let fixture = try bundle()
        let snapshot = try MCPLauncher.makeStore(binaryURL: fixture.executable).snapshot
        let initial = try WorkspaceScriptingAPI.bundleInfo(.object([:]), snapshot: snapshot)
        // makeStore resolves executable symlinks before bundle discovery walks its ancestors.
        let canonicalExecutable = try XCTUnwrap(MCPLauncher.canonicalURL(forPath: fixture.executable.path))
        let canonicalBundle = canonicalExecutable.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let expectedBundle: ScriptValue = .object([
            "path": .string(canonicalBundle.path),
            "infoPlistPath": .string(canonicalBundle.appendingPathComponent("Contents/Info.plist").path), "bundleIdentifier": .string("com.example.fixture"),
            "executable": .string("FixtureExecutable"), "name": .string("Fixture"),
            "shortVersion": .string("1.2"), "version": .string("3"), "packageType": .string("APPL"),
            "minimumSystemVersion": .string("13.0"), "documentTypes": fixture.types, "documentTypeCount": .int(2),
        ])
        XCTAssertEqual(initial["bundle"], expectedBundle)
        XCTAssertEqual(initial["bundleSource"], .string("live Info.plist read at call time; not tied to the analysed snapshot"))
        var plist = try WorkspaceScriptingAPI.boundedPlist(at: fixture.plist)
        plist["CFBundleIdentifier"] = "live.changed"
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: fixture.plist)
        let changed = try WorkspaceScriptingAPI.bundleInfo(.object([:]), snapshot: snapshot)
        XCTAssertEqual(changed["bundle"]?["bundleIdentifier"], .string("live.changed"))
        XCTAssertEqual(changed["bundleSource"], initial["bundleSource"])
        for key in ["uuid", "platform", "minimumOSVersion", "sdkVersion", "buildTools", "linkedDylibs", "signing", "imageSlot", "imageOwner"] {
            XCTAssertEqual(changed[key], initial[key], key)
        }
        let bare = try MCPLauncher.makeStore(binaryURL: file(MachOFixture.makeExecutable().bytes)).snapshot
        let absent = try WorkspaceScriptingAPI.bundleInfo(.object([:]), snapshot: bare)
        XCTAssertEqual(absent["bundle"], .null)
        XCTAssertNil(absent["bundleSource"], "no successful plist read is claimed for a missing bundle")
    }

    func testF18ThinHeaderOwnMagicCPUAndRawSubtypeConsistency() throws {
        // These prefixes exercise the listing consistency check, not parser admission of 32-bit/big-endian files.
        func prefix(magic: [UInt8], cpu: Int32, subtype: Int32, littleEndian: Bool) -> Data {
            var bytes = Data(magic)
            for value in [UInt32(bitPattern: cpu), UInt32(bitPattern: subtype)] {
                let shifts = littleEndian ? [0, 8, 16, 24] : [24, 16, 8, 0]
                bytes.append(contentsOf: shifts.map { UInt8(truncatingIfNeeded: value >> $0) })
            }
            return bytes
        }
        let rawSubtype = Int32(bitPattern: 0x80000002)
        let thinFact = try fact(.thin, count: 1, index: 0, subtype: rawSubtype)
        for (magic, littleEndian) in [([UInt8(0xce), 0xfa, 0xed, 0xfe], true),
            ([0xcf, 0xfa, 0xed, 0xfe], true), ([0xfe, 0xed, 0xfa, 0xce], false),
            ([0xfe, 0xed, 0xfa, 0xcf], false)] {
            let bytes = prefix(magic: magic, cpu: arm, subtype: rawSubtype, littleEndian: littleEndian)
            let reply = try WorkspaceScriptingAPI.sliceListing(data: bytes, fact: thinFact)
            XCTAssertEqual(reply["slices"]?.arrayValue?.first?["cpuSubtype"], .int(-2147483646))
            XCTAssertEqual(reply["slices"]?.arrayValue?.first?["architecture"], .string("arm64e"))
            for changed in [prefix(magic: magic, cpu: x86, subtype: rawSubtype, littleEndian: littleEndian),
                prefix(magic: magic, cpu: arm, subtype: 2, littleEndian: littleEndian),
                Data(bytes.prefix(11)), Data(repeating: 0, count: 12)] {
                XCTAssertThrowsError(try WorkspaceScriptingAPI.sliceListing(data: changed, fact: thinFact)) { error in
                    guard case ScriptingError.structuredRefusal(let value) = error else { return XCTFail("\(error)") }
                    XCTAssertEqual(value.code, .preconditionFailed)
                    XCTAssertEqual(value.detail, "the file changed since analysis: the fat table no longer matches the analysed slice")
                    XCTAssertFalse(value.retryable)
                }
            }
        }
        let original = MachOFixture.makeExecutable(cpuSubtype: 2).bytes
        let url = try file(original)
        let loaded = try MCPLauncher.makeStore(binaryURL: url)
        try MachOFixture.makeExecutable(cpuType: x86, cpuSubtype: 2).bytes.write(to: url)
        refusal(.preconditionFailed) { try WorkspaceScriptingAPI(store: loaded).execute("slices") }
    }

    func testF19ThinSliceLaunchRefusesBeforeAnalysis() throws {
        let url = try file(MachOFixture.makeExecutable().bytes)
        let provider = SliceRecordingProvider()
        XCTAssertThrowsError(try MCPLauncher.makeBoundStore(binaryURL: url, engine: provider, sliceArchitecture: "arm64")) { error in
            guard case MCPLauncherError.sliceRequiresUniversal(let requested) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(requested, "arm64")
            XCTAssertEqual(error.localizedDescription, "--slice arm64 needs a universal (fat) binary; this file is thin.")
        }
        XCTAssertTrue(provider.requests.isEmpty)
    }

    func testF20CombinedSliceJournalFormsAreExactAndDisjoint() throws {
        for arguments in [["app", "--mcp", "/tmp/binary", "--slice", "x86_64", "--journal", "/tmp/journal"],
                          ["app", "--mcp=/tmp/binary", "--slice=x86_64", "--journal=/tmp/journal"]] {
            let request = try XCTUnwrap(MCPLauncher.requestedSliceJournalLaunch(from: arguments))
            XCTAssertEqual(request.binary, MCPLauncher.canonicalURL(forPath: "/tmp/binary"))
            XCTAssertEqual(request.architecture, "x86_64")
            XCTAssertEqual(request.journal, MCPLauncher.canonicalURL(forPath: "/tmp/journal"))
            XCTAssertNil(MCPLauncher.requestedBinary(from: arguments))
            XCTAssertNil(MCPLauncher.requestedJournalLaunch(from: arguments))
            XCTAssertNil(MCPLauncher.requestedSliceLaunch(from: arguments))
        }
        for arguments in [["app"], ["app", "--mcp", "/tmp/binary"],
            ["app", "--mcp", "/tmp/binary", "--slice", "arm64"],
            ["app", "--mcp=/tmp/binary", "--journal=/tmp/journal"],
            ["app", "--mcp", "/tmp/binary", "--journal", "/tmp/journal", "--slice", "arm64"],
            ["app", "--mcp=/tmp/binary", "--journal=/tmp/journal", "--slice=arm64"],
            ["app", "--mcp", "/tmp/binary", "--slice", "arm64", "--journal=/tmp/journal"],
            ["app", "--mcp=/tmp/binary", "--slice", "arm64", "--journal", "/tmp/journal"],
            ["app", "--mcp=/tmp/binary", "--slice=", "--journal=/tmp/journal"],
            ["app", "--mcp=/tmp/binary", "--slice=arm64\0", "--journal=/tmp/journal"],
            ["app", "--mcp=", "--slice=arm64", "--journal=/tmp/journal"],
            ["app", "--mcp=/tmp/binary", "--slice=arm64", "--journal="],
            ["app", "--mcp=/tmp/binary\0", "--slice=arm64", "--journal=/tmp/journal"],
            ["app", "--mcp=/tmp/binary", "--slice=arm64", "--journal=/tmp/journal\0"],
            ["app", "--mcp=/tmp/binary", "--slice=arm64", "--journal=/tmp/journal", "extra"],
            ["app", "--run-script", "--mcp=/tmp/binary", "--slice=arm64", "--journal=/tmp/journal"]] {
            XCTAssertNil(MCPLauncher.requestedSliceJournalLaunch(from: arguments), "\(arguments)")
        }
    }

    func testF23ExistingSliceAndSigningShapesRemainByteIdentical() throws {
        let fixture = MachOFixture.makeUniversalDualExecutable()
        let universal = try WorkspaceScriptingAPI.sliceListing(data: fixture.bytes, fact: fact())
        let expectedUniversal: ScriptValue = .object(["containerKind": .string("universal"), "sliceCount": .int(2),
            "selectedSliceIndex": .int(1), "slices": .array([
                .object(["index": .int(0), "architecture": .string("x86_64"), "cpuType": .int(Int64(x86)),
                    "cpuSubtype": .int(3), "offset": .hex(0x30), "size": .hex(UInt64(MachOFixture.makeExecutable(cpuType: x86).bytes.count)),
                    "alignment": .int(4), "selected": .bool(false)]),
                .object(["index": .int(1), "architecture": .string("arm64"), "cpuType": .int(Int64(arm)),
                    "cpuSubtype": .int(0), "offset": .hex(UInt64(fixture.arm64SliceOffset)), "size": .hex(UInt64(fixture.arm64SliceSize)),
                    "alignment": .int(4), "selected": .bool(true)]),
            ])])
        XCTAssertEqual(try universal.jsonData(), try expectedUniversal.jsonData())
        let thin = MachOFixture.makeExecutable(cpuSubtype: 2).bytes
        let thinReply = try WorkspaceScriptingAPI.sliceListing(data: thin, fact: fact(.thin, count: 1, index: 0, subtype: 2))
        let expectedThin: ScriptValue = .object(["containerKind": .string("thin"), "sliceCount": .int(1), "selectedSliceIndex": .int(0),
            "slices": .array([.object(["index": .int(0), "architecture": .string("arm64e"), "cpuType": .int(Int64(arm)),
                "cpuSubtype": .int(2), "offset": .hex(0), "size": .hex(UInt64(thin.count)), "alignment": .null, "selected": .bool(true)])])])
        XCTAssertEqual(try thinReply.jsonData(), try expectedThin.jsonData())
        let app = try bundle()
        var snapshot = try MCPLauncher.makeStore(binaryURL: app.executable).snapshot
        snapshot.machOMetadata?.codeSignature = .init(teamIdentifier: "TEAM", identifier: "fixture.id", hashTypeName: "SHA-256",
            codeSignatureFlags: 0x10000, entitlementsFormat: "XML", entitlementsXML: "SECRET-XML",
            entitlementsDER: true, entitlementsKeyCount: 1, entitlementsKeys: ["SECRET-KEY"], entitlementsParsed: true)
        let reply = try WorkspaceScriptingAPI.bundleInfo(.object([:]), snapshot: snapshot)
        let presentation = MachOSignatureCoveragePresentation(imageName: snapshot.binaries[0].name,
            architecture: snapshot.binaries[0].architecture, selectedSliceIndex: snapshot.binaries[0].selectedSliceIndex,
            hasOtherContainerBytes: nil, hasCodeSignature: true, machOSelectedSliceFact: snapshot.binaries[0].machOSelectedSliceFact)
        let expectedSigning: ScriptValue = .object(["present": .bool(true), "identifier": .string("fixture.id"),
            "teamIdentifier": .string("TEAM"), "hashType": .string("SHA-256"), "flags": .string("0x10000"),
            "source": .string(presentation.source), "coverage": .string(presentation.coverage), "signature": .string(presentation.signature)])
        XCTAssertEqual(try reply["signing"]?.jsonData(), try expectedSigning.jsonData())
        XCTAssertEqual(reply["linkedDylibs"], .array(try XCTUnwrap(snapshot.machOMetadata).dependentDylibs.map {
            .object(["path": .string($0.path), "kind": .string($0.kind), "currentVersion": .string($0.currentVersion),
                "compatibilityVersion": .string($0.compatibilityVersion), "ordinal": .int(Int64($0.ordinal))])
        }))
    }
}

private final class SliceRecordingProvider: AnalysisProviding, @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [Int?] = []
    private let lie: Bool
    private let replaceFact: Bool
    private let forcedFact: MachOSelectedSliceFact?
    init(lie: Bool = false, replaceFact: Bool = false, forcedFact: MachOSelectedSliceFact? = nil) {
        self.lie = lie; self.replaceFact = replaceFact; self.forcedFact = forcedFact
    }
    var requests: [Int?] { lock.lock(); defer { lock.unlock() }; return recorded }
    func analyze(url: URL, requestedSliceIndex: Int?, overrides: [UInt64: AddressOverride],
                 cancellation: AnalysisCancellationToken) throws -> WorkspaceSnapshot {
        lock.lock(); recorded.append(requestedSliceIndex); lock.unlock()
        var snapshot = try AnalysisEngine().analyze(url: url, requestedSliceIndex: lie ? 1 : requestedSliceIndex,
                                                    overrides: overrides, cancellation: cancellation)
        if replaceFact { snapshot.binaries[0].machOSelectedSliceFact = forcedFact }
        return snapshot
    }
    func openBinary(url: URL, requestedSliceIndex: Int?, overrides: [UInt64: AddressOverride],
                    cancellation: AnalysisCancellationToken) async throws -> WorkspaceSnapshot {
        try analyze(url: url, requestedSliceIndex: requestedSliceIndex, overrides: overrides, cancellation: cancellation)
    }
}
