import XCTest
@testable import MacScope

final class SwiftDemanglerDriverCoverageTests: XCTestCase {
    func testF1OracleRendering() {
        let name = "_$s7GhosttyAAO3AppC6action_6targetAESbSv_So08ghostty_D2_saSo0e1_C2_satFZ"
        let expected = "static Ghostty.Ghostty.App.action(_: Swift.UnsafeMutableRawPointer, target: __C.ghostty_target_s, action: __C.ghostty_action_s) -> Swift.Bool"
        XCTAssertEqual(SwiftDemangler.demangle(name), expected)
        XCTAssertEqual(Demangler.mangledToReadable(name), expected)
    }

    func testF2OracleRendering() {
        let name = "_$s7GhosttyAAO3AppC12reloadConfig7surface4softySv_SbtF"
        let expected = "Ghostty.Ghostty.App.reloadConfig(surface: Swift.UnsafeMutableRawPointer, soft: Swift.Bool) -> ()"
        XCTAssertEqual(SwiftDemangler.demangle(name), expected)
        XCTAssertEqual(Demangler.mangledToReadable(name), expected)
    }

    func testF3OracleRendering() {
        let name = "_$s7Ghostty11SecureInputC12removeScopedyySOF"
        let expected = "Ghostty.SecureInput.removeScoped(Swift.ObjectIdentifier) -> ()"
        XCTAssertEqual(SwiftDemangler.demangle(name), expected)
        XCTAssertEqual(Demangler.mangledToReadable(name), expected)
    }

    func testF4OracleRendering() {
        let name = "_$s10Foundation4DataV15_RepresentationO6append10contentsOfySW_tF"
        let expected = "Foundation.Data._Representation.append(contentsOf: Swift.UnsafeRawBufferPointer) -> ()"
        XCTAssertEqual(SwiftDemangler.demangle(name), expected)
        XCTAssertEqual(Demangler.mangledToReadable(name), expected)
    }

    func testF5OracleRendering() {
        let name = "_$s7GhosttyAAO11SurfaceViewC14setCursorShapeyySo28ghostty_action_mouse_shape_eaF"
        let expected = "Ghostty.Ghostty.SurfaceView.setCursorShape(__C.ghostty_action_mouse_shape_e) -> ()"
        XCTAssertEqual(SwiftDemangler.demangle(name), expected)
        XCTAssertEqual(Demangler.mangledToReadable(name), expected)
    }

    func testF6LabelReferenceUsesMainParser() {
        let name = "_$s7SwiftUI13AnyTransitionV5scaleAD6anchorAC12CoreGraphics7CGFloatV_AA9UnitPointVtFZ"
        let expected = "static SwiftUI.AnyTransition.scale(scale: CoreGraphics.CGFloat, anchor: SwiftUI.UnitPoint) -> SwiftUI.AnyTransition"
        let budget = SwiftDemangler.Budget()
        let result = SwiftDemangler.demangleWithFacts(name, budget: budget)
        XCTAssertEqual(result?.rendered, expected)
        XCTAssertEqual(budget.factsSource, "main")
        XCTAssertEqual(SwiftDemangler.demangle(name), expected)
    }

    func testF7GhosttySignatureFacts() {
        let result = SwiftDemangler.demangleWithFacts("_$s7GhosttyAAO3AppC6action_6targetAESbSv_So08ghostty_D2_saSo0e1_C2_satFZ")
        XCTAssertEqual(result?.rendered, "static Ghostty.Ghostty.App.action(_: Swift.UnsafeMutableRawPointer, target: __C.ghostty_target_s, action: __C.ghostty_action_s) -> Swift.Bool")
        XCTAssertEqual(result?.parameterTypes, ["Swift.UnsafeMutableRawPointer", "__C.ghostty_target_s", "__C.ghostty_action_s"])
        XCTAssertEqual(result?.resultType, "Swift.Bool")
        XCTAssertEqual(result?.facts?.hasNonScalarParameter, true)
        XCTAssertEqual(result?.facts?.hasNonScalarReturn, false)
    }

    func testF8BareStandardTypes() {
        XCTAssertEqual(SwiftDemangler.demangle("$sSv"), "Swift.UnsafeMutableRawPointer")
        XCTAssertEqual(SwiftDemangler.demangle("$sSW"), "Swift.UnsafeRawBufferPointer")
        XCTAssertEqual(SwiftDemangler.demangle("$sSO"), "Swift.ObjectIdentifier")
    }

    func testF9NestedAAAccessorCorrection() {
        // Pin incorrectly inserts .App into the property type before .Config.
        XCTAssertEqual(SwiftDemangler.demangle("_$s7GhosttyAAO3AppC6configAB6ConfigCvg"),
            "Ghostty.Ghostty.App.config.getter : Ghostty.Ghostty.Config")
    }

    func testAllSixteenNestedAACorrections() {
        let cases: [(String, String)] = [
            // GHC:11737
            ("_$s7GhosttyAAO3AppC6configAB6ConfigCvg", "Ghostty.Ghostty.App.config.getter : Ghostty.Ghostty.Config"),
            // GHC:9680
            ("_$s7GhosttyAAO11SurfaceViewC11searchStateAB09OSSurfaceC0C06SearchE0CSgvg", "Ghostty.Ghostty.SurfaceView.searchState.getter : Ghostty.Ghostty.OSSurfaceView.SearchState?"),
            // GHC:9682
            ("_$s7GhosttyAAO11SurfaceViewC11searchStateAB09OSSurfaceC0C06SearchE0CSgvs", "Ghostty.Ghostty.SurfaceView.searchState.setter : Ghostty.Ghostty.OSSurfaceView.SearchState?"),
            // GHC:9805
            ("_$s7GhosttyAAO11SurfaceViewC14progressReportAB6ActionV08ProgressE0VSgvg", "Ghostty.Ghostty.SurfaceView.progressReport.getter : Ghostty.Ghostty.Action.ProgressReport?"),
            // GHC:9806
            ("_$s7GhosttyAAO11SurfaceViewC14progressReportAB6ActionV08ProgressE0VSgvs", "Ghostty.Ghostty.SurfaceView.progressReport.setter : Ghostty.Ghostty.Action.ProgressReport?"),
            // GHC:9973
            ("_$s7GhosttyAAO11SurfaceViewC28pendingClipboardConfirmationAB0eF7RequestCSgvg", "Ghostty.Ghostty.SurfaceView.pendingClipboardConfirmation.getter : Ghostty.Ghostty.ClipboardConfirmationRequest?"),
            // GHC:10395
            ("_$s7GhosttyAAO13OSSurfaceViewC14progressReportAB6ActionV08ProgressE0VSgvg", "Ghostty.Ghostty.OSSurfaceView.progressReport.getter : Ghostty.Ghostty.Action.ProgressReport?"),
            // GHC:10399
            ("_$s7GhosttyAAO13OSSurfaceViewC14progressReportAB6ActionV08ProgressE0VSgvs", "Ghostty.Ghostty.OSSurfaceView.progressReport.setter : Ghostty.Ghostty.Action.ProgressReport?"),
            // GHC:10405
            ("_$s7GhosttyAAO13OSSurfaceViewC18childExitedMessageAB05ChildeF0VSgvg", "Ghostty.Ghostty.OSSurfaceView.childExitedMessage.getter : Ghostty.Ghostty.ChildExitedMessage?"),
            // GHC:10435
            ("_$s7GhosttyAAO13OSSurfaceViewC5errorAB5ErrorOSgvg", "Ghostty.Ghostty.OSSurfaceView.error.getter : Ghostty.Ghostty.Error?"),
            // GHC:12632
            ("_$s7GhosttyAAO6ConfigC13bellAudioPathAB0bE0VSgvg", "Ghostty.Ghostty.Config.bellAudioPath.getter : Ghostty.Ghostty.ConfigPath?"),
            // GHC:12656
            ("_$s7GhosttyAAO6ConfigC14macosIconFrameAB09MacOSIconE0Ovg", "Ghostty.Ghostty.Config.macosIconFrame.getter : Ghostty.Ghostty.MacOSIconFrame"),
            // GHC:12732
            ("_$s7GhosttyAAO6ConfigC17autoUpdateChannelAB04AutodE0Ovg", "Ghostty.Ghostty.Config.autoUpdateChannel.getter : Ghostty.Ghostty.AutoUpdateChannel"),
            // GHC:12775
            ("_$s7GhosttyAAO6ConfigC18macosWindowButtonsAB011MacOSWindowE0Ovg", "Ghostty.Ghostty.Config.macosWindowButtons.getter : Ghostty.Ghostty.MacOSWindowButtons"),
            // GHC:12819
            ("_$s7GhosttyAAO6ConfigC21commandPaletteEntriesSayAB7CommandVGvg", "Ghostty.Ghostty.Config.commandPaletteEntries.getter : [Ghostty.Ghostty.Command]"),
            // GHC:12835
            ("_$s7GhosttyAAO6ConfigC22macosTitlebarProxyIconAB013MacOSTitlebareF0Ovg", "Ghostty.Ghostty.Config.macosTitlebarProxyIcon.getter : Ghostty.Ghostty.MacOSTitlebarProxyIcon"),
        ]
        for (name, expected) in cases { XCTAssertEqual(SwiftDemangler.demangle(name), expected, name) }
    }

    func testC1TGProGetterUnchanged() {
        XCTAssertEqual(Demangler.mangledToReadable("_$s10Foundation10NSNotFoundSivg"),
            "Foundation.NSNotFound.getter : Swift.Int")
    }

    func testC2LiteralUnchanged() {
        // DT:1793
        XCTAssertEqual(Demangler.mangledToReadable("_$s10DataViewerAAC12setDirectory_12forSessionIdy10Foundation3URLV_AE4UUIDVtYaF"),
            "DataViewer.DataViewer.setDirectory(_: Foundation.URL, forSessionId: Foundation.UUID) async -> ()")
    }

    func testC3AccessorsUnchanged() {
        // DT:397
        XCTAssertEqual(Demangler.mangledToReadable("_$s10DataViewerAAC3url10Foundation3URLVvg"),
            "DataViewer.DataViewer.url.getter : Foundation.URL")
        // DT:399
        XCTAssertEqual(Demangler.mangledToReadable("_$s10DataViewerAAC7handlerAA7HandlerCvg"),
            "DataViewer.DataViewer.handler.getter : DataViewer.Handler")
    }

    func testC4StaticAccessorsUnchanged() {
        // DT:1514
        XCTAssertEqual(Demangler.mangledToReadable("_$s10DataViewerAAC5localABvgZ"),
            "static DataViewer.DataViewer.local.getter : DataViewer.DataViewer")
        // DT:1518
        XCTAssertEqual(Demangler.mangledToReadable("_$s10DataViewerAAC5localABvpZMV"),
            "property descriptor for static DataViewer.DataViewer.local : DataViewer.DataViewer")
        // DT:1522
        XCTAssertEqual(Demangler.mangledToReadable("_$s10DataViewerAAC5localABvgZTu"),
            "async function pointer to static DataViewer.DataViewer.local.getter : DataViewer.DataViewer")
    }

    func testC5SelfTypeUnchanged() {
        // DT:2039
        XCTAssertEqual(Demangler.mangledToReadable("$s12CoreGraphics7CGFloatV6isLess4thanSbAC_tF"),
            "CoreGraphics.CGFloat.isLess(than: CoreGraphics.CGFloat) -> Swift.Bool")
        // DT:2041
        XCTAssertEqual(Demangler.mangledToReadable("$s12CoreGraphics7CGFloatV8advanced2byA2C_tF"),
            "CoreGraphics.CGFloat.advanced(by: CoreGraphics.CGFloat) -> CoreGraphics.CGFloat")
        // DT:2043
        XCTAssertEqual(Demangler.mangledToReadable("$s4self3FooV2m1yyACF"),
            "self.Foo.m1(self.Foo) -> ()")
        // DT:2045
        XCTAssertEqual(Demangler.mangledToReadable("$s4self3FooV2m41p1qyAC_ACtF"),
            "self.Foo.m4(p: self.Foo, q: self.Foo) -> ()")
        // DT:2048
        XCTAssertEqual(Demangler.mangledToReadable("$s3cal5OuterV5InnerV2miyyAEF"),
            "cal.Outer.Inner.mi(cal.Outer.Inner) -> ()")
        // DT:2050
        XCTAssertEqual(Demangler.mangledToReadable("$s3cal5OuterV5InnerV2moyyACF"),
            "cal.Outer.Inner.mo(cal.Outer) -> ()")
        // DT:2052
        XCTAssertEqual(Demangler.mangledToReadable("$s3cal5OuterV5InnerV4both1i1oyAE_ACtF"),
            "cal.Outer.Inner.both(i: cal.Outer.Inner, o: cal.Outer) -> ()")
    }

    func testC6ObjCClosureUnchanged() {
        // DT:2170
        XCTAssertEqual(Demangler.mangledToReadable("_$s10ACPToolLib15URLSessionStoreC10addSession_2idySo12NSURLSessionC_SStFyyXEfU_TA"),
            "partial apply forwarder for closure #1 () -> () in ACPToolLib.URLSessionStore.addSession(_: __C.NSURLSession, id: Swift.String) -> ()")
    }

    func testC7RunLengthUnchanged() {
        // DT:1649
        XCTAssertEqual(Demangler.mangledToReadable("_$s10ACPToolLib10printError_9separator10terminatoryypd_S2StF"),
            "ACPToolLib.printError(_: Any..., separator: Swift.String, terminator: Swift.String) -> ()")
    }

    func testC8AAClosuresUnchanged() {
        // DT:1534
        XCTAssertEqual(Demangler.mangledToReadable("_$s10DataViewerAAC9localTask33_FC1F129190A6C68A1C5A1438BA3C6606LLScTyABs5Error_pGvpZfiAByYaKcfU_"),
            "closure #1 () async throws -> DataViewer.DataViewer in variable initialization expression of static DataViewer.DataViewer.(localTask in _FC1F129190A6C68A1C5A1438BA3C6606) : Swift.Task<DataViewer.DataViewer, Swift.Error>")
        // DT:1538
        XCTAssertEqual(Demangler.mangledToReadable("_$s10DataViewerAAC9localTask33_FC1F129190A6C68A1C5A1438BA3C6606LLScTyABs5Error_pGvpZfiAByYaKcfU_TA"),
            "partial apply forwarder for closure #1 () async throws -> DataViewer.DataViewer in variable initialization expression of static DataViewer.DataViewer.(localTask in _FC1F129190A6C68A1C5A1438BA3C6606) : Swift.Task<DataViewer.DataViewer, Swift.Error>")
        // DT:1542
        XCTAssertEqual(Demangler.mangledToReadable("_$s10DataViewerAAC9localTask33_FC1F129190A6C68A1C5A1438BA3C6606LLScTyABs5Error_pGvpZfiAByYaKcfU_TATQ0_"),
            "(1) await resume partial function for partial apply forwarder for closure #1 () async throws -> DataViewer.DataViewer in variable initialization expression of static DataViewer.DataViewer.(localTask in _FC1F129190A6C68A1C5A1438BA3C6606) : Swift.Task<DataViewer.DataViewer, Swift.Error>")
    }

    func testAdditionalAAControlsUnchanged() {
        // DT:753
        XCTAssertEqual(Demangler.mangledToReadable("_$s10DataViewerAAC12setDirectory_12forSessionIdy10Foundation3URLV_AE4UUIDVtYaFTu"),
            "async function pointer to DataViewer.DataViewer.setDirectory(_: Foundation.URL, forSessionId: Foundation.UUID) async -> ()")
        // DT:777
        XCTAssertEqual(Demangler.mangledToReadable("_$s10DataViewerAAC12setDirectory_12forSessionIdy10Foundation3URLV_AE4UUIDVtYaFTY0_"),
            "(1) suspend resume partial function for DataViewer.DataViewer.setDirectory(_: Foundation.URL, forSessionId: Foundation.UUID) async -> ()")
        // DT:1433
        XCTAssertEqual(Demangler.mangledToReadable("_$s10DataViewerAAC3url10Foundation3URLVvpMV"),
            "property descriptor for DataViewer.DataViewer.url : Foundation.URL")
        // DT:1437
        XCTAssertEqual(Demangler.mangledToReadable("_$s10DataViewerAAC7handlerAA7HandlerCvpWvd"),
            "direct field offset for DataViewer.DataViewer.handler : DataViewer.Handler")
        // DT:1530
        XCTAssertEqual(Demangler.mangledToReadable("_$s10DataViewerAAC9localTask33_FC1F129190A6C68A1C5A1438BA3C6606LLScTyABs5Error_pGvpZ"),
            "static DataViewer.DataViewer.(localTask in _FC1F129190A6C68A1C5A1438BA3C6606) : Swift.Task<DataViewer.DataViewer, Swift.Error>")
    }

    // Constructed witness; outside-oracle interpretation is NOT CONFIRMED.
    func testN1PrivateContextRemainsNil() {
        XCTAssertNil(SwiftDemangler.demangle("_$s7Ghostty3Foo33_863305F73E773BCB4AB49BECEAF65FAFLLC6action_6targetAESbSv_S2itF"))
    }

    // Constructed witness; outside-oracle interpretation is NOT CONFIRMED.
    func testN2PrivateFunctionRemainsNil() {
        XCTAssertNil(SwiftDemangler.demangle("_$s7GhosttyAAO3AppC6action33_863305F73E773BCB4AB49BECEAF65FAFLL_6targetAESbSv_S2itFZ"))
        XCTAssertNil(SwiftDemangler.demangle("_$s7GhosttyAAO3AppC6action33_863305F73E773BCB4AB49BECEAF65FAFLL6target6sourceAGSbSv_S2itFZ"))
    }

    // Constructed witness; outside-oracle interpretation is NOT CONFIRMED.
    func testN3LeadingIdentifiersRemainsNil() {
        XCTAssertNil(SwiftDemangler.demangle("$s3foo3bar1f6target6sourceACSbSv_S2itF"))
    }

    // Constructed witness; outside-oracle interpretation is NOT CONFIRMED.
    func testN4ConstrainedExtensionRemainsNil() {
        XCTAssertNil(SwiftDemangler.demangle("$s7Ghostty3FooVAAAA5ProtoRzrlE6action6target6sourceAFSbSv_S2itF"))
    }

    // Constructed witness; outside-oracle interpretation is NOT CONFIRMED.
    func testN5StandardInitialContextRemainsNil() {
        XCTAssertNil(SwiftDemangler.demangle("$sSa6action6target6sourceACSbSv_S2itF"))
    }

    func testPrivateFunctionsWithoutLabelReferences() {
        // GHC:11733
        XCTAssertEqual(SwiftDemangler.demangle("_$s7GhosttyAAO3AppC4redo33_863305F73E773BCB4AB49BECEAF65FAFLL_6targetSbSv_So08ghostty_J2_satFZTf4dnd_n"),
            "function signature specialization <Arg[0] = Dead, Arg[2] = Dead> of static Ghostty.Ghostty.App.(redo in _863305F73E773BCB4AB49BECEAF65FAF)(_: Swift.UnsafeMutableRawPointer, target: __C.ghostty_target_s) -> Swift.Bool")
        // GHC:11625
        XCTAssertEqual(SwiftDemangler.demangle("_$s7GhosttyAAO3AppC10gotoWindow33_863305F73E773BCB4AB49BECEAF65FAFLL_6target9directionSbSv_So08ghostty_K2_saSo0m8_action_C9_window_eatFZTf4ddnd_n"),
            "function signature specialization <Arg[0] = Dead, Arg[1] = Dead, Arg[3] = Dead> of static Ghostty.Ghostty.App.(gotoWindow in _863305F73E773BCB4AB49BECEAF65FAF)(_: Swift.UnsafeMutableRawPointer, target: __C.ghostty_target_s, direction: __C.ghostty_action_goto_window_e) -> Swift.Bool")
    }

    func testFiveAdditionalRealNames() {
        // GHC:1828
        XCTAssertEqual(SwiftDemangler.demangle("_$s7Ghostty11SecureInputC12removeScopedyySOFTq"),
            "method descriptor for Ghostty.SecureInput.removeScoped(Swift.ObjectIdentifier) -> ()")
        // GHC:1861
        XCTAssertEqual(SwiftDemangler.demangle("_$s7Ghostty11SecureInputC9setScoped_7focusedySO_SbtFTq"),
            "method descriptor for Ghostty.SecureInput.setScoped(_: Swift.ObjectIdentifier, focused: Swift.Bool) -> ()")
        // GHC:9810
        XCTAssertEqual(SwiftDemangler.demangle("_$s7GhosttyAAO11SurfaceViewC14setCursorShapeyySo28ghostty_action_mouse_shape_eaFTq"),
            "method descriptor for Ghostty.Ghostty.SurfaceView.setCursorShape(__C.ghostty_action_mouse_shape_e) -> ()")
        // GHC:10048
        XCTAssertEqual(SwiftDemangler.demangle("_$s7GhosttyAAO11SurfaceViewC7surfaceSvSgvg"),
            "Ghostty.Ghostty.SurfaceView.surface.getter : Swift.UnsafeMutableRawPointer?")
        // GHC:10367
        XCTAssertEqual(SwiftDemangler.demangle("_$s7GhosttyAAO13OSSurfaceViewC11surfaceSizeSo08ghostty_D7_size_saSgvg"),
            "Ghostty.Ghostty.OSSurfaceView.surfaceSize.getter : __C.ghostty_surface_size_s?")
    }
    // Constructed witness; oracle NOT CONFIRMED.
    // The unnarrowed AA offset loses private self type at index 4 and returns nil.
    func testN6AAPrivateLevelKeepsPinLayout() {
        let name = "_$s7GhosttyAAO3Foo33_863305F73E773BCB4AB49BECEAF65FAFLLC6actionyyAEF"
        let expected = "Ghostty.Ghostty.(Foo in _863305F73E773BCB4AB49BECEAF65FAF).action(Ghostty.Ghostty.(Foo in _863305F73E773BCB4AB49BECEAF65FAF)) -> ()"
        XCTAssertEqual(SwiftDemangler.demangle(name), expected)
        XCTAssertEqual(Demangler.mangledToReadable(name), expected)
    }
}
