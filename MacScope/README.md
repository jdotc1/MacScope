# MacScope application source

The [repository README](../README.md) introduces the product. This directory
contains the SwiftUI/AppKit application, its app-owned model and workspace
state, native service targets, analysis engines, fixtures, and a generated
Xcode project definition.

MacScope is a locally built Apple-silicon application.
The development contract is **macOS 27.0+**, **Xcode 27** (not a particular
beta/RC/build number), Swift 6 language mode, and certificate-backed
Apple Development signing for the ordinary app and embedded workers.
Signed and notarized builds are published on the repository's Releases page.
See [Development](../docs/DEVELOPMENT.md).

## Where behavior lives

| Directory | Responsibility |
| --- | --- |
| [`App/`](App) | Startup, commands, window/document routing, headless JSON/MCP entry points, crash-report import, AIRS handoff/bound review, runtime service composition. |
| [`Features/`](Features) | Native editors, browsers, inspector, debugger, metadata, comparisons, reconstruction, REA, assistant, shell, settings, and workspace UI. |
| [`Models/`](Models) | Image/analysis identity, presentation and wire models, reconstruction and debugger contracts. |
| [`Stores/`](Stores) | Workspace commands, persistence, annotations, source/revision identity, debugger and reconstruction state. |
| [`Services/`](Services) | Parsers, disassembly, decompilation, symbols, DWARF, Swift/ObjC metadata, type/ABI models, import/export, version matching, native function execution, component evidence, Verified Analysis, and regeneration/resource round trips. |
| [`AnalysisWorkerService/`](AnalysisWorkerService) | Isolated analysis/loading and bounded external engine use. |
| [`NativeDecompilerXPCService/`](NativeDecompilerXPCService) | Native SLEIGH worker; source/build resources stay behind the service boundary. |
| [`AIAgentWorkerService/`](AIAgentWorkerService) | Local inference worker, without app state ownership or independent command authorization. |
| [`ShellBrokerService/`](ShellBrokerService) | Process/PTY broker, terminal capture, and source-execution boundaries. |
| [`Plugins/`](Plugins) and [`PluginSDK/`](PluginSDK) | Plugin manifest and trust/worker boundaries. |
| [`Tests/`](Tests) | CoreTests, Phase2Tests, installed UI-test sources, fixtures and named historical oracle results. |
| [`python/`](python) | Pure-Python MCP client and tests; [usage](python/README.md). |
| [`project.yml`](project.yml) | Declarative XcodeGen source, target membership, deployment and build settings. |

[AppCommands.swift](App/AppCommands.swift) is the clearest inventory of
currently wired UI/menu entry points: loading, navigation, editors,
native pseudocode, crash-report import, comparisons, AIRS handoff/bound
review, reconstruction actions, local debugger, patch/assembly operations,
and exports. The editor also
contains a bounded **Run Function** control; the captured-app
`export-project` route is a separate AppleScript-only scripting bridge. Source presence
does not imply every action is enabled for every target.

## Default decompiler and selected backend scope

The native signed SLEIGH XPC path is the default ARM64 pseudocode engine;
MacIR remains a distinct fallback/analysis implementation. Results carry
typed status and image context. The configured runtime policy is read
once at process startup; see the
[root README](../README.md#native-pseudocode-policy).

The loader supports ARM64 and x86_64 static analysis, but native
x86_64 pseudocode remains staged/disabled, and x86 debugging is out of
scope. Local LLDB launch and attach are ARM64/macOS only and subject
to platform authorization; remote debugging is excluded.
The binding [capability contract](PARITY_CONTRACT.md) owns exclusions.

The [MCP launcher](App/MCPLauncher.swift) can select a binary or an
existing `.mscope` workspace, with explicit universal-slice and journal
forms. Tool advertisement defaults to a smaller `core` catalog, and
Verified Analysis headless commands retain separate journal/live/saved
checkpoint semantics. See [MCP and verification](../docs/MCP-AND-VERIFICATION.md).
The [ComponentEvidence](Services/ComponentEvidence) AR1–AR3 code
tracks component inventory, signature facts, and security-delta analysis;
this is **not** evidence that a combined security-delta UI is enabled.
The framed analysis reply wire v5 path is default-off, and the Objective-C
marked-ivar-symbol planner remains disabled.

Local AI uses MTPLX under the app's authorization boundary.
A stored endpoint/model preference alone is not runtime readiness.

## Building and evidence

From the repository root:

```zsh
./Scripts/bootstrap.sh
./Scripts/dev_loop.sh --build-only
./Scripts/dev_loop.sh CoreTests/SomeSuite/someCase
```

The first two commands prepare/generate and build for development.
The optional third is a focused **iteration** selector, not
source-qualified or installed acceptance. Use
[the development guide](../docs/DEVELOPMENT.md) for exact
qualification, signed installation, and optional unsigned Debug
procedures. This repo's ordinary build uses verified offline
dependency inputs and external work roots.

The project uses explicit target/source membership. Analysis-layer
sources shared with the app must remain in the appropriate analysis
library; debugger-engine, AI protocol, and decompiler service
memberships have independent authority. Do not link native SLEIGH
implementation objects into the app target merely to make a feature
reachable. Regenerate `MacScope/MacScope.xcodeproj` from `project.yml`
rather than editing or committing it.

Source files and fixtures indicate implementation/test coverage,
not a current pass count, signing approval, or installed product.
See the [dated source-status snapshot](../docs/STATUS.md).

## Further reading

- [Capabilities and limitations](../docs/CAPABILITIES.md)
- [User workflows](../docs/WORKFLOWS.md)
- [Headless MCP and verified annotations](../docs/MCP-AND-VERIFICATION.md)
- [Crash report to pseudocode](../docs/CrashReportImport.md)
- [Native function execution safety](../docs/NATIVE-FUNCTION-EXECUTION.md)
- [Captured-app project export](../docs/REGENERATION-USAGE.md)
- [Development and qualification](../docs/DEVELOPMENT.md)
- [All tracked documentation](../docs/README.md)
- [Canonical nomenclature](../docs/brand/Nomenclature.md)

Historical contracts/designs and past test reports remain evidence
for their own recorded versions.
