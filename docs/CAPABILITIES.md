# MacScope capabilities and limits

**Evidence boundary:** This guide inventories **tracked source and reachable
entry points**, not a native build, signed runtime test, installed acceptance,
or full feature parity with another analysis product. The
[source-status snapshot](STATUS.md) records the reviewed commit, source
observations, and outstanding evidence gaps.

## Reading the matrix

- **Product surface** means an app menu, editor, panel, or headless entry point
  is wired in the tracked source. A command may be disabled when no compatible
  binary, process, service, or workspace evidence is available.
- **Backend in source** means implementation is tracked; it does not certify
  fidelity for every architecture, binary, or compiler case.
- **Qualified** requires the product's explicit native and installed evidence.
  This documentation review did not run those gates.

## Formats and architectures

| Input or architecture | Documented scope | Boundary |
| --- | --- | --- |
| Mach-O, universal/fat, apps, frameworks, dylibs, XPC services | Primary loading and static inspection; multiple images per workspace | Per-slice and address-domain identity must remain explicit. |
| dyld shared-cache images | Static image/metadata inspection, extraction-related paths | Full cross-subcache depth and symbolication are not universally guaranteed. |
| ELF, PE, COFF | Cross-format loading and static inspection | PE/Windows code is not a Windows debugging or decompilation target. COFF has a user-invoked reanalysis operation. |
| ARM64 / arm64e | Disassembly, static analysis, ARM64 pseudocode, local macOS LLDB debugging | Native engine and OS authorization must be available; PAC and newer ABI cases require evidence-specific interpretation. |
| x86_64 | Loading, disassembly, static analysis, and an assembler path | Production x86_64 decompilation is not enabled; an experimental native profile is staged but disabled. No x86 debugger. |
| AArch32/Thumb, i386, PowerPC, Hexagon | Explicitly excluded from supported disassembly/analysis | Do not list these as current implementation gaps or claim they work. |

The [capability contract](../MacScope/PARITY_CONTRACT.md) controls the formal
inclusions and exclusions. The loader and parser implementations live under
[`Services/Loader`](../MacScope/Services/Loader) and
[`ParserEngines`](../MacScope/ParserEngines).

## Workspace and investigation surfaces

| Capability | Source-backed product entry | Important limit |
| --- | --- | --- |
| Coordinated code views | Disassembly, Pseudocode, Graph, and Hex modes in [`EditorSurfaceView`](../MacScope/Features/Editor/EditorSurfaceView.swift) | View availability depends on the loaded image and analysis state. |
| Crash reports | **File → Open Crash Report…** and [`CrashReportView`](../MacScope/Features/CrashReports/CrashReportView.swift) read Apple `.ips` reports, correlate frames by build UUID and navigate into matched pseudocode | Reports remain read-only and session-local; incomplete, ambiguous, or stale image evidence cannot authorize navigation. See [the crash guide](CrashReportImport.md). |
| Navigation | Sections, imports, exports, strings, symbols, XREFs, navigation history, find, go-to-address, and quick-open commands in [`AppCommands`](../MacScope/App/AppCommands.swift) | Image-qualified addresses must not be mixed with runtime addresses. |
| Objective-C/Swift metadata | [Objective-C parsers](../MacScope/Services/ObjectiveC), [Swift metadata recovery](../MacScope/Services/SwiftMetadata), demangling, signatures, Swift-interface and Objective-C-header export | Partial or malformed metadata can yield explicit unresolved results. Recovered declarations are not original source. |
| Types and debug symbols | dSYM/DWARF import, type browser/editor, C-header import/export, function signatures | Imported facts and inferred types have distinct provenance. |
| Native ARM64 pseudocode | Signed native SLEIGH worker, request/retry/refresh/cancel commands, typed status and a disclosed [MacIR fallback](../MacScope/Services/Decompiler/MacIR.swift) | Default-on policy is subject to worker readiness, validation, cancellation, and degraded states; not full semantic equivalence. |
| Byte/instruction editing | Hex byte patches, assembler sheets, and patched-binary export | A patched output is not automatically safe, runnable, validly signed, or equivalent to the original. |
| Local debugger | LLDB launch/attach controls, thread/stack inspection, logical breakpoints, watchpoints, run-to-cursor, and session identity | ARM64 on the same Mac only; SIP, entitlements, code signing, user scope, and target policy may deny an operation. |
| Run Function (native execution) | [Run Function sheet](../MacScope/Features/Editor/RunFunctionSheet.swift) calls a selected ARM64 function in a fresh, owned process using a [dedicated runner](../MacScope/Services/NativeExecution) | Executes real code (including initializers). Requires confirmed C ABI/signature, admitted input, helper and cleanup; not a malware sandbox or general runtime-equivalence proof. See [safety guide](NATIVE-FUNCTION-EXECUTION.md). |
| Comparison and evidence | Compare loaded images, match functions, transfer candidate annotations, import AIRS handoffs, and open **AIRS Bound Review…** | Candidate matches and imported claims require image/revision identity and review; navigation does not certify the imported claim's semantics. |
| Security-oriented inspection | Code-signature/entitlement comparison, load-path risk, attack-surface triage, unwind audit, parser cross-checks | Findings indicate static evidence or discrepancies, not exploitation, compromise, or guaranteed vulnerability. |
| Reconstruction | [Reconstruction dashboard](../MacScope/Features/Reconstruction/ReconstructionDashboardView.swift), corpus import, job lifecycle, checkpoints and evidence projections | State and authority are gated. Reconstruction source output is a proposal until accepted and verified. |
| REA and AppKit semantics | REA workbench and retained evidence, NIB/ObjC semantic fusion implementation | Availability is subject to admitted resources and qualified paths; selective integration is not blanket REA compatibility. |
| Local assistant | [Assistant UI](../MacScope/Features/Assistant), separate AI worker and app-owned authorization | MTPLX local inference only under current policy. Model output is not source evidence or execution permission. |
| Terminal and shell | Broker-isolated shell/PTY surfaces with reviewed Ghostty integration | User-authorized process execution is a distinct trust boundary; neither analysis input nor a model response automatically confers shell authority. |
| Automation | `--run-script` JSON runner, `--mcp` for a binary or saved workspace, universal-slice selection, explicit edit journal, and [Python client](../MacScope/python/README.md) | The command allowlist, source identity, transport bounds, and write authorization remain separate. The Python `open()` helper has no slice/journal option. See [MCP guide](MCP-AND-VERIFICATION.md). |
| Verified annotation and checkpoint | [Verified Analysis services](../MacScope/Services/VerifiedAnalysis) and headless `verified-commit`, `verified-checkpoint`, `verified-checkpoint-isolated` tools | `verified-commit` needs a headless journal owner and is not available to bound document sessions; its same-process readback and journal durability are not a saved-package checkpoint. Evidence links can be synthetic placeholders. |
| Export | Listing, single/all pseudocode, graph PDF, Objective-C/Swift/C headers, BinExport2 menu path | An exposed export command is not evidence of format-wide compatibility or behavioral acceptance. |
| Captured-app project regeneration | AppleScript `export-project` through [RegenerationExport](../MacScope/Services/RegenerationExport) emits an editable Xcode project skeleton with nonfunctional function stubs and selected resource round trips | Not original source recovery, an executable behavioral clone, or generic MCP/`--run-script` access. See [usage](REGENERATION-USAGE.md). |
| Workspace persistence | `.mscope` packages, multi-image context, saved labels/comments/bookmarks/types and reconstruction evidence | Reopen, migration, and recovery claims require their own tests and package identities. |

Most app entry points above are visible in
[`AppCommands.swift`](../MacScope/App/AppCommands.swift),
[`WorkspaceRootView.swift`](../MacScope/Features/Workspace/WorkspaceRootView.swift),
and [`SidebarView.swift`](../MacScope/Features/Sidebar/SidebarView.swift).
The tracked source also contains isolated
[analysis](../MacScope/AnalysisWorkerService),
[native decompiler](../MacScope/NativeDecompilerXPCService),
[AI-agent](../MacScope/AIAgentWorkerService), and
[shell broker](../MacScope/ShellBrokerService) service targets.

## Staged engineering capabilities, not current product promises

The [ComponentEvidence](../MacScope/Services/ComponentEvidence) source now
contains component inventory and exact code-signature observations (AR1/AR2),
plus component security-delta values, rules, analysis, and paging (AR3).
This audit did **not** establish a user-facing command for the combined
security-delta result or its signed/installed acceptance. It belongs in the
**implemented-source** column, not a product demonstration.

The source also includes a **default-off** framed analysis-reply wire v5
experiment, a **disabled** Objective-C ivar marked-symbol planner, and
launch-gated native decompiler phase counters/diagnostic export. Neither
test/source presence nor a merged PR enables these globally. See
[evidence status](STATUS.md) for how to read these claims.

## Known boundaries and deliberately deferred areas

- Production decompilation and debugging are ARM64-focused. The
  x86_64 native profile is staged, not
  enabled production pseudocode.
- Debugging a process on another Mac, Windows debugging, and Windows
  decompilation are excluded.
- The MTPLX endpoint and selected model must be observed ready; a saved
  preference or a model name is not a readiness test.
- Plugins and outside helpers have their own code-signature/authorization
  controls. Native parser output, model text, imported AIRS data, and
  reconstruction hypotheses do not overwrite app-owned workspace truth.
- Auto-update is not provided. Signed and notarized builds are published on the
  repository's Releases page.
- No complete cross-tool feature parity, universal compiler reconstruction,
  full decompiler semantic equivalence, or current installed acceptance is
  inferred from source presence.

For practical steps, use [Workflows](WORKFLOWS.md); for the difference between
local iteration and qualification, use [Development](DEVELOPMENT.md).
