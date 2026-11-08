# Working with MacScope

These steps describe product entry points visible in the tracked app sources,
not a claim that every workflow has passed installed acceptance. A compatible
Apple-silicon Mac and a prepared, qualified build are prerequisites. See
[Capabilities](CAPABILITIES.md) for architecture restrictions and
[Development](DEVELOPMENT.md) for build policy.

## Inspect a binary

1. Choose **File → Open Binary…** for a Mach-O, ELF/PE, or compatible
   container, or **File → Open Workspace…** for a saved `.mscope` package.
   **Load Additional Binary…** brings another image into the workspace.
2. Choose **Disassembly**, **Pseudocode**, **Graph**, or **Hex** in the editor.
   Pseudocode is an ARM64 path; for unsupported inputs the UI should report
   an unavailable/degraded state instead of implying decompilation.
3. Open **Imports**, **Exports**, **Sections**, symbols/strings/XREFs, or
   **Signature & Dependencies**. Use **Navigate → Go to Address…** or
   **Find…** to explore within the active image.
4. Optionally **Read Debug Symbols File…** and **Import C Header…**.
   Imported debug/types data and inferred analysis remain distinguishable
   from bytes actually observed in the binary.
5. Use bookmarks, labels, annotations, and types; save the `.mscope` workspace
   when those edits must persist.

The [menu implementation](../MacScope/App/AppCommands.swift) and
[editor source](../MacScope/Features/Editor/EditorSurfaceView.swift) are the
best references when a label differs between builds.

## Open a crash report and navigate to its function

Choose **File → Open Crash Report…** (or open/drop an Apple `.ips` report).
The report is read-only and opens in a separate window with the crashed
thread, frame list, and captured registers. When a frame's build UUID and
address map unambiguously into a loaded image/function, MacScope can navigate
to that function and, where a unique source map exists, the corresponding
pseudocode text. Missing, duplicate, or mismatched identities cannot select
an arbitrary function. Reopen the report after loading the exact crashed
binary. See [Crash report to pseudocode](CrashReportImport.md).

## Request or export pseudocode

Select an ARM64 function, then use **Request Native Pseudocode**; the menu
also exposes retry, refresh, and cancellation. MacScope's startup policy
defaults the signed native decompiler on. Readiness and output validation are
separate: a request may fail or degrade. The MacIR alternative must be
attributed as fallback, not silently described as SLEIGH output.

For a retained artifact choose **Export Pseudocode…** or
**Export All Pseudocode…**. Other export commands include listing, graph
PDF, Objective-C header, Swift interface, C types, and BinExport2.
Check the scope of each export against the source image and currently
accepted analysis; exported text is not proof of source-level equivalence.

## Compare images and review AIRS evidence

Load two images, then choose **Compare Images…** to inspect function-version
candidate matches. Annotations transferred between versions must retain
their source and destination identities. **Import AIRS Handoff…** is exposed
when a focused binary is available; it imports bounded AIRS-derived evidence
for review. **Open AIRS Bound Review…** is a separate source-bound review and
navigation path. Neither command establishes live bidirectional synchronization
or automatically promotes an imported claim to verified analysis.

Source references:
[version-comparison UI](../MacScope/Features/VersionCompare/VersionCompareSheet.swift),
[AIRS importer](../MacScope/App/AIRSHandoffImport.swift).

## Inspect a local process

The debugger pane and related commands expose local ARM64 launch/attach,
run-to-cursor, logical breakpoints, watchpoints, frames, and runtime
observations. Choose a compatible target and inspect the app's identity and
permission diagnostics before attaching. Debugger addresses and process
observations must be correlated to the selected static image; do not assume
that a file offset or unslid address is a runtime PC.

Only processes on the **same Mac** are in scope, and macOS may refuse an
attach. Preserve detach-versus-terminate intent. There is no remote debugger
or x86 debugger in the supported product contract. See
[debugger implementation](../MacScope/Features/Debugger/DebuggerPanelView.swift).

## Execute a selected ARM64 function

The editor's **Run Function…** control calls the selected function in a
fresh owned process. It may execute the target's loader initializers and
constructors before the selected function. Confirm the signature and C
calling convention, review pointer/global arguments and time limits,
and use only targets you are authorized to **execute**, not merely read.
This is not passive binary inspection, nor an assurance of safe execution
of hostile code. See [Native Run Function safety](NATIVE-FUNCTION-EXECUTION.md).

## Export a captured-app Xcode skeleton

`export-project` is a captured-workspace **AppleScript** command, not a
normal MCP or legacy JSON-batch command. It writes an editable but
nonfunctional project with stubbed functions and selected resource
round-trip handling; do not describe it as full decompilation or a
working reconstructed app. See [Regeneration usage](REGENERATION-USAGE.md).

## Edit, assemble, or export a patched image

Hex/assembly controls support user-authored changes and patched-binary
exports. Verify offsets, image ownership, original bytes, architecture,
and target signing requirements. Never assume that patching preserves
signature validity, loadability, control flow, or memory protections.
Prefer working on a copy of a binary you own or are authorized to assess.

## Use the assistant or Reconstruction

The assistant is a local, evidence-grounded analysis surface with bounded
tools and app-owned authorization; it currently integrates **MTPLX**. A configured model name is not a ready model, and AI text
is not authority to read arbitrary local files, run shell commands, or
change a workspace. User-granted tool actions remain separate.

The Reconstruction destination supports corpus imports, job creation and
start/pause/resume/cancel actions, checkpointed state, and evidence review.
Those are workflow surfaces, not a guarantee that every generated program
passes semantic tests. Retain exact source and checkpoint identities.

## Automate locally

The app executable has two headless modes:

```zsh
/path/to/MacScope.app/Contents/MacOS/MacScope --run-script /path/to/script.json /path/to/binary
/path/to/MacScope.app/Contents/MacOS/MacScope --mcp /path/to/binary
```

The first runs a bounded JSON command batch. The second serves local
JSON-RPC over stdio for a selected binary **or an existing `.mscope` package**.
On a universal binary, an explicit `--slice <architecture>` chooses a
unique slice. `--journal <path>` attaches a replayable edit journal; the
ordered flag combinations are defined in the
[headless MCP guide](MCP-AND-VERIFICATION.md). The standard-library
[Python client](../MacScope/python/README.md) drives the basic
`--mcp <path>` launch, but not the optional journal/slice flags through its
`open()` signature.

Tool listing defaults to `core`, with an explicit `full` profile available
through `MACSCOPE_MCP_LIST_PROFILE`; the listing profile does not grant
additional authority. Headless edits are not automatically saved to a
`.mscope` document. Do not treat local automation as remote access or as
permission to execute analyzed input.

### Verify a headless annotation

For a source-backed name/comment edit, or a validated address type/function
signature, use the specialized `verified-commit` command only in a **journal-attached headless session**. Its success is a journal-line commit with
same-process live readback, **not** a fresh read of a saved workspace.
Preserve the returned `expectationOperation` and caller-chosen `operationId`.
An exact retry can be idempotent; a changed operation with the same ID is
refused. If a commit is indeterminate, restart with the same package and
journal and reconcile before another mutation.

`verified-checkpoint` is read-only and inspects the current store.
`verified-checkpoint-isolated` runs a separate read-only process against
a saved package in the supported headless path. Check publication and
checkpoint results separately. Both accept bounded inputs and may refuse.
The [MCP/verification guide](MCP-AND-VERIFICATION.md) describes these
contracts and their distinct evidence tiers.

## When a result is unavailable

Preserve the exact input, architecture/slice, image identity, source commit,
selected mode, worker diagnostics, and error/degraded status. Try a
focused reproduction. Lack of data, unavailable
runtime, or authorization denial is not a zero-length result or proof
that the analyzed program lacks the feature.
