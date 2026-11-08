# Headless MCP, workspace sessions, and verified annotations

MacScope exposes a **local, app-owned** Model Context Protocol (MCP / JSON-RPC over stdio) interface. It is a separate process mode of the built macOS application, not a network server and not independent permission for a model or a binary to run commands. This guide describes **source-observed contracts** at [the reviewed revision](STATUS.md); native or installed acceptance is separate.

## Launch a session

Run the already-built, locally authorized executable (the paths below are placeholders):

~~~zsh
/path/to/MacScope.app/Contents/MacOS/MacScope --mcp /path/to/binary
/path/to/MacScope.app/Contents/MacOS/MacScope --mcp /path/to/workspace.mscope
/path/to/MacScope.app/Contents/MacOS/MacScope --mcp /path/to/universal-binary --slice arm64
/path/to/MacScope.app/Contents/MacOS/MacScope --mcp /path/to/workspace.mscope --journal /path/to/edits.journal
~~~

The parser also supports explicit `--mcp=…` / `--slice=…` / `--journal=…` forms and a combined `--mcp <binary> --slice <architecture> --journal <path>` form. **The option order is fixed**, and `--slice` applies only to a universal binary, not a saved workspace. An unknown, ambiguous, or mismatched requested architecture is refused. A `.mscope` argument must be an existing workspace directory; a path alone does not create a package. The selected binary's canonical identity is checked while it remains the session's bound source.

A client must perform the MCP handshake before calling tools. Use the server's `commands` result or tool catalog for current argument schemas and eligibility. A tool may be listed but refuse when its image, document, generation, resource, or authorization prerequisites are not met. Transport is local; there is no remote debugger in this mode.

## Tool discovery and safe edits

The default `MACSCOPE_MCP_LIST_PROFILE` is `core`. Set it to `full` before launching the process when the client needs the broader documented catalog:

~~~zsh
MACSCOPE_MCP_LIST_PROFILE=full /path/to/MacScope.app/Contents/MacOS/MacScope --mcp /path/to/binary
~~~

This setting changes **advertisement only**; it is not a command allow-list, a capability gate, or an escalation of authority. Unknown profile text emits a warning and selects `full`. The server maintains a separate, closed set of executable commands with bounded arguments, replies, cancellation, and source/analysis identity checks. Some writes support `basedOnGeneration` to refuse edits against stale analysis; inspect the live schema and returned generation before using that precondition.

Ordinary `rename`, `set-comment`, and other edits change the session's live state. They do **not** automatically save a `.mscope` package. Use the documented `save-workspace` operation where admitted. A `--journal` session records edits for replay; a journal is **not** itself a newly published workspace snapshot. The file must be an authorized explicit path. Consult the [Python client](../MacScope/python/README.md) for its basic subprocess wrapper; its `open()` signature launches only `--mcp <path>`, without optional `--slice` or `--journal` parameters.

## Verified Analysis: distinguish four states

The current code exposes three specialized MCP commands:

| Command | Intended use | Crucial boundary |
| --- | --- | --- |
| `verified-commit` | Commit one reviewed `name`, `comment`, `addressType`, or `functionSignature` with an audit record. | **Headless owner with an attached edit journal only**; bound document sessions are refused. The commit point is the fsynced journal line plus same-process live projection, not saved-package publication. |
| `verified-checkpoint` | Compare a supplied expectation against the **current live store** without mutation. | Same-process readback only; it does not prove durability or a fresh load from disk. |
| `verified-checkpoint-isolated` | In the supported async headless path, check operation expectations from a **saved package** using a fresh child process. | Not attachable and not available for a bound document session; package identity, timeout, and refusal paths apply. |

For `verified-commit`, `name`, `comment`, and `functionSignature` target a **function entry**; `addressType` targets a **non-entry address inside exactly one mapped segment**. Values have field-specific canonicalization and UTF-8 limits. `functionSignature` takes canonical signature JSON rather than a free-form declaration. Read the published tool schema before supplying a value.

A successful headless commit reports `verificationTier: journal+live-projection`, `durability: journal`, and `evidenceQuality: synthetic-link`. In particular, synthetic evidence links are placeholders, not confirmed origin/semantic evidence. A returned `expectationOperation` can be used to construct the later checkpoint request. No command should label a journal receipt “persisted and independently verified” until the saved package has actually been checked.

For retries, provide a stable `operationId`. An exact replay of the same operation can return `existing`; reusing the ID with different address/field/value/rationale is a conflict. If the reply reports an **indeterminate** commit or a recovery latch, do not blindly retry within the same process: restart `--mcp` against the same package and journal to reconcile before acting.

## Evidence provenance and limitations

- A source image, selected slice, session revision, verified annotation receipt, and newly read package are different identities. Preserve the IDs in any automated report.
- An imported AIRS claim, model suggestion, native analysis result, or attached tool reply is not automatically accepted workspace truth.
- A test fixture or portable-core verification does not certify installed app/service behavior. [Source status](STATUS.md) identifies what was inspected and what remains untested in this documentation pass.
- The [capability contract](../MacScope/PARITY_CONTRACT.md) governs supported architectures and excluded debugger/decompiler targets.

**Implementation references:** [launcher](../MacScope/App/MCPLauncher.swift), [server](../MacScope/Services/Scripting/MCPServer.swift), [tool listing profile](../MacScope/Services/Scripting/MCPToolListingProfile.swift), [verified commit](../MacScope/Services/Scripting/WorkspaceScriptingAPI+VerifiedCommit.swift), [live checkpoint](../MacScope/Services/Scripting/WorkspaceScriptingAPI+VerifiedCheckpoint.swift), [isolated checkpoint](../MacScope/Services/Scripting/WorkspaceScriptingAPI+VerifiedCheckpointIsolated.swift).
