# MacScope evidence status

This page explains how to read status claims in this repository. It deliberately carries no commit pin or pass count: those go stale as `main` moves. For a current evaluation, build the commit you care about and retain the actual receipts.

Source presence, a test file, a passing historical run, a merged PR, and a qualified installed binary are distinct evidence classes.

## Entry points to verify in source

- [`AppCommands.swift`](../MacScope/App/AppCommands.swift) wires binary/workspace loading, the Disassembly/Pseudocode/Graph/Hex modes, crash-report and AIRS review windows, debugger, patching and assistant commands.
- [`MCPLauncher.swift`](../MacScope/App/MCPLauncher.swift) accepts a binary or saved `.mscope` workspace in `--mcp` mode, with explicit `--slice` (universal slice) and `--journal` (edit journal) launch forms; see [Headless MCP and verification](MCP-AND-VERIFICATION.md).
- [`MCPServer.swift`](../MacScope/Services/Scripting/MCPServer.swift) exposes a closed headless command catalog. [`MCPToolListingProfile.swift`](../MacScope/Services/Scripting/MCPToolListingProfile.swift) advertises a smaller `core` list by default (for example `info`, `decompile`, `functions`, `xrefs`) or `full` via `MACSCOPE_MCP_LIST_PROFILE`; listing does not change execution authorization.
- The [Python client](../MacScope/python/README.md) wraps a base `--mcp <path>` child process.
- The [capability contract](../MacScope/PARITY_CONTRACT.md) is authoritative for intentional inclusions and exclusions.

## Still unestablished without a fresh build

- Current App/CoreTests/Phase2Tests compilation and results on the required Apple-silicon macOS 27/Xcode 27 host.
- Live launch, signing, isolation, cancellation, and end-to-end acceptance for individual XPC services, MTPLX, LLDB, REA, native SLEIGH, and other optional resources.
- Universal pseudocode fidelity, reference-tool behavioral equivalence, safe execution of untrusted code, or complete/automatic reconstruction of original application behavior.
- Correctness of any particular exported file, patched binary, cross-image match, AIRS report, or verified annotation without its input-specific evidence and acceptance path.
- Correlation between current Git `main` and any installed `/Applications/MacScope.app`.

## How to refresh this snapshot

Resolve the exact new `main` commit, compare changed source paths and reachable commands against this snapshot, inspect **candidate-specific** build/test/installation receipts, and only then revise the date and observations. The [build guide](DEVELOPMENT.md) separates ordinary development from source-qualified candidate and installed-product validation. Do not roll forward a prior receipt merely because a commit merged.
