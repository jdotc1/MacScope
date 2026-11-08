# MacScope documentation

MacScope is an Apple-silicon macOS binary-analysis workbench. This index
separates the current product guides, binding capability decisions, and historical
engineering material. A source file, test fixture, or proposed design does not by
itself establish that a feature passed signed, native, or installed acceptance.

## Start here

| Document | Use it for |
| --- | --- |
| [Product overview](../README.md) | What MacScope does, its limits, and a quick build entry point. |
| [Capabilities and limitations](CAPABILITIES.md) | Format/architecture matrix, product surfaces, and support boundaries. |
| [Workflows](WORKFLOWS.md) | Opening and investigating binaries, native pseudocode, crash reports, AIRS review, debugging, and automation. |
| [Headless MCP and verification](MCP-AND-VERIFICATION.md) | CLI launch variants, tool discovery, journal semantics, verified commits, and fresh-process checkpoints. |
| [Crash report to pseudocode](CrashReportImport.md) | `.ips` import, UUID-bound frame resolution, captured registers, and navigation limits. |
| [Native Run Function safety](NATIVE-FUNCTION-EXECUTION.md) | Confined local ARM64 function calls, signature confirmation, execution risk, and cleanup. |
| [Captured-app project export](REGENERATION-USAGE.md) | AppleScript regeneration of a buildable but nonfunctional Xcode skeleton. |
| [Development and qualification](DEVELOPMENT.md) | Environment, dependency handling, build/test commands, signing, and installation gates. |
| [Evidence status](STATUS.md) | How to read status claims, source entry points, and what is not established by source alone. |
| [Capability contract](../MacScope/PARITY_CONTRACT.md) | Binding inclusions, exclusions, and behavioral-acceptance vocabulary. |
| [App source guide](../MacScope/README.md) | Targets, service boundaries, source layout, and implementation references. |

## Specialized reference

- [Product nomenclature](brand/Nomenclature.md) and [theme tokens](design/tokens/token-reference.md).
- [Offline dependencies](dependencies/DependencyWorkflow.md),
  [component manifest](../THIRD_PARTY_COMPONENTS.yml), and
  [third-party notices](../THIRD_PARTY_NOTICES.md).
- [Local unsigned Debug variant](UNSIGNED_DEVELOPMENT.md), separate from
  certificate-backed builds and installed acceptance.
- [ABI evidence](abi/darwin-varargs/VALIDATION.md).
- [Python API](../MacScope/python/README.md),
  [parser differential/oracle guide](../Scripts/parser-oracles/README.md), and
  [native decompiler bridge guide](../Tools/NativeDecompilerBridge/README.md).
- [Portable Swift Linux toolchain helper](../Scripts/setup-swift-linux.sh),
  explicitly separate from the required Xcode/macOS app build and qualification.

## How to interpret the rest of this tree

`docs/design/` contains individual designs and contracts; some remain proposals
or disabled profiles. Dated files under `docs/build/` and
`MacScope/Tests/CoreTests/GoldenFixtures/` preserve evidence for their recorded
inputs and dates, not an assertion about the latest `main`, the installed app,
or future roadmap gates. The source and contract can advance independently of
those artifacts.

For a
current evaluation use [STATUS.md](STATUS.md) and retain the actual qualification
receipt from the relevant macOS build.
