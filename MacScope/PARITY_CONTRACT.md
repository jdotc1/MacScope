# MacScope Capability Contract

**Source/evidence boundary (2026-10-27):** This contract records approved product scope and exclusions. The [source-status snapshot](../docs/STATUS.md) and [capability matrix](../docs/CAPABILITIES.md) describe observable code and entry points, not native or installed gate acceptance. Earlier Apple Silicon/H-series reviews, handoffs, and roadmap/program records are not tracked in this Git revision. A proposed profile, portable draft, or reference-tool comparison does not establish enabled runtime support or behavioral equivalence.

Authoritative, binding scope and acceptance vocabulary for MacScope's capability
surface. Where a descriptive guide disagrees about **approved scope**, this
contract wins; where a claim concerns **current implementation or qualification**,
it requires source and candidate-specific evidence. No dated planning artifact is
a substitute for a signed installed-product receipt.

## 1. Capability scope

**Current product direction:** native SLEIGH is the default ARM64 decompiler; MacIR is the distinct retained analysis/fallback substrate. SSA remains default-off and SEC lanes are off under the recorded product policy. Earlier U-series proposals do not establish runtime support or installed acceptance. For tracked user-facing source paths see the [capabilities guide](../docs/CAPABILITIES.md).

**Local AI provider:** MTPLX is the only supported product inference integration. MTPLX owns model loading, unloading and context management; MacScope retains explicit loopback endpoint, bounded request policy and model selection authority behind its existing worker boundary.

**Active MTPLX precision-first contract:** integration and tuning prioritize
grounded accuracy and faithful semantics over speed. Accept only explicit valid
MTPLX policy and exact observed endpoint/model/context authority; desired model
names and stored preferences are not observations of a ready runtime. Reasoning
and context choices must be quality-evaluated rather than reduced solely for
latency. Unknown or insufficient evidence remains explicit, and malformed,
stale or ungrounded outputs cannot become workspace truth. Retain bounded
requests, cancellation/drain semantics, typed result validation and existing
app-owned tool authorization; tuning grants no additional execution authority.
Live quality evidence and synthetic transport evidence are distinct. A prior
MTPLX execution/evaluation design was kept outside this tracked repository
revision; its absence is not evidence that live tuning or installed acceptance
has been completed.

MacScope's target is a **comprehensive, native Apple-Silicon macOS
binary-analysis workbench** — defined on its own terms, not relative to any
other product. The material capability surface is:

- **Loading:** Mach-O executables, app bundles, dylibs, frameworks, XPC
  services, universal/fat containers, dyld shared-cache images; plus ELF and PE
  for cross-format inspection.
- **Static analysis:** ARM64 + x86_64 disassembly, control-flow graphs,
  cross-references, symbol and import/export recovery, Objective-C
  class/metadata and Swift metadata/demangling, code signatures, chained fixups,
  DWARF/dSYM debug info.
- **Decompilation:** ARM64 pseudocode with structured control flow and
  typed-local recovery.
- **Debugging:** LLDB-backed launch and arbitrary local process attach for
  macOS ARM64 targets. Local attach is an in-scope capability (explicit product
  decision, 2026-07-13), subject to macOS signing, hardened-runtime,
  authorization, user-boundary, SIP, and platform protections. The product
  must provide process identity/compatibility checks, precise denial
  diagnostics, PID-reuse protection, and distinct detach-versus-terminate
  semantics; “arbitrary” does not promise that macOS permits every target.
- **Editing & automation:** byte patching + an ARM64/x86 assembler behind an
  app-owned assembler boundary; reviewed pure-Swift encoder implementations may
  run in the app, while native or otherwise crash-prone assembler engines remain
  service-isolated; a scripting/command surface (in-process API, MCP) and a
  native plugin story.
- **Workspaces:** the current `.mscope` package (`manifest.json` plus
  attachments, atomically replaced) and its SQLite serialization/staging
  layer, with document lifecycle, autosave, and conflict handling. Phase 2
  durable identity and recovery requirements are frozen independently of the
  future physical package representation, which remains an F1 decision.
- **AI investigation (Phase 2):** a local-first, evidence-grounded assistant
  whose first release uses typed read-only MacScope operations and current,
  image-qualified citations. Later authority tiers remain separately gated.

Code presence alone is **not** completion — see §3. Behavioral correctness is
validated against **authorized external reference oracles** (see §7) and
MacScope-owned semantic contracts; adopting an approved dependency does not by
itself establish correctness.

## 2. Project status

- **First-party design-system reuse.** The pinned Lumen submodule and local Swift package recorded in
  [FIRST_PARTY_COMPONENTS.json](../FIRST_PARTY_COMPONENTS.json) provide the
  design system. Exact commit/tree provenance, offline ordinary builds,
  source-bound qualification and preserved user settings remain required.
- **Platform/toolchain decision (2026-07-13).** MacScope requires Apple
  Silicon, macOS 27.0 or newer, and the current Xcode 27 major line with its
  bundled Swift compiler in Swift 6 language mode and bundled LLDB. Xcode
  27 beta, RC, and patch/build revisions are accepted; a transient build
  number is not part of the product contract.
- **Local signing/distribution decision (2026-07-13).** Keep certificate-backed
  Apple Development signing for stable local development and installed-app
  validation. Release builds are Developer ID signed and notarized and published on the
  repository's Releases page.
- **Phase 2 foundation acceptance.** F0 requires frozen authority,
  persistence, threat, capability, corpus, and evaluation contracts plus a
  fail-closed executable validator. Volatile branch, review, and gate status
  requires separately retained dated evidence, not this binding capability
  contract or a [status snapshot](../docs/STATUS.md).
- **Phase 2 authority decision.** The MacScope app alone owns durable reducer
  state, authorization, dispatch/routing, result and evidence acceptance,
  canonical commit, persistence, and final user-visible truth. A worker may
  mechanically execute only a declared app-authorized operation within its
  narrow role and returns a versioned typed proposal/result without inheriting
  app authority.
- **Phase 2 historical release ceilings.** R0 was foundation-only and had
  no execution authority. The scoped R1 Grounded Local Assistant contract
  limits assistant-origin operations to typed native reads, without shell,
  debugger control, workspace mutation, or external-tool execution. This
  is **not** a claim that the independently authorized terminal or debugger
  product surfaces are absent from the current app.
- **Phase 2 F0 historical non-claims.** F0 itself did not select or integrate a provider/model,
  added a new XPC target, exposed a shell or PTY, or applied a Phase 2
  persistence migration.
- **Debug Assist boundary.** Arbitrary local process attach remains in scope for
  later typed, read-only-first Debug Assist after debugger identity/lifecycle
  prerequisites. Remote debugging remains an explicit exclusion.
- **Selected REA integration (owner-authorized, 2026-10-11).** The pinned
  `morluto/rea` native/dyld, compiled UI and captured-process comparison algorithms
  may be selectively copied with their reviewed permissive dependency closure
  into a digest-bound JavaScriptCore resource hosted only by AnalysisWorker.
  MacScope retains loader, process, capture, evidence acceptance and persistence
  authority. No REA server, Node runtime, arbitrary scripts, new inference provider
  or automatic target execution is introduced. Each capability remains unavailable
  until its affected native/worker and installed acceptance passes; existing
  successful reconstruction evidence retains its original source identity.
- **Approved open-source reuse (binding, 2026-07-20).** Public open-source
  components with express owner approval may be vendored, linked, invoked,
  adapted, or selectively copied only in the approved integration mode.
  The former local owner allowlist is not tracked on this Git revision; its
  absence does not extend approval to additional components. Every
  dependency-bearing change must use an
  immutable revision/checksum, preserve applicable licenses and notices, be
  recorded in `THIRD_PARTY_COMPONENTS.yml`, avoid implicit build-time downloads,
  keep dependency-specific objects behind MacScope-owned protocols/DTOs, and pass
  the required security, determinism, differential, rollback, and full-suite
  gates. Proprietary, non-public, unapproved, or license-incompatible source and
  binary resources remain prohibited. Required public open-source license and
  notice files are authorized repository content; this authorization does not
  extend to proprietary reference-tool code, resources, branding, or SDK
  implementation code.

## 3. Capability status vocabulary

Target: **full functional and behavioral coverage** of the capability scope in
§1, except the explicit exclusions. Code presence alone is **not** completion.
Every tracked capability is one of these states:

1. `absent` — not implemented.
2. `implemented_unreachable` — code exists but no user/menu/shortcut/scripting
   path reaches it.
3. `reachable_unvalidated` — user-reachable, but not validated end to end.
4. `internally_validated` — exercised by MacScope tests.
5. `behaviorally_equivalent` — output matches an authorized external reference
   oracle on reference inputs (§7).
6. `approved_deviation` — an intentional difference backed by a recorded
   decision (below).
7. `explicit_exclusion` — a documented non-goal (below).

Acceptance: a capability is "done" only at `internally_validated` or higher (or
is an `approved_deviation` / `explicit_exclusion`). A claim of full coverage
additionally requires `behaviorally_equivalent` evidence (a normalized
golden-output match against an external oracle).

### Milestone-gate status vocabulary

Roadmap milestone gates use a separate three-state program vocabulary:

1. `PASSED` — every criterion is satisfied by recorded, current evidence.
2. `BLOCKED` — at least one named criterion remains unsatisfied; the blocker is
   recorded and may be evidence-, environment-, policy-, or engineering-bound.
3. `GATED` — evaluation or activation is intentionally deferred until a named
   prerequisite gate reaches `PASSED`.

Gate status never substitutes for the capability states above. A gate may be
`BLOCKED` or `GATED` even when individual capabilities are internally validated,
and it may become `PASSED` only from evidence rather than source presence.

## 4. Explicit exclusions (approved omissions — NOT gaps)

These are intentional product decisions. They are **not** unresolved questions,
missing work, release blockers, defects, or future implementation tasks, and
they are **excluded from coverage calculations and validation matrices**. Do not
implement them, create tasks/fixtures/loaders/ decoders/UI/tests/benchmarks for
them, or list them as gaps/blockers/decisions.

1. x86 debugging.
2. x86 decompilation outside the staged macOS x86_64 SysV native profile. The sealed DTO contract is admitted;
   production request construction and native runtime exposure remain disabled.
   Resource admission, runtime readiness and semantic acceptance are later phases.
   i386, Windows, native Swift ABI and an x86 MacIR backend remain excluded.
3. Windows debugging.
4. Windows decompilation.
5. **PowerPC disassembly and analysis.**
6. **Hexagon disassembly and analysis.**
7. **i386 / 32-bit x86 disassembly and analysis.**
8. **Remote debugging of a target process on another system.** Local ARM64
   launch and arbitrary local process attach on the same Mac remain in scope.
9. **32-bit ARM / Thumb (AArch32: A32 and T32/Thumb-2) disassembly and
   analysis** (decided 2026-10-17).

> **Approved architecture omissions:** MacScope intentionally omits PowerPC,
> Hexagon, i386/32-bit-x86, and 32-bit ARM/Thumb (AArch32) disassembly and
> analysis. These omissions are
> explicit product decisions. They are not coverage gaps, unresolved deviations,
> release blockers, or future implementation requirements, and they are excluded
> from coverage calculations and validation matrices. x86_64 loading,
> disassembly, and static analysis remain in scope.

**Scope guards (do not over-broaden the exclusions):**

- The exclusions do **not** generalize to **x86_64**: x86_64 loading,
  disassembly, and static analysis remain **in scope**.
- The exclusions do **not** generalize to **ARM64**: ARM64 loading, disassembly,
  analysis, decompilation, and macOS debugging remain **in scope**. The 32-bit
  ARM exclusion covers the AArch32 instruction sets only, not arm64 or arm64e.
- Windows/PE **loading, disassembly, static analysis, symbols, imports, exports,
  relocations, and metadata** remain **in scope** — only Windows _debugging_ and
  _decompilation_ are excluded.
- Other architectures (68k, 6502, etc.) are **not decided** by
  this contract; do not silently classify them as excluded. They are open
  product questions.
- When a finding couples an excluded architecture with an in-scope concern (e.g.
  "PowerPC + arm64e PAC semantics"), remove only the excluded-architecture
  portion and keep the in-scope part.

## 5. Approved deviations (with evidence)

Intentional design choices, recorded so they are not re-litigated as gaps:

- **LLDB-only debugger backend** (debugger via LLDB public APIs).
- **ARM64 production decompilation**; macOS x86_64 SysV has a staged, disabled
  native target contract. No Intel pseudocode capability is advertised yet.
- **Apple-Silicon / macOS-centric** platform focus.
- **MacScope-owned `.mscope` package** as the stable project format. The
  current GUI package is a JSON manifest plus attachments; SQLite is used as a
  serialization/staging authority. A future physical package/schema change is
  not approved until the F1 migration and recovery design is frozen.
- **Richer Python SDK object-model work is deferred**, while the tracked
  [dependency-free Python MCP client](python/README.md) already provides a
  local headless command wrapper. Native-plugin extensibility remains bound
  by its signed/authorized host contracts.
- **Auto-update / Updates-preferences deferral.**

## 6. Open product questions (not settled by this contract)

These remain open unless a stronger recorded decision resolves them:

- The final validation and safety requirements of byte editing, instruction
  assembly, and patched-executable output across supported inputs. The Hex
  patch/assembler/export source and menus exist; that fact does not establish
  signed, loadable, or behaviorally accepted patched outputs.
- Full dyld shared-cache depth (sub-cache stitching + symbolication).
- Residual scripting primitives beyond the approved SDK deferral.
- General AppleScript automation beyond the specific captured-workspace
  `export-project` bridge; [its usage contract](../docs/REGENERATION-USAGE.md)
  does not authorize arbitrary headless/remote scripting.
- The scope of BinDiff interoperability beyond the **existing BinExport2 export
  command**; a reachable export is not blanket format acceptance or BinDiff
  import capability.
- Native execution acceptance outside the bounded, manually confirmed
  [Run Function](../docs/NATIVE-FUNCTION-EXECUTION.md) helper contract;
  source integration is not host isolation/safety or installed acceptance.
- Behavioral reconstruction beyond [captured-app skeleton export](../docs/REGENERATION-USAGE.md),
  whose function bodies remain nonfunctional stubs.
- Other architecture families (68k, 6502, …).

## 7. Behavioral-equivalence acceptance rule

Reaching `behaviorally_equivalent` for an in-scope capability requires a
normalized golden-output comparison against an **authorized external reference
oracle** on a fixed binary set. MacScope's side ships in
`MacScope/Tests/CoreTests/Support/Golden/GoldenOutput.swift`; the fixture layout reserves slots for
reference outputs. Two independent oracles are
supported — an open-source disassembler (Ghidra) and a reference disassembler —
each normalized to the same schema. Do **not** generate or require golden
fixtures for PowerPC, Hexagon, i386, or 32-bit ARM/Thumb.
