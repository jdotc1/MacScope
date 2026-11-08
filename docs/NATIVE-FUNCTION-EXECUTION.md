# Native Run Function: execution scope and safety

The [editor control](../MacScope/Features/Editor/RunFunctionSheet.swift),
[preparation gate](../MacScope/Services/NativeExecution/NativeFunctionPreparation.swift),
and [execution coordinator](../MacScope/Services/NativeExecution/NativeExecutionCoordinator.swift)
are tracked. Their presence is **not** a signed runtime acceptance result.

**This feature runs actual native code on your Mac.** Do not use it to
detonate unknown or hostile binaries. The bounded owned-process design
is not a security guarantee, substitute for a malware-analysis sandbox,
or permission to execute software you do not own or have authority to run.

## What it does

On a compatible, currently bound macOS ARM64 executable, the editor's
**Run Function…** control prepares an exact image/function binding and
starts a fresh MacScope-owned target. The program's loader and
constructors can execute before the selected function; the call then
runs before the target's main body. Results can include a typed scalar
return value, runtime function address, fault/diagnostic details, and
**before/after snapshots of specifically selected memory regions**.

This is separate from the normal local debugger session, not a
headless bulk execution interface or reconstruction oracle. A
successful call does not establish behavioral equivalence to an
independently reconstructed function.

## Admission and controls

- The original, unchanged executable must still match its retained
  file stamp, slice identity, UUID, bytes, and image/analysis
  provenance. A fresh open may be required after any file change.
- This source path currently requires a **macOS ARM64 main executable**
  with one valid `LC_MAIN` and UUID. Encrypted, ambiguous, or
  unsupported inputs are refused. A dylib or general PE/ELF file is
  not a native-call target.
- The call uses a **C calling convention**; the user must confirm the
  prototype when evidence is insufficient or edited. DWARF-derived
  evidence and manually overridden signatures are distinguished.
- Scalar and bounded pointer/buffer arguments are supported. The
  request allows up to **16 parameters**, and selected observation
  regions are limited to **16 regions / 64 KiB total**.
- The user-selectable call limit is **0.1–10 seconds**; the coordinator
  also applies a separate overall watchdog. Timeout is a guard,
  not proof that every side effect was prevented.
- The coordinator binds its attach to an owned, retained process
  instance and validates response identities. It runs only one
  native-call job at a time. If cleanup cannot be confirmed, further
  calls are blocked until the app restarts.

The precise limits and eligibility rules belong to
[NativeFunctionCallModels.swift](../MacScope/Models/NativeExecution/NativeFunctionCallModels.swift),
[NativeFunctionPreparation.swift](../MacScope/Services/NativeExecution/NativeFunctionPreparation.swift),
and the [owned target](../MacScope/Services/NativeExecution/NativeExecutionOwnedTarget.swift).

## Interpreting results

- A *completed call* means this bounded execution path reported an
  outcome, **not** that the function is safe or semantically equivalent
  under every caller context, process state, or ABI.
- Memory comparison includes only nominated buffers/globals; writes
  to other regions, writes later restored, and external side effects
  can escape those snapshots.
- Constructors, loaded libraries, files, network operations, child
  processes, or other side effects may occur depending on target
  behavior and host policy. Treat input as executable, not passive.
- The printed error and cleanup status matter. Do not infer a void
  return or no side effect from missing result data.

The general [Workflows](WORKFLOWS.md), [Capabilities](CAPABILITIES.md),
and [Status](STATUS.md) guides distinguish this source integration
from native/installed qualification.
