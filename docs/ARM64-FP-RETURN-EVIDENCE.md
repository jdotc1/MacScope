# ARM64 scalar floating-point operations and return evidence

This bounded investigation follows the retained Decompile-Eval task 0/O0
`_func0`, at `0x1000004b0` through `0x100000580` (exclusive). The observed raw
output was produced by source `cf2ba5f8120021022bc14d01d29a474a98b5ef51`.
The correction starts from main merge `08e8513712a3de5292d9279e38573cfc0d0aade8`.

The rule is to preserve independently known integer-register producers across
validated scalar FP operations and known flag-branch edges. A producer fact is
not a source declaration or proof that a register is the function's result.
Parameter order and return authority remain separate decisions.

## Contract trace

| Boundary | Retained evidence and source behavior |
| --- | --- |
| Decoded inputs | `str x0,[sp,#0x10]`, `str w1,[sp,#0xc]`, and `str s0,[sp,#8]` read the three incoming register views before local writes. |
| Parameter identity | The builder retains separate GPR and SIMD binding identities. Its recovered mixed-bank rows have no source positions. The raw printer emits `x0:int64_t in_x0, w1:int32_t in_w1, s0:float in_s0` in an ABI-input comment, rather than choosing a source parameter order. |
| Stack and data flow | The raw body preserves the three initial spills and their reloads. `ldrsw` supplies signed 32-bit index-use evidence. The array accesses preserve a 64-bit base plus a scaled index, and `ldr s0/s1` establishes binary32 memory accesses. These observations do not establish the original parameter names, array extent, qualifiers, or nominal pointer declaration. |
| Local type inference | `LocalTypeInferencePass` keeps width defaults unless stronger facts reach the same value/slot. Its `baseSlot` lookup only recognizes an exact mapped value, so the composite indexed address in this case does not propagate a pointer fact to the spilled base. The retained `local_10` remains `int64_t`; this correction does not change that inference rule. |
| FP intermediate representation | `scalarFPSemantics` already recognizes `fsub s0,s0,s1`, `fcvt d0,s0`, `fabs d0,d0`, and `fcvt d1,s1`. The main lifter attaches numeric descriptors and typed destination values. The previously accepted FCMP/PL recovery is preserved. |
| Return-producer effects before this correction | `BuilderState.returnProducerWrites` did not consume those scalar descriptors. Encountering a valid scalar FP operation therefore refused the whole producer walk. The return CFG also used the printable-comparison table as its validity test and refused `b.pl`. These were losses of recoverable effect/control-flow facts. |
| Corrected producer walk | Scalar operations with validated physical operands preserve GPR facts unless they actually write a GPR. MI/PL/VS/VC contribute their existing parsed target and fallthrough as possible successors. No condition expression or FP flag value is inferred. The retained function's last integer producer is the load at `0x100000574`. |
| Return authority and C output | The last three instructions are `ldr w0,[sp,#0x1c]`, stack restoration, and `ret`. A load-only producer remains insufficient under `admitsReturnProducerKinds`; the `unresolved_return_contract` fallback remains. The default printed `int64_t` is not evidence that the source returned a 64-bit integer. No new raw C compilability or runtime result is established. |

## Information that requires an independent signature

The integer and FP argument cursors advance independently. Consequently these
three source orders all associate `numbers` with X0, `size` with W1, and
`threshold` with S0:

```c
int f(float *numbers, int size, float threshold);
int f(float *numbers, float threshold, int size);
int f(float threshold, float *numbers, int size);
```

This is an ABI ambiguity demonstration, not reconstructed source. The retained
register uses alone cannot select among these orders or exclude unused formal
parameters. The bank allocation follows the independent NGRN/NSRN cursors in
[AAPCS64, parameter passing](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst#parameter-passing).
The existing Darwin scalar binder implements that distinction.

The benchmark's original declaration, `int func0(float numbers[], int size,
float threshold)`, supplies the missing source order, names, and return type to
DEA's separate assisted exporter. The W0 reload alone does not distinguish an
`int`, `unsigned int`, or another source-level contract. Visible stores of zero
and one are not promoted through memory without a proof of reaching stores and
alias behavior. This change deliberately preserves that refusal.

The supported fallback is the existing explicit source-prototype/ABI-binding
route, with the existing identity admission. The historical assisted packet
lacks the required image UUID/content identity and remains ineligible for
automatic RG3 stub replacement. Making its C syntax acceptable is separate from
proving execution equivalence or upgrading the raw result.

## Supported and refused cases

- Supported scalar numeric forms must pass the existing `scalarFPSemantics`
  parser, including width, arity, and immediate constraints, and use canonical
  in-range physical operands. S/D destinations do not write GPRs even when their
  numeric result is integer bits. Zero-register destinations also do not define
  a GPR value.
- A conversion that writes W/X marks that physical register's producer unknown,
  killing any earlier constant instead of borrowing it. It grants no return
  type or value authority.
- MI/PL/VS/VC are admitted only as known `b.`/`bc.` two-successor edges. Existing
  target parsing and reachable-row checks remain in force. Unknown suffixes,
  malformed mnemonics, extra operands, and missing targets remain refused.
- Mixed scalar widths, unsupported half forms, out-of-range/noncanonical
  registers, and invalid conversion immediates are not admitted by the new
  scalar rule. Existing validated vector handling is unchanged.
- A later S0/D0 result cannot borrow an earlier integer producer's authority.
  Load-only results, mixed-bank source-order uncertainty, and unknown
  instructions remain conservative. FPCR/FPSR state, exception/trap behavior,
  and source/runtime equivalence are not established by this effect inventory.

The production boundary is `MacIRBuilder+State.swift`: its scalar write
classifier and the two return CFG guards. New methods are added to the existing
`NoEvidenceReturnMarkerTests.swift`. No parameter binder, type-inference pass,
printer, decoder, assisted producer, identity consumer, or project configuration
is changed.

## Retained evidence and validation

The following are local navigation paths under
`<local path omitted>`; they are not
cross-device download links. Existing evidence is reused without rerunning or
rehashing the inputs:

- Original function and compile receipt: `cases/task-000-O0/c_func.c` and
  `cases/task-000-O0/reference-build.execution.json`.
- Instructions and capture receipt:
  `queues/macho-linux-v1/cases/task-000-O0/disassembly.stdout.log` and
  `disassembly.execution.json` in the same directory.
- Raw output and authoritative capture:
  `queues/macho-linux-v1/attempts/fcmp-pilot-4/cases/task-000-O0/pseudocode.c`
  and `decompile-result-fcmp-pilot-4.json` in the same directory.
- Pilot verdict: `queues/macho-linux-v1/attempts/fcmp-pilot-4/receipts/pilot-summary.json`.
  It remains `NOT_COMPILABLE` / `SIGNATURE_MISMATCH`. No candidate was executed;
  the normalized candidate was not reached.
- Assisted-only evidence: `compilation-repair/export-contract.json`,
  `signature-assisted.c`, `new-assisted-syntax.execution.json`, and `RESULT.json`.
  Its existing syntax pass does not establish raw recovery or runtime equivalence.
- Prior focused compiler/link recipe and retained-core receipt:
  `fcmp-fix/FIX-RECEIPT.json`, `final-primary-command.json`, and
  `final-new-test-link.execution.json`. These establish the reusable harness
  route, not validation of the new correction.

New validation uses the actual changed State primary with the retained static
core/dependency objects, plus a test-only import overlay containing only the new
methods and their existing helpers. The application target is not rebuilt. The
52-instruction retained-text fixture exercises the changed producer walk; it
does not decode or execute the benchmark binary again. New first-run receipts
are kept under the existing focused harness at
`<local path omitted>`.
The changed production primary compiled successfully once (47.017 seconds), and
the new-selector bundle linked successfully once (4.296 seconds). All seven new
methods passed on their first individual runs, with one executed test confirmed
per selector and zero failures. The retained-family method reached all 52 rows,
reported the final W0 producer as a load, and retained the load-only authority
refusal. The static core is reused from source
`4dcad20b7910735e6725bdba9961b9f8b6e1442f`; the retained compiler recipe uses
Swift 6 and the macOS 27.2 SDK with an arm64/macOS 27.0 target. This is a focused
native source regression result, not a newly built, installed, or qualified app.

Existing passing selectors, app qualification, source/signing/dependency
verification, and pilot/full runs are not repeated. The original raw failure and
assisted-only syntax result remain unchanged.
