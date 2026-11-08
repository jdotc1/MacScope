# Assisted Objective-C void0 statements

`ObjCVoid0ExportService` consumes a captured `MacIRFunction` and explicit, independently qualified source evidence. Its only successful output is an ordinary instance `objc_msgSend` statement for a fixed method with zero explicit arguments, exact `void` return, and a non-consuming source-qualified object receiver. The result remains `LOWERED_UNCOMPILED`, records source assistance, and requires separate complete-body admission.

For example, a complete ordinary `- (void)refresh;` contract, qualified `self`, positive selector-reference identity, and unused catalog result may produce:

```objc
((void (*)(id, SEL))objc_msgSend)(self, @selector(refresh));
```

The required header is `<objc/message.h>`. There is no redeclaration, generic variadic fallback, bridge, owning local, ARC operation, or runtime execution.

## Evidence and composition

`makeContext` bounds and inspects the complete request before comparing capture or evidence identities. It retains an immutable value snapshot and gives the context a private instance identity. Captured image/slice/analysis/function identities and receipt references are reused; this service neither computes fingerprints nor authenticates receipt contents. Supplying DTOs is an adapter responsibility and does not turn absent or unrelated facts into qualified evidence.

`resolvePlainSend` accepts only an instruction identity. It finds the unique stored instruction and derives its frame, operands and result from that snapshot. The contract, operand and unused-result gates issue certificates that cannot be constructed outside their implementation file. Planning rejects certificates from another call or context, even if the external capture fields match.

The contract gate requires a complete qualified declaration or explicit source-assisted call-site contract. Variadic status, receiver consumption, special ownership, effective family, dispatch side, calling convention, direct-method status, applicability and resolved semantic completeness are explicit facts. Missing Boolean values remain unknown. Runtime metadata alone refuses. Present runtime encoding is consumed in full and must be exactly `v16@0:8`; absent encoding is permitted only with the otherwise complete source contract.

The receiver gate accepts a unique authoritative object parameter row and entry binding. `self` additionally requires a unique qualified enclosing instance method. A qualified `id receiver` needs no invented nominal class. Simple identity-preserving assignments are permitted only through positively 64-bit X-register destinations and X-register or entry-GPR sources, with unique definitions ordered before the call and no branches, joins or earlier return. W-register sources/destinations, narrowed receiver leaves and unknown-width temporaries refuse. This receiver proof is separate from conservative W/X matching for result liveness. Arbitrary expressions, integer conversion, memory reconstruction and weak/joined values refuse.

Known captured parameters, locals and name bindings named `objc_msgSend`, `id` or `SEL` refuse with `EMISSION_BINDING_CONFLICT`, because they can shadow the runtime function or cast typedefs. This bounded check does not invent an unshadowed binding certificate for an entire source body; complete-body lexical and ownership admission remain separate.

## Complete bounded inspection

The use proof visits every supported operation input, call argument/control input/rich piece/indirect result pointer, nested value, switch index/case/default target, phi incoming value, function return value and instruction `returnTarget`. Register `wN`/`xN` views share an SSA identity. A non-nil suppressed result must be the uniquely defined catalog `x0`/`w0` result and have no use. Definitions, value identities and evidence are never compared through recursive synthesized `MacIRValue` or `MacIRInstruction` equality.

Unknown values, unknown operations, opaque intrinsics and uninspected semantic sidecars refuse. The explicit sidecar refusal list covers the current instruction model; any future sidecar requires review of this inspector. Function CFG/SSA auxiliary models and format-call sidecars also refuse. Scalar memory width/extension metadata carries no extra value inputs; reconciliation evidence and disassembly source spelling are not used as semantic authority. This conservative first envelope can refuse a call whose broader function would require a separate semantic proof.

Limits are refusals, with no truncation:

- 2,048 instructions and 64 combined linkage/contract/operand/enclosing-method records.
- 32,768 aggregate value visits, depth 64, and at most 128 inputs per supported nested collection.
- 128 incoming values per phi and 4,096 phi inputs in total.
- 256 KiB aggregate inspected evidence/source text, 128 UTF-8 bytes per identifier/selector, and 64 UTF-8 bytes per raw encoding.

All string admission counts stop at the first byte above their limit. All value traversal is iterative. The inspector also bounds function metadata rows, call input collections and composite fragments before walking or flattening them.

## Scope and validation

This is an internal app-module service. It adds no RG3 packet changes, regeneration adapter, printer integration, method/class body replacement, compilation claim, app launch or generated-call execution. Full-body control/lifetime closure and a future typed Objective-C export transport remain separate work.

`ObjCVoid0ExportServiceTests.swift` defines the eight accepted design groups plus immutable-call substitution, return-target-only use, context/identity conflicts, receiver ambiguity, sidecar refusal, and exact node/depth/phi/text/record boundary cases. `RG5_VOID0_STANDALONE` exposes the same synthetic scenario functions to a separately authorized module-level runner without importing the app test module. The implementation handoff leaves these new definitions unrun; validation evidence belongs to the parent-owned first changed-boundary check, not to this source document.
