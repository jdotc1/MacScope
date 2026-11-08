# Controlled synthetic BinDiff comparison

This opt-in developer-side comparison uses three hand-authored function records
per side. `_alpha` is unchanged, `_beta` changes an immediate from 2 to 3,
`_removed` is absent in the new set, and `_added` is new. Each function has one
basic block and there are no calls. The synthetic BinExport2 inputs contain the
`mov` operand records; other operands are incomplete. The standalone Swift
harness calls the production `FunctionVersionMatcher` with hand-supplied
fingerprints. These records are not real binary exports or fingerprints produced
by MacScope's analysis adapter.

## Reuse existing evidence

```sh
./Scripts/test.sh --bindiff-comparison --reuse-receipt "$RECEIPT"
```

This displays the retained receipt as historical evidence and runs neither
matcher. It does not authenticate the receipt, verify source identity, or
promote the result to a current qualification.

## New run

The verification-reuse guardrail applies: **do not repeat a check whose inputs
have not changed without the maintainer's explicit permission in chat for that specific
run**. For an authorized new run, choose a new output directory outside the
repository:

```sh
./Scripts/test.sh --bindiff-comparison --run --out "$NEW_EXTERNAL_OUT"
```

The driver uses the storage guard and requires `protoc`, the selected Swift
compiler, and BinDiff. Its default BinDiff configuration is
`/opt/homebrew/libexec/bindiff/8/bindiff.json`; override it with
`--bindiff-config` when necessary. It encodes the textproto inputs, compiles a
standalone matcher harness, invokes both comparison engines, and records their
outputs in `comparison.json`. It checks the controlled MacScope matcher
expectations; BinDiff's candidate pairs and scores are reported for inspection,
not gated as truth. A failed run may leave partial output but no final receipt.

The inputs and scores do not establish real-binary accuracy or installed-app
behavior. BinDiff's Ghidra exporter compatibility is a separate question. The
regular Xcode CoreTests path is unchanged. Portable tests of the driver use
substitute tools and are discoverable under `Scripts/tests` by governance.
