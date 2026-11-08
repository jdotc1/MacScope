# Focused LLVM, MacScope, and Capstone comparison

This developer-only workflow adds a third observation to the existing ARM64
`differential_sweep.py` report. It is limited to 128 explicit words and does not
generate or sweep a random corpus. The example list covers a few basic arithmetic,
load, branch, return, and undecodable encodings. It is a diagnostic sample, not a
coverage or correctness claim.

Requirements: a compatible `cstool` executable, the active Xcode command-line
LLVM tools, and a probe built from the intended MacScope decoder sources. Use an
existing source-matched probe and retained evidence when available. Probe builds
and further comparisons remain subject to the repository's verification and
storage policies.

For a new, authorized run, choose a new output directory outside the checkout and
supply the source-matched probe:

```sh
storage-guard run -- python3 Scripts/arm64_golden/differential_sweep.py \
  --words-file Scripts/arm64_golden/fixtures/focused-arm64.words \
  --probe "$PROBE" --jobs 1 --out "$OUT"
storage-guard run -- python3 Scripts/arm64_golden/compare_capstone.py \
  --sweep "$OUT/sweep.tsv" --base 0x100000000 --out "$OUT/capstone.json"
```

The comparator checks the base against `summary.json`, keeps every row in input
order, and records the address, all three renderings and Capstone's decode status.
It refuses to replace an existing output. A failed Capstone decode is recorded
as `not-decoded`, not as proof the encoding is invalid. Syntax, aliases, target
features, and version differences can cause textual disagreements. Investigate
individual rows against the relevant ISA and tool capabilities before drawing
semantic conclusions. The Swift probe is standalone decoder evidence, not an app
build, installed acceptance, or decompiler qualification.

## Existing test driver

The opt-in test mode reuses an existing source-matched probe and the three
previously built Csmith objects. It selects the first eight instructions from
each object plus the seven curated words, removes duplicate words, and runs
the existing LLVM/MacScope comparison followed by Capstone. It does not rebuild
or re-verify the supplied products. Supply objects from the documented Csmith
fixture sources and compiler settings; the caller is responsible for their
source and build identity.

```sh
./Scripts/test.sh --arm64-oracles --probe "$PROBE" \
  --fixture-objects "$OBJECT_DIR" --out "$NEW_EXTERNAL_OUT"
```

The output directory must not already exist. The driver uses the storage guard.
`selected.json` records the original object offsets and words; the comparison
uses new synthetic addresses, so original PC-relative targets and relocations are
not retained. The curated cases gate decode availability and LLVM/MacScope
spelling-only differences. Csmith sample differences are reported for review,
not treated as semantic verdicts. The regular Xcode test mode is unchanged.
Portable unit tests for the comparison and selector are discovered under
`Scripts/tests` by the governance suite.
