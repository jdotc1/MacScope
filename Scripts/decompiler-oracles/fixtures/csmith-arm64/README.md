# Bounded Csmith source fixtures

The three committed sources were generated with Csmith 2.3.0, Git version
`30dccd73b`, using seeds 101, 202, and 303. Each source records its exact
options. The bounds are `--max-funcs 3 --max-block-depth 2 --max-block-size 3
--max-expr-complexity 5 --max-array-len-per-dim 3 --concise`.

They are C source inputs, not a claim of decompiler correctness. They require the
matching Csmith runtime headers. For an authorized new fixture build, place
objects in a new scratch directory outside the checkout, for example:

```sh
storage-guard run -- xcrun clang -arch arm64 -std=c99 -O1 \
  -I /opt/homebrew/opt/csmith/include/csmith-2.3.0 \
  -c Scripts/decompiler-oracles/fixtures/csmith-arm64/seed-101.c \
  -o "$OUT/seed-101.o"
```

Use the same command for the other seeds. Record the compiler, options, and
resulting artifact for each investigation; compiler options affect the code.
Csmith and Clang warnings should be inspected, not assumed to establish a
runtime defect. The generated programs have not been used as a semantic oracle
for MacScope. Keep their source and relevant runtime headers with any exported
reproducer, subject to the applicable licenses.

To use existing objects in the bounded test driver, see `Scripts/arm64_golden/README-capstone.md`.
