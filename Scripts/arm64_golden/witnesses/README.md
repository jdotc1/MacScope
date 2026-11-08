# Focused Unicorn and Z3 witness

This developer-side mode uses one retained MacScope A64 oracle case and one
64-bit expression based on the unsigned `ubfiz` lifter. It is not an Xcode
CoreTests run, app acceptance, a fresh MacIR evaluation, or proof of C semantics.

* Unicorn executes only oracle `v000001` (`add w0, w1, w2`) with its recorded
  inputs. It checks X0, X1, X2, and NZCV, including zero extension of X0.
* Z3 searches for a 64-bit value where `(x & 0x1fffffffffffffff) << 2`
  differs from `(x << 2) & 0x7ffffffffffffffc`. `unsat` proves equivalence of
  those two fixed-width bit-vector models only.

## Reuse existing evidence

The driver can display a prior receipt without running Unicorn, Z3, a compiler,
or a source/dependency verifier:

```sh
./Scripts/test.sh --arm64-witness --reuse-receipt "$RECEIPT"
```

This displays historical evidence as supplied; it does not authenticate the
receipt, check its source identity, or promote it to a current qualification.
Use the original receipt and its source/checkout scope when reporting results.

## New run

The repository's verification-reuse guardrail applies: **do not repeat a check
whose inputs have not changed without the maintainer's explicit permission in chat for that
specific run**. If a new run is authorized, the opt-in command compiles the
witness and invokes Unicorn and Z3 once each. Choose a new output directory
outside the repository:

```sh
./Scripts/test.sh --arm64-witness --run --out "$NEW_EXTERNAL_OUT"
```

The driver uses the storage guard and requires the Unicorn headers and library,
a C compiler, and the `z3` executable. The Unicorn prefix defaults to
`/opt/homebrew/opt/unicorn` and can be overridden with `--unicorn-prefix`.
The new receipt records tool output and its limited scope; it is not a
cryptographically bound source-verification or native-qualification receipt.
A failed or interrupted run may leave partial output, never a passing receipt.
The normal `Scripts/test.sh` CoreTests mode is unchanged. Portable tests of
this driver's routing and failure handling use substitute tools and are
available through the existing `Scripts/tests` governance discovery.
