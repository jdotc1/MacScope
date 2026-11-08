# Focused QBDI ARM64 trace

This opt-in developer-side mode instruments one owned two-instruction function:
`add w0, w1, w2` (word `0x0b020020`), followed by `ret`. The add uses the
inputs from MacScope A64 oracle `v000001`; the callback records pre- and
post-instruction X0, X1, X2, and NZCV. The program requires one before and
after callback and checks the returned value and the selected register effects.

This traces an independently built fixture. It is not a MacScope app runtime
trace, a fresh MacIR evaluation, a native qualification, or proof of all
instructions or operating-system behavior.

## Reuse existing evidence

```sh
./Scripts/test.sh --arm64-qbdi --reuse-receipt "$RECEIPT"
```

This displays a retained receipt without compiling or running QBDI. It labels the
text as historical evidence; it does not authenticate the receipt, verify its
source identity, or promote it to current qualification.

## New run

The verification-reuse guardrail applies: **do not repeat a check whose inputs
have not changed without the maintainer's explicit permission in chat for that specific
run**. For an authorized new run, use a new output directory outside the
repository:

```sh
./Scripts/test.sh --arm64-qbdi --run --out "$NEW_EXTERNAL_OUT"
```

The driver uses the storage guard and requires a macOS arm64 C compiler and
QBDI headers and library. The QBDI prefix defaults to `/opt/homebrew/opt/qbdi`
and can be changed with `--qbdi-prefix`. The output receipt records the trace
and limited scope; it is not a digest-bound source-verification or qualification
receipt. A failed or interrupted run may leave partial output, never a passing
receipt. The normal Xcode CoreTests mode is unchanged. Portable tests of the
driver and entrypoint use substitute tools and are discoverable under
`Scripts/tests` by the governance suite.
