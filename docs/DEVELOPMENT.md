# Development, testing, and qualification

This is a source-backed guide. The scripts themselves remain authoritative for exact
arguments, dependencies, and safeguards. This documentation review did **not**
execute an Apple-silicon build, XCTest, signed-worker launch, or installed gate.

## Host and source requirements

- Apple silicon (`arm64`) with macOS **27.0 or later**.
- Xcode **27** (any supported beta, RC, or patch in that major line), its
  bundled Swift 6 toolchain and LLDB, and the repository-pinned XcodeGen.
- Verified repository-owned dependency sources, including the checked-out
  Lumen gitlink. Normal builds use the offline sources/verified external
  work-root artifacts, not background dependency downloads.
- An approved certificate-backed Apple Development identity for ordinary
  app and XPC builds, with manual/profileless signing and hardened runtime.
  The isolated CI and explicit unsigned Debug variant are separate policies.

Confirm the canonical repository remote URL and
the intended integration commit before qualifying. A remote may be named
`origin` or `github`; the **URL and ref**, not its nickname, establish identity.
Do not substitute a stale local checkout or an unrelated MacScope repository.

The declarative XcodeGen source is
[`MacScope/project.yml`](../MacScope/project.yml); generated
`MacScope/MacScope.xcodeproj` is disposable and must not be committed.
The checkout contains a [dependency manifest](../THIRD_PARTY_COMPONENTS.yml),
[notices](../THIRD_PARTY_NOTICES.md), and
[first-party component pin](../FIRST_PARTY_COMPONENTS.json).

## Ordinary development

From the repository root:

```zsh
./Scripts/bootstrap.sh
./Scripts/dev_loop.sh --build-only
```

A focused or bundle-scoped iteration uses:

```zsh
./Scripts/dev_loop.sh CoreTests/SomeSuite
./Scripts/dev_loop.sh Phase2Tests/SomeSuite/someCase
./Scripts/dev_loop.sh CoreTests
```

A selector always names the bundle. The developer loop reuses retained
DerivedData and verified dependency/cache evidence; it is **iteration evidence,
not a release or installed-acceptance result**. See
[`Scripts/dev_loop.sh`](../Scripts/dev_loop.sh) and its `--help` for concurrency,
work-root, cache, and test-timeout controls.

The explicit test runner is:

```zsh
./Scripts/test.sh
./Scripts/test.sh CoreTests/SomeSuite/someCase
```

With no selector, `test.sh` runs CoreTests. 

## CI and portable source-level checks

[`Scripts/setup-swift-linux.sh`](../Scripts/setup-swift-linux.sh) is an
**optional, explicit Ubuntu 24.04 x86_64 / Swift 6.4.2** helper for
portable source work. It is **not** an alternative to Xcode for building,
running, signing, or qualifying the macOS application. It installs no macOS
tools and does not change the application's Xcode 27/Swift 6 product contract.
Do not run it on an Apple-silicon Mac or invoke it as an implicit build step.

The standard-library Python client's portable tests can be run without a
MacScope app build:

~~~zsh
python3 Scripts/ci/run_python_client_tests.py
~~~

Native end-to-end Python tests still require a qualified MacScope executable
and the explicit binding described in [the client guide](../MacScope/python/README.md).

## Source-qualified candidate

A qualification run begins with a locally resolved, canonical remote-tracking
ref and an absolute **external** work root:

```zsh
./Scripts/qualify_local_private_build.sh \
  --work-root /absolute/external/macscope-candidate \
  --integration-ref refs/remotes/origin/main \
  --mode prepare
```

Substitute the **verified** ref name on the workstation. Supported modes
are `prepare`, `smoke`, `focused-test`, `full-test`, and `release`.
For a selected test, use `--mode focused-test --only-testing
CoreTests/SomeSuite/someCase`. The qualifier seals source/dependency identities,
uses the shared heavy-build gate, and retains receipts. Reuse a valid run
identity rather than constructing new evidence for an unchanged input set.
See [the qualifier](../Scripts/qualify_local_private_build.sh) for supported
release and installed-UI production options.

Ordinary qualification is offline. `--materialize-dependencies` is an
explicit exception surface, not an instruction to fetch packages casually.
A passing focused test does not mean the full or Release gate passed.

## Local installation and installed acceptance

**Building is not installing.** The installer has two distinct modes:

1. The ordinary Release installation path accepts a validated
   `--app-bundle /absolute/path/MacScope.app` plus, optionally, a
   `--signing-receipt`. It requires Release configuration and performs
   staged replacement and a closed-bundle comparison.
2. `--mode installed-acceptance` runs the separate governed transaction:
   begin, eight required envelopes, commit or rollback, followed by a
   final-candidate validator. It is never implicit.

For the second mode, `Scripts/install_local_private_build.sh --help` prints
its **complete** required invocation. The caller must supply the canonical
`--integration-ref`, qualification receipt/run ID/nonce, predecessor observation
digest, candidate artifact root, empty external work root, destination, signing
policy, and begin/compiler/report/commit/rollback timeouts. These are
candidate-specific values emitted or selected by the qualification process.
**Do not copy dummy values, manufacture envelopes, or run an installer merely
because a build succeeded.** Preserve the predecessor and its transaction
outputs until the final receipt is validated.

For an actual operation, use the matching qualified candidate and
[the installer source](../Scripts/install_local_private_build.sh).
An older successful receipt does not establish that the currently installed
application matches the latest repository commit.

## Explicit unsigned Debug alternative

[`build_unsigned_development.sh`](../Scripts/build_unsigned_development.sh)
takes `PREPARED_CHECKOUT PREPARED_DERIVED_DATA OUTPUT_ROOT` and is documented
in [UNSIGNED_DEVELOPMENT.md](UNSIGNED_DEVELOPMENT.md). It is strictly a
local, prepared, unsigned **Debug** workflow; it cannot substitute for
signed worker qualification, Release, CI, or installed acceptance.

## Change hygiene

- Keep dependency pins and generated build output separate. Use the
  [dependency workflow](dependencies/DependencyWorkflow.md) for intentional
  acquisitions or pin changes.
- Protect image/session identity, app-owned authorization, worker isolation,
  persistence contracts, and explicit degraded/error states.
- When documenting a capability, cite the product entry point and state which
  acceptance level has actually been observed. Source files alone do not
  prove behavior; date and bind the real test/qualification receipts.
- For the tracked scope, start
  with [the capability contract](../MacScope/PARITY_CONTRACT.md) and
  [the status snapshot](STATUS.md).
