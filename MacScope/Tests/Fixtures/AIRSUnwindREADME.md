# Owned unwind audit fixtures

`AIRSUnwindLoops.dylib` is copied from AIRS `build/loop-evidence/supported-cfi/owned.dylib`, assembled from `fixtures/toolchain/loops.S`. Its saved oracle is `build/loop-evidence/supported-cfi/owned.audit.json`, model `arm64-bounded-loops-v28`.

`AIRSCFARegister.dylib` is copied from AIRS `build/cfa-register-evidence/owned.dylib`, assembled from `fixtures/toolchain/cfa-register.S`. Its saved oracle is `build/cfa-register-evidence/owned.audit.json`, model `arm64-bounded-cfa-register-v30`.

Both are the maintainer's owned, linked ARM64 fixtures. Tests inspect their bytes as data; they never load or execute these images. The loop fixture checks one natural loop and excludes calls inside that loop. Calls after loops retain synchronous call-site scope. The CFA fixture adds the bounded register-only CFA update.

The accompanying `AIRSUnwindLoops.S` and `AIRSCFARegister.S` are verbatim copies of AIRS `fixtures/toolchain/loops.S` and `fixtures/toolchain/cfa-register.S`, respectively. Fixture governance exempts only these exact binary/source pairs while the sources are regular files, not symlinks. The saved binaries are reused without rebuilding.

The first-audit identities below are reused from those saved reports, without recomputing provenance hashes or rebuilding the fixtures:

| Fixture | Slice size | UUID | Slice and container SHA-256 |
| --- | ---: | --- | --- |
| AIRSUnwindLoops.dylib | 17480 | 9f20e834-0ec1-31f0-aa9c-6153bbab70c6 | e4957a86d91eb3722f975b48aee12bace61211e7a737a56a9249dad9b598d8d1 |
| AIRSCFARegister.dylib | 16904 | eada8dec-ff01-3904-b0b8-2365df568169 | e3ef10557917add67fd62dcebc9ea7f0893339a362325e3511ed4c5f7e9e9a93 |

Both have slice offset zero, preferred base zero, ordinary arm64 subtype zero, and dylib file type. `UnwindAuditOracleTests` projects parser-derived sections, symbols and function starts into `LoadedBinary` and supplies these existing identity receipts. This deliberately avoids repeating provenance hashing in the production file loader. Expected function ranges are assertions only; they are never audit inputs.
