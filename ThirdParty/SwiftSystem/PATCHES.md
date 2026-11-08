# Local patches

Upstream: https://github.com/apple/swift-system at tag 1.8.1, commit 869129b7bf4ecc57b97d0193ad29690ca2134750.

Manifest only: removed the SystemTests and MemberImportVisibility test targets, the test excludes and the CMakeLists.txt excludes (CMake files are not vendored). No Swift source modified.

Both the upstream copy and this tree were taken by `git clone --depth 1 --branch 1.8.1`; no upstream script was run. Any further change needs a new entry here.
