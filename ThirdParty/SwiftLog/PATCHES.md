# Local patches

Upstream: https://github.com/apple/swift-log at tag 1.17.0, commit e3da04078777e6a1b72ce19981fbd6539b0847d8.

Manifest only: removed the LoggingTests and InMemoryLoggingTests targets and the CMakeLists.txt excludes (CMake files and docc catalogs are not vendored). No Swift source modified.

Both the upstream copy and this tree were taken by `git clone --depth 1 --branch 1.17.0`; no upstream script was run. Any further change needs a new entry here.
