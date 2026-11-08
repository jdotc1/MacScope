# Local patches

Upstream: https://github.com/mattt/eventsource at tag 1.6.0, commit bb4b61273b5a976bb571859c17f903ebc3439df1.

Manifest rewritten: removed the AsyncHTTPClient trait, the async-http-client and swift-nio dependencies, and the test target; platform list reduced to macOS 12. Removed Sources/EventSource/EventSource+AsyncHTTPClient.swift (compiled only under the AsyncHTTPClient trait). Remaining sources are unmodified; EventSource.swift keeps its inactive #if AsyncHTTPClient blocks.

Both the upstream copy and this tree were taken by `git clone --depth 1 --branch 1.6.0`; no upstream script was run. Any further change needs a new entry here.
