# Local patches

Upstream: https://github.com/modelcontextprotocol/swift-sdk at tag 0.12.1, commit a0ae212ebf6eab5f754c3129608bc5557637e605.

Manifest rewritten: removed products mcp-everything-server and mcp-everything-client, targets MCPConformanceServer, MCPConformanceClient and MCPTests, and dependencies swift-nio and swift-docc-plugin. Removed Sources/MCPConformance. Dependencies on swift-system, swift-log and eventsource now use local paths. Platform list reduced to macOS 13. No Swift source under Sources/MCP is modified.

Both the upstream copy and this tree were taken by `git clone --depth 1 --branch 0.12.1`; no upstream script was run. Any further change needs a new entry here.
