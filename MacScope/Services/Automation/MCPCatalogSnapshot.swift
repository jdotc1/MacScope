// Item 1282. Authored, unrun. The authoritative builder remains on the authority.
struct MCPCatalogSnapshot: Sendable, Equatable {
    let commands: [ScriptingCommandInfo]
    private let nameToIndex: [String: Int]
    let mutatingNames: Set<String>

    init(commands: [ScriptingCommandInfo]) {
        self.commands = commands
        var index: [String: Int] = [:]
        for (offset, command) in commands.enumerated() {
            if index[command.name] == nil { index[command.name] = offset }
        }
        nameToIndex = index
        // Preserve the session's all-occurrences filter, not the first-wins index.
        mutatingNames = Set(commands.filter(\.mutates).map(\.name))
    }

    static func capture(_ commands: [ScriptingCommandInfo]) -> Self {
        Self(commands: commands)
    }

    func command(named name: String) -> ScriptingCommandInfo? {
        guard let offset = nameToIndex[name] else { return nil }
        return commands[offset]
    }

    func mutates(_ name: String) -> Bool? { command(named: name)?.mutates }
}
