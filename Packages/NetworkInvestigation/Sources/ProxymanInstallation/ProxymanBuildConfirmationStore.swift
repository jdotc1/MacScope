public protocol ProxymanBuildConfirmationStoring: Sendable {
    func isConfirmed(cdhash: String) async -> Bool
    func confirm(cdhash: String) async
}

public actor InMemoryProxymanBuildConfirmationStore: ProxymanBuildConfirmationStoring {
    private var confirmed: Set<String> = []

    public init() {}

    public func isConfirmed(cdhash: String) async -> Bool {
        confirmed.contains(cdhash)
    }

    public func confirm(cdhash: String) async {
        confirmed.insert(cdhash)
    }
}
