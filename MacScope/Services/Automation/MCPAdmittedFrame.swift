import Foundation

// Item 1282. Authored, unrun. Admission is syntactic, not JSON-RPC authorization.
// The caller retains whitespace handling, validResponseID, receipt and fence logic.
struct MCPAdmittedFrame: Sendable {
    let value: Phase2ProductionJSONValue
    let byteCount: Int

    var originalID: Phase2ProductionJSONValue? { value.objectValue?["id"] }

    private init(value: Phase2ProductionJSONValue, byteCount: Int) {
        self.value = value
        self.byteCount = byteCount
    }

    static func limits(maximumBytes: Int) -> Phase2StrictJSONLimits {
        Phase2StrictJSONLimits(
            maximumBytes: maximumBytes,
            maximumDepth: 16,
            maximumTokens: 100_000,
            maximumMembersAndElements: 50_000
        )
    }

    static func admit(_ data: Data, maximumBytes: Int) throws -> Self {
        do {
            return Self(
                value: try Phase2StrictJSONParser().parse(
                    data, limits: limits(maximumBytes: maximumBytes)),
                byteCount: data.count
            )
        } catch {
            // The same public failure type as HeadlessJSON.decode.
            throw HeadlessJSONError.invalid
        }
    }

    func legacyValue() throws -> ScriptValue {
        // Requires the private-to-internal access row; do not duplicate conversion.
        try HeadlessJSON.convert(value)
    }
}
