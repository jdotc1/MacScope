/// App-only bridge; retains the record for the call and adds no clocks, spans or logs.
final class NativeDecompilerFacetMemoObserver: AnalysisFacetMemoObserver {
    private let record: NativeDecompilerPhaseRecord

    init(record: NativeDecompilerPhaseRecord) {
        self.record = record
    }

    func recordFacetMemo(hit: Bool) {
        record.add(.facetMemoHits, hit ? 1 : 0)
        record.add(.facetMemoMisses, hit ? 0 : 1)
    }
}
