import NEWFEATURESCore
import SwiftUI

/// Deliberately presentation-only. The host owns selection, source validation,
/// request cancellation and authorization. Add to the existing browser surface
/// only after integration tests; do not replace the current CallGraphModel.
struct NEWFEATURESSubsystemExplorerView: View {
    let path: NEWFEATURESPathReport?
    let batch: NEWFEATURESRecursiveReport?
    let isWorking: Bool
    let onFindPath: () -> Void
    let onAnalyzeSubsystem: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Button("Find call path", action: onFindPath)
                    .disabled(isWorking)
                Button("Analyze subsystem", action: onAnalyzeSubsystem)
                    .disabled(true)
            }
            if let path {
                Text("Call path: \(path.status.rawValue)")
                    .font(.headline)
                Text("\(path.visitedFunctions) functions inspected")
                if path.status == .found {
                    ForEach(Array(path.path.enumerated()), id: \.offset) { entry in
                        Text("\(entry.offset + 1). image \(entry.element.image.slot), 0x\(String(entry.element.address, radix: 16))")
                            .font(.system(.body, design: .monospaced))
                    }
                } else {
                    Text("No complete path established from the accepted call references.")
                }
            }
            if let batch {
                Text("Recursive analysis: \(batch.termination.rawValue)")
                    .font(.headline)
                Text("\(batch.acceptedNativeFunctionCount) complete native function results")
                ForEach(Array(batch.results.enumerated()), id: \.offset) { entry in
                    HStack {
                        Text("0x\(String(entry.element.function.address, radix: 16))")
                        Spacer()
                        Text(entry.element.outcome.rawValue)
                    }
                    .font(.system(.caption, design: .monospaced))
                }
                Text("Coverage is limited to the observed call graph and admitted source snapshot.")
                    .font(.caption)
            }
        }
    }
}
