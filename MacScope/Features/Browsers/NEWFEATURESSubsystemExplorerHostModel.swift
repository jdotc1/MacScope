import NEWFEATURESCore
import SwiftUI

/// The view input the Subsystem Explorer renders. Pure data: no store, window or Dock.
struct NEWFEATURESSubsystemExplorerInput {
    let path: NEWFEATURESPathReport?
    let batch: NEWFEATURESRecursiveReport?
    let isWorking: Bool
}

/// Host-side logic for the "Subsystems" browser pane. The view is presentation-only; this
/// builds its input from an already admitted verified-call projection. Recursive analysis is
/// not wired, so `batch` is always nil and the Analyze action is never enabled.
enum NEWFEATURESSubsystemExplorerHostModel {
    static let paneTitle = "Subsystems"
    static let analyzeEnabled = false

    /// Nothing selected, nothing running. The pane opens in this state.
    static let idle = NEWFEATURESSubsystemExplorerInput(path: nil, batch: nil, isWorking: false)

    /// Runs the bounded verified-path search over a fixture or admitted projection graph.
    static func input(graph: NEWFEATURESGraphSnapshot, source: NEWFEATURESFunctionKey,
                      destination: NEWFEATURESFunctionKey,
                      budget: NEWFEATURESReadBudget) throws -> NEWFEATURESSubsystemExplorerInput {
        let report = try NEWFEATURESPathfinder.shortestVerifiedPath(
            from: source, to: destination, graph: graph, budget: budget,
            operation: NEWFEATURESGraphOperation(budget: budget))
        return NEWFEATURESSubsystemExplorerInput(path: report, batch: nil, isWorking: false)
    }
}

/// The pane shown by the Browsers sheet. Endpoint selection is not part of this slice, so
/// the find action has nothing to run and stays inert; the MCP read is the working surface.
struct NEWFEATURESSubsystemsBrowserView: View {
    var body: some View {
        let input = NEWFEATURESSubsystemExplorerHostModel.idle
        // isWorking is true so the find action is disabled until endpoint selection exists.
        NEWFEATURESSubsystemExplorerView(
            path: input.path, batch: input.batch, isWorking: true,
            onFindPath: {}, onAnalyzeSubsystem: {})
            .padding()
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            .accessibilityIdentifier("browsers.subsystems.view")
    }
}
