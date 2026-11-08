import SwiftUI
import LumenUI

enum RegenerationAccessibilityIdentifiers {
    static let card = "regeneration.card"
    static let chooseFolder = "regeneration.chooseFolder"
    static let files = "regeneration.files"
    static let states = "regeneration.states"
    static let languageTable = "regeneration.languageTable"
    static let resources = "regeneration.resources"
    static let dependencies = "regeneration.dependencies"
    static let structure = "regeneration.structure"
    static let findings = "regeneration.findings"
    static let functionList = "regeneration.function.list"
    static let functionSearch = "regeneration.function.search"
    static let functionState = "regeneration.function.state"
    static let functionLanguage = "regeneration.function.language"
    static let functionPage = "regeneration.function.page"
}

/// Presentation text for the regeneration card, derived from the projection so the same strings
/// can be asserted without a view.
enum RegenerationProgressText {
    static let caveat = "Compiles means compiles, not correct. Accepted comes only from the Reconstruction pipeline."

    static func title(_ state: RegenerationFunctionState) -> String {
        switch state {
        case .stub: "Stub"
        case .external: "External"
        case .filled: "Filled"
        case .compiles: "Compiles"
        case .accepted: "Accepted"
        }
    }

    static func title(_ language: RegenerationLanguage) -> String {
        switch language {
        case .objc: "Objective-C"
        case .swift: "Swift"
        case .c: "C"
        case .unknown: "Unknown"
        }
    }

    static func title(_ confidence: RegenerationDependencyConfidence) -> String { confidence.rawValue.capitalized }

    static func fileLine(_ file: RegenerationExportFile) -> String { "\(file.name): \(file.state.summary)" }

    static func equivalenceLine(_ result: RegenerationResourceEquivalence) -> String {
        switch result {
        case .equal: "Equal"
        case .different: "Different"
        case .notChecked: "Converter ran, not checked"
        }
    }

    static let notAttempted = "Not attempted"

    static func percent(_ score: Double) -> String { String(format: "%.1f%%", score * 100) }

    static func dimensionLine(_ row: RegenerationDimensionResult) -> String {
        if row.status == .notMeasured { return "\(row.dimension.rawValue): not measured, \(row.notMeasuredReason ?? "no reason given")" }
        let score = row.score.map(percent) ?? "no score"
        return "\(row.dimension.rawValue): \(row.matched) matched, \(row.missingInRebuilt) missing, "
            + "\(row.extraInRebuilt) extra, \(row.differing) differing, \(score)"
    }

    static func stateSummary(_ projection: RegenerationProgressProjection) -> String {
        RegenerationFunctionState.allCases
            .map { "\(projection.stateCounts[$0] ?? 0) \(title($0).lowercased())" }
            .joined(separator: ", ")
    }
}

/// Regeneration progress for one export folder, inside the Reconstruction dashboard. Function
/// navigation is offered only when the host reports a matching image identity.
struct RegenerationProgressCard: View {
    let projection: RegenerationProgressProjection
    var onChooseExportFolder: (() -> Void)? = nil
    var onNavigateToAddress: ((String) -> Void)? = nil

    @State private var stateFilter: RegenerationFunctionState?
    @State private var languageFilter: RegenerationLanguage?
    @State private var search = ""
    @State private var pageIndex = 0

    var body: some View {
        ReconstructionSummaryCard(title: "Regeneration", systemImage: "arrow.triangle.2.circlepath") {
            VStack(alignment: .leading, spacing: Lumen.Space.s6) {
                chooser
                Text(RegenerationProgressText.caveat)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                filesSection
                if let message = projection.emptyMessage {
                    Text(message).foregroundStyle(.secondary)
                }
                if !projection.functions.isEmpty {
                    statesSection
                    languageSection
                }
                if !projection.resources.isEmpty { resourcesSection }
                if !projection.dependencyGroups.isEmpty { dependenciesSection }
                if !projection.dimensions.isEmpty { structureSection }
                if !projection.findings.isEmpty { findingsSection }
                if !projection.functions.isEmpty { functionList }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier(RegenerationAccessibilityIdentifiers.card)
    }

    private var chooser: some View {
        HStack {
            if let appName = projection.appName {
                Text(appName).font(.subheadline.weight(.semibold))
            }
            Spacer()
            Button("Choose Export Folder…") { onChooseExportFolder?() }
                .disabled(onChooseExportFolder == nil)
                .accessibilityIdentifier(RegenerationAccessibilityIdentifiers.chooseFolder)
        }
    }

    private var filesSection: some View {
        VStack(alignment: .leading, spacing: Lumen.Space.s2) {
            ForEach(projection.files, id: \.name) { file in
                Text(verbatim: RegenerationProgressText.fileLine(file))
                    .font(.caption)
                    .foregroundStyle(file.state.isLoaded || file.state == .notProducedYet ? .secondary : .primary)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityIdentifier(RegenerationAccessibilityIdentifiers.files)
        .accessibilityLabel("Export files")
        .accessibilityValue(projection.files.map(RegenerationProgressText.fileLine).joined(separator: "; "))
    }

    private var statesSection: some View {
        VStack(alignment: .leading, spacing: Lumen.Space.s5) {
            stateBar
            ReconstructionMetricGrid(metrics: RegenerationFunctionState.allCases.map {
                .init(title: RegenerationProgressText.title($0), value: projection.stateCounts[$0] ?? 0)
            })
        }
        .accessibilityElement(children: .ignore)
        .accessibilityIdentifier(RegenerationAccessibilityIdentifiers.states)
        .accessibilityLabel("Function states")
        .accessibilityValue("\(projection.functions.count) functions: \(RegenerationProgressText.stateSummary(projection))")
    }

    private var stateBar: some View {
        GeometryReader { proxy in
            HStack(spacing: 1) {
                ForEach(RegenerationFunctionState.allCases, id: \.self) { state in
                    let count = projection.stateCounts[state] ?? 0
                    if count > 0 {
                        Rectangle()
                            .fill(color(for: state))
                            .frame(width: max(2, proxy.size.width * CGFloat(count) / CGFloat(projection.functions.count)))
                    }
                }
            }
        }
        .frame(height: 8)
        .clipShape(RoundedRectangle(cornerRadius: 4))
    }

    private func color(for state: RegenerationFunctionState) -> Color {
        switch state {
        case .stub: .gray
        case .external: .purple
        case .filled: .blue
        case .compiles: .orange
        case .accepted: .green
        }
    }

    private var languageSection: some View {
        let table = RegenerationFunctionState.allCases.map { state in
            RegenerationLanguage.allCases.map { projection.count(state: state, language: $0) }
        }
        return Grid(alignment: .leading, horizontalSpacing: Lumen.Space.s6, verticalSpacing: Lumen.Space.s2) {
            GridRow {
                Text("")
                ForEach(RegenerationLanguage.allCases, id: \.self) { Text(RegenerationProgressText.title($0)).font(.caption) }
            }
            ForEach(Array(RegenerationFunctionState.allCases.enumerated()), id: \.offset) { row, state in
                GridRow {
                    Text(RegenerationProgressText.title(state)).font(.caption)
                    ForEach(Array(table[row].enumerated()), id: \.offset) { _, value in
                        Text(value, format: .number).font(.caption.monospacedDigit())
                    }
                }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityIdentifier(RegenerationAccessibilityIdentifiers.languageTable)
        .accessibilityLabel("Functions by state and language")
        .accessibilityValue(languageAccessibilityValue(table))
    }

    private func languageAccessibilityValue(_ table: [[Int]]) -> String {
        zip(RegenerationFunctionState.allCases, table).map { state, row in
            RegenerationProgressText.title(state) + ": " + zip(RegenerationLanguage.allCases, row)
                .map { "\($1) \(RegenerationProgressText.title($0))" }.joined(separator: ", ")
        }.joined(separator: "; ")
    }

    private var resourcesSection: some View {
        let lines = resourceLines
        return VStack(alignment: .leading, spacing: Lumen.Space.s5) {
            Text("Resources").font(.subheadline.weight(.semibold))
            ReconstructionMetricGrid(metrics: RegenerationResourceStatus.allCases.map {
                .init(title: $0.rawValue.capitalized, value: projection.resourceStatusCounts[$0] ?? 0)
            })
            ReconstructionMetricGrid(metrics: lines.map { .init(title: $0.0, value: $0.1) })
        }
        .accessibilityElement(children: .ignore)
        .accessibilityIdentifier(RegenerationAccessibilityIdentifiers.resources)
        .accessibilityLabel("Resources")
        .accessibilityValue(lines.map { "\($0.0) \($0.1)" }.joined(separator: ", "))
    }

    private var resourceLines: [(String, Int)] {
        [(RegenerationProgressText.notAttempted, projection.notAttemptedResourceCount)]
            + RegenerationResourceEquivalence.allCases.map {
                (RegenerationProgressText.equivalenceLine($0), projection.resourceEquivalenceCounts[$0] ?? 0)
            }
    }

    private var dependenciesSection: some View {
        VStack(alignment: .leading, spacing: Lumen.Space.s2) {
            Text("Dependencies").font(.subheadline.weight(.semibold))
            ForEach(projection.dependencyGroups, id: \.confidence) { group in
                Text(verbatim: dependencyLine(group)).font(.caption)
                ForEach(group.dependencies, id: \.id) { dependency in
                    Text(verbatim: "\(dependency.name) (\(dependency.kind.rawValue)), claims \(dependency.claimedFunctionCount)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .padding(.leading, Lumen.Space.s5)
                }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityIdentifier(RegenerationAccessibilityIdentifiers.dependencies)
        .accessibilityLabel("Dependencies")
        .accessibilityValue(projection.dependencyGroups.map(dependencyLine).joined(separator: "; "))
    }

    private func dependencyLine(_ group: RegenerationDependencyGroup) -> String {
        "\(RegenerationProgressText.title(group.confidence)): \(group.dependencies.count) dependencies, "
            + "\(group.claimedFunctionCount) functions claimed"
    }

    private var structureSection: some View {
        VStack(alignment: .leading, spacing: Lumen.Space.s2) {
            Text("Rebuilt binary structure").font(.subheadline.weight(.semibold))
            Grid(alignment: .leading, horizontalSpacing: Lumen.Space.s5, verticalSpacing: Lumen.Space.s2) {
                GridRow {
                    ForEach(["Dimension", "Matched", "Missing", "Extra", "Differing", "Score"], id: \.self) {
                        Text($0).font(.caption.weight(.semibold))
                    }
                }
                ForEach(projection.dimensions, id: \.dimension) { row in
                    GridRow {
                        Text(row.dimension.rawValue)
                        if row.status == .notMeasured {
                            Text("Not measured: \(row.notMeasuredReason ?? "no reason given")")
                                .gridCellColumns(5)
                                .foregroundStyle(.secondary)
                        } else {
                            Text(row.matched, format: .number)
                            Text(row.missingInRebuilt, format: .number)
                            Text(row.extraInRebuilt, format: .number)
                            Text(row.differing, format: .number)
                            Text(row.score.map(RegenerationProgressText.percent) ?? "n/a")
                        }
                    }
                    .font(.caption.monospacedDigit())
                }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityIdentifier(RegenerationAccessibilityIdentifiers.structure)
        .accessibilityLabel("Rebuilt binary structure")
        .accessibilityValue(projection.dimensions.map(RegenerationProgressText.dimensionLine).joined(separator: "; "))
    }

    private var findingsSection: some View {
        VStack(alignment: .leading, spacing: Lumen.Space.s2) {
            Text("Consistency findings").font(.subheadline.weight(.semibold))
            ForEach(Array(projection.findings.prefix(50).enumerated()), id: \.offset) { _, finding in
                Text(verbatim: "\(finding.code): \(finding.message)").font(.caption)
            }
            if projection.findings.count > 50 {
                Text("\(projection.findings.count - 50) more findings not shown").font(.caption).foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityIdentifier(RegenerationAccessibilityIdentifiers.findings)
        .accessibilityLabel("Consistency findings")
        .accessibilityValue("\(projection.findings.count) findings")
    }

    // MARK: Function list

    private var functionList: some View {
        let page = projection.page(pageIndex: pageIndex, state: stateFilter, language: languageFilter, search: search)
        return VStack(alignment: .leading, spacing: Lumen.Space.s5) {
            Text("Functions").font(.subheadline.weight(.semibold))
            HStack {
                Picker("State", selection: $stateFilter) {
                    Text("All states").tag(RegenerationFunctionState?.none)
                    ForEach(RegenerationFunctionState.allCases, id: \.self) {
                        Text(RegenerationProgressText.title($0)).tag(RegenerationFunctionState?.some($0))
                    }
                }
                .accessibilityIdentifier(RegenerationAccessibilityIdentifiers.functionState)
                Picker("Language", selection: $languageFilter) {
                    Text("All languages").tag(RegenerationLanguage?.none)
                    ForEach(RegenerationLanguage.allCases, id: \.self) {
                        Text(RegenerationProgressText.title($0)).tag(RegenerationLanguage?.some($0))
                    }
                }
                .accessibilityIdentifier(RegenerationAccessibilityIdentifiers.functionLanguage)
                TextField("Search name or address", text: $search)
                    .textFieldStyle(.roundedBorder)
                    .accessibilityIdentifier(RegenerationAccessibilityIdentifiers.functionSearch)
            }
            .onChange(of: stateFilter) { pageIndex = 0 }
            .onChange(of: languageFilter) { pageIndex = 0 }
            .onChange(of: search) { pageIndex = 0 }
            if onNavigateToAddress != nil, let first = projection.functions.first, !projection.navigation(for: first).canNavigate {
                Text(projection.navigation(for: first).reason).font(.caption).foregroundStyle(.secondary)
            }
            LazyVStack(alignment: .leading, spacing: Lumen.Space.s2) {
                ForEach(page.functions) { function in functionRow(function) }
            }
            HStack {
                Button("Previous") { pageIndex = max(0, page.pageIndex - 1) }
                    .disabled(page.pageIndex == 0)
                Text("Page \(page.pageIndex + 1) of \(page.pageCount), \(page.totalCount) functions")
                    .font(.caption.monospacedDigit())
                Button("Next") { pageIndex = min(page.pageCount - 1, page.pageIndex + 1) }
                    .disabled(page.pageIndex >= page.pageCount - 1)
            }
            .accessibilityElement(children: .contain)
            .accessibilityIdentifier(RegenerationAccessibilityIdentifiers.functionPage)
            .accessibilityValue("Page \(page.pageIndex + 1) of \(page.pageCount), \(page.totalCount) functions")
        }
        .accessibilityIdentifier(RegenerationAccessibilityIdentifiers.functionList)
    }

    @ViewBuilder
    private func functionRow(_ function: RegenerationProgressFunction) -> some View {
        let navigation = projection.navigation(for: function)
        let label = "\(function.name ?? "(unnamed)"), \(function.imageQualifiedAddress), "
            + "\(RegenerationProgressText.title(function.state)), \(RegenerationProgressText.title(function.language))"
        if let onNavigateToAddress, navigation.canNavigate {
            Button { onNavigateToAddress(function.imageQualifiedAddress) } label: { rowContent(function) }
                .buttonStyle(.plain)
                .accessibilityLabel(label)
        } else {
            rowContent(function)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel(label)
                .accessibilityValue(onNavigateToAddress == nil ? "" : navigation.reason)
        }
    }

    private func rowContent(_ function: RegenerationProgressFunction) -> some View {
        HStack {
            Text(function.name ?? "(unnamed)")
            Spacer()
            Text(RegenerationProgressText.title(function.state)).foregroundStyle(.secondary)
            Text(function.imageQualifiedAddress).font(.caption.monospaced()).foregroundStyle(.secondary)
        }
        .font(.caption)
        .contentShape(Rectangle())
    }
}
