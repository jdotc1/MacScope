import Foundation
import Observation
import SwiftUI

struct NativeFunctionArgumentDraft: Identifiable {
    enum PointerInput: String, CaseIterable { case null = "NULL", string = "C string", buffer = "Byte buffer", image = "Image global" }
    let id = UUID()
    var type: NativeFunctionScalarType
    var integer = "0"
    var pointerInput: PointerInput = .null
    var string = ""
    var bufferSize = 32
    var hexBytes = ""
    var globalAddress: UInt64?
}

@MainActor @Observable
final class NativeFunctionRunModel {
    private(set) var prepared: NativePreparedFunction?
    private(set) var result: NativeFunctionCallResult?
    private(set) var error: String?
    private(set) var preparing = false
    private(set) var running = false
    private(set) var signatureEdited = false
    var returnType: NativeFunctionScalarType = .uint64
    var arguments: [NativeFunctionArgumentDraft] = []
    var signatureConfirmed = false
    var timeoutSeconds = 2.0
    var selectedGlobals: Set<UInt64> = []
    var globalSizes: [UInt64: Int] = [:]
    @ObservationIgnored private var generation = UUID()
    @ObservationIgnored private var documentID: UUID?
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var requestID: UUID?
    @ObservationIgnored private var coordinator: NativeExecutionCoordinator?

    var ineligibleReason: String? {
        guard let prepared else { return nil }
        if case .ineligible(let reason) = prepared.evidence { return reason }
        return nil
    }
    var provenanceLabel: String {
        guard !signatureEdited, let prepared, case .authoritative = prepared.evidence else { return "User override" }
        return "DWARF · authoritative"
    }
    var canRun: Bool {
        prepared != nil && !preparing && !running && signatureConfirmed && ineligibleReason == nil
            && coordinator != nil && result?.cleanupConfirmed != false
    }

    func prepare(binary: BinaryImage, function: FunctionSummary, analysis: ImageAnalysis,
                 documentID: UUID, coordinator: NativeExecutionCoordinator?) async {
        let previous = self.documentID == documentID ? prepared : nil
        let previousResult = result
        cancel()
        let revision = UUID()
        generation = revision
        running = false; task = nil; requestID = nil
        self.documentID = documentID
        self.coordinator = coordinator
        prepared = nil; result = nil; error = nil; preparing = true
        let preparation = Task.detached(priority: .userInitiated) {
            try NativeFunctionPreparation.prepare(binary: binary, function: function, analysis: analysis)
        }
        do {
            let value = try await withTaskCancellationHandler { try await preparation.value } onCancel: { preparation.cancel() }
            guard generation == revision, !Task.isCancelled else { return }
            prepared = value
            if let previous, previous.image.binaryID == value.image.binaryID,
               previous.function.startAddress == value.function.startAddress,
               previous.image.selectedSliceSHA256 == value.image.selectedSliceSHA256,
               previous.image.fileStamp == value.image.fileStamp {
                result = previousResult
            }
            signatureEdited = false
            selectedGlobals = []; globalSizes = [:]
            switch value.evidence {
            case .authoritative(let prototype):
                returnType = prototype.returnType
                arguments = prototype.parameterTypes.map { NativeFunctionArgumentDraft(type: $0) }
                signatureConfirmed = true
            case .needsExplicitSignature:
                returnType = .uint64; arguments = []; signatureConfirmed = false
            case .ineligible:
                returnType = .void; arguments = []; signatureConfirmed = false
            }
        } catch {
            if generation == revision, !Task.isCancelled { self.error = error.localizedDescription }
        }
        if generation == revision { preparing = false }
    }

    func signatureChanged() { signatureEdited = true; signatureConfirmed = false }
    func addArgument() {
        guard arguments.count < 16 else { return }
        arguments.append(.init(type: .uint64)); signatureChanged()
    }
    func removeArgument(id: UUID) { arguments.removeAll { $0.id == id }; signatureChanged() }

    func run() {
        guard canRun, let prepared, let coordinator else { return }
        do {
            let provenance: NativeFunctionPrototype.Provenance = signatureEdited ? .userOverride : {
                if case .authoritative = prepared.evidence { return .authoritativeDWARF }
                return .userOverride
            }()
            let prototype = try NativeFunctionPrototype(returnType: returnType, parameterTypes: arguments.map(\.type), provenance: provenance)
            let values = try arguments.map { try argument($0, prepared: prepared) }
            let globals = prepared.globals.filter { selectedGlobals.contains($0.staticAddress) }.map {
                NativeExecutionObservedGlobal(name: $0.name, staticAddress: $0.staticAddress,
                    byteCount: globalSizes[$0.staticAddress] ?? $0.byteCount)
            }
            let request = try NativeFunctionCallRequest(image: prepared.image, staticFunctionAddress: prepared.function.startAddress,
                prototype: prototype, arguments: values, globals: globals, timeoutSeconds: timeoutSeconds)
            requestID = request.id
            running = true; error = nil; result = nil
            let revision = generation
            task = Task {
                defer { if generation == revision { running = false; task = nil; requestID = nil } }
                do {
                    let value = try await coordinator.run(request)
                    guard generation == revision else { return }
                    result = value
                } catch {
                    guard generation == revision else { return }
                    self.error = error.localizedDescription
                }
            }
        } catch { self.error = error.localizedDescription }
    }

    func cancel() {
        task?.cancel()
        if let requestID, let coordinator { Task { await coordinator.cancel(requestID: requestID) } }
    }

    func resetForDocumentChange() {
        cancel(); generation = UUID(); prepared = nil; result = nil; error = nil
        preparing = false; running = false; documentID = nil; requestID = nil; task = nil
    }

    private func argument(_ draft: NativeFunctionArgumentDraft, prepared: NativePreparedFunction) throws -> NativeFunctionArgument {
        guard draft.type == .pointer else { return .integer(try draft.type.parseInteger(draft.integer)) }
        switch draft.pointerInput {
        case .null: return .nullPointer
        case .string:
            let bytes = Data(draft.string.utf8)
            guard !bytes.contains(0), bytes.count < 65_536 else {
                throw NativeExecutionError.invalidRequest("C strings must fit within 65,536 bytes including their terminator. Use a byte buffer for embedded NUL bytes.")
            }
            return .buffer(bytes + Data([0]))
        case .buffer:
            guard (1...65_536).contains(draft.bufferSize) else {
                throw NativeExecutionError.invalidRequest("Buffer size must be between 1 and 65,536 bytes.")
            }
            let text = draft.hexBytes.filter { !$0.isWhitespace }
            guard text.utf8.count <= 131_072, text.utf8.count.isMultiple(of: 2),
                  text.utf8.allSatisfy({ (48...57).contains($0) || (65...70).contains($0) || (97...102).contains($0) }) else {
                throw NativeExecutionError.invalidRequest("Initial buffer bytes must be complete hexadecimal pairs.")
            }
            let ascii = Array(text.utf8)
            var bytes = Data()
            for index in stride(from: 0, to: ascii.count, by: 2) {
                let pair = String(decoding: ascii[index..<(index + 2)], as: UTF8.self)
                guard let byte = UInt8(pair, radix: 16) else { throw NativeExecutionError.invalidRequest("Invalid buffer bytes.") }
                bytes.append(byte)
            }
            guard bytes.count <= draft.bufferSize else { throw NativeExecutionError.invalidRequest("Initial bytes exceed the selected buffer size.") }
            bytes.append(Data(repeating: 0, count: draft.bufferSize - bytes.count))
            return .buffer(bytes)
        case .image:
            guard let address = draft.globalAddress, let global = prepared.globals.first(where: { $0.staticAddress == address }) else {
                throw NativeExecutionError.invalidRequest("Choose an image global for the pointer parameter.")
            }
            return .imageRegion(.init(name: global.name, staticAddress: address,
                byteCount: globalSizes[address] ?? global.byteCount))
        }
    }
}

@MainActor
struct RunFunctionAction: View {
    @ObservedObject var store: WorkspaceStore
    let function: FunctionSummary?
    @Environment(\.debuggerRuntimeAuthorities) private var authorities
    @State private var presented = false
    @State private var model = NativeFunctionRunModel()

    var body: some View {
        Button("Run Function…", systemImage: "play.circle") { presented = true }
            .disabled(function == nil || store.focusedBinary == nil)
            .help("Call this function in a fresh confined process")
            .sheet(isPresented: $presented, onDismiss: { model.cancel() }) {
                RunFunctionSheet(model: model)
                    .task {
                        guard let binary = store.focusedBinary, let analysis = store.focusedAnalysis, let function else { return }
                        await model.prepare(binary: binary, function: function, analysis: analysis,
                            documentID: store.documentInstallationID, coordinator: authorities?.nativeExecutionCoordinator)
                    }
            }
            .onChange(of: store.documentInstallationID) { _, _ in presented = false; model.resetForDocumentChange() }
            .onDisappear { model.cancel() }
    }
}

@MainActor
struct RunFunctionSheet: View {
    @Bindable var model: NativeFunctionRunModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text(model.prepared.map { "Run \($0.function.name)" } ?? "Run Function").font(.title2.weight(.semibold))
                    Text("Fresh confined process · ARM64 native").foregroundStyle(.secondary)
                }
                Spacer()
                Button("Close") { dismiss() }.disabled(model.running).keyboardShortcut(.cancelAction)
            }
            Text("Each run allows loader initialization and constructors, then calls the selected function before the program’s main body. Other threads remain stopped during the call.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if model.preparing { ProgressView("Preparing function…") }
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    if let prepared = model.prepared {
                        GroupBox("Prototype") {
                            VStack(alignment: .leading, spacing: 10) {
                                HStack {
                                    Picker("Returns", selection: Binding(get: { model.returnType }, set: { model.returnType = $0; model.signatureChanged() })) {
                                        ForEach(NativeFunctionScalarType.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                                    }.frame(maxWidth: 300)
                                    Spacer(); Text(model.provenanceLabel).foregroundStyle(.secondary)
                                }
                                if case .needsExplicitSignature(let reason) = prepared.evidence {
                                    Text(reason).font(.callout).foregroundStyle(.secondary)
                                }
                                if let reason = model.ineligibleReason { Text(reason).foregroundStyle(.red) }
                                ForEach($model.arguments) { $argument in
                                    NativeFunctionArgumentRow(argument: $argument, globals: prepared.globals,
                                        changed: model.signatureChanged, remove: { model.removeArgument(id: argument.id) })
                                }
                                Button("Add parameter", systemImage: "plus") { model.addArgument() }
                                    .disabled(model.arguments.count >= 16 || model.ineligibleReason != nil)
                                Toggle("I confirm this signature uses the C calling convention.", isOn: $model.signatureConfirmed)
                            }.padding(8)
                        }.disabled(model.running || model.ineligibleReason != nil)
                        if !prepared.globals.isEmpty {
                            DisclosureGroup("Observed globals (\(model.selectedGlobals.count) selected)") {
                                ScrollView {
                                    LazyVStack(alignment: .leading) {
                                        ForEach(prepared.globals) { global in
                                            HStack {
                                                Toggle(global.name, isOn: Binding(get: { model.selectedGlobals.contains(global.staticAddress) }, set: { value in
                                                    if value { model.selectedGlobals.insert(global.staticAddress) }
                                                    else { model.selectedGlobals.remove(global.staticAddress) }
                                                }))
                                                TextField("Bytes", value: Binding(get: { model.globalSizes[global.staticAddress] ?? global.byteCount },
                                                    set: { model.globalSizes[global.staticAddress] = $0 }), format: .number)
                                                    .frame(width: 80)
                                            }
                                        }
                                    }.padding(8)
                                }.frame(maxHeight: 160)
                            }.disabled(model.running)
                        }
                        HStack {
                            Text("Time limit")
                            TextField("Seconds", value: $model.timeoutSeconds, format: .number).frame(width: 70)
                            Text("seconds (0.1–10)").foregroundStyle(.secondary)
                        }.disabled(model.running)
                    }
                    if let error = model.error { Text(error).foregroundStyle(.red).textSelection(.enabled) }
                    if let result = model.result { NativeExecutionResultView(result: result) }
                }
            }
            HStack {
                Text("At most 16 observed regions and 64 KiB per run.").font(.caption).foregroundStyle(.secondary)
                Spacer()
                if model.running {
                    ProgressView().controlSize(.small)
                    Button("Cancel") { model.cancel() }
                } else {
                    Button("Run Function", systemImage: "play.fill") { model.run() }
                        .buttonStyle(.borderedProminent).disabled(!model.canRun).keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(24).frame(minWidth: 680, idealWidth: 760, minHeight: 560, idealHeight: 680)
        .interactiveDismissDisabled(model.running)
    }
}

private struct NativeFunctionArgumentRow: View {
    @Binding var argument: NativeFunctionArgumentDraft
    let globals: [NativeExecutionObservedGlobal]
    let changed: () -> Void
    let remove: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Picker("Parameter type", selection: Binding(get: { argument.type }, set: { argument.type = $0; changed() })) {
                    ForEach(NativeFunctionScalarType.allCases.filter { $0 != .void }, id: \.self) { Text($0.rawValue).tag($0) }
                }.frame(width: 200)
                if argument.type != .pointer { TextField("Decimal or hexadecimal", text: $argument.integer) }
                Spacer()
                Button("Remove", systemImage: "minus.circle", action: remove).labelStyle(.iconOnly)
            }
            if argument.type == .pointer {
                Picker("Pointer input", selection: $argument.pointerInput) {
                    ForEach(NativeFunctionArgumentDraft.PointerInput.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }.pickerStyle(.segmented)
                switch argument.pointerInput {
                case .null: EmptyView()
                case .string: TextField("UTF-8 text; a NUL terminator is added", text: $argument.string)
                case .buffer:
                    HStack {
                        TextField("Size in bytes", value: $argument.bufferSize, format: .number).frame(width: 120)
                        TextField("Initial hex bytes (empty means zero-filled)", text: $argument.hexBytes)
                    }
                case .image:
                    Picker("Global", selection: $argument.globalAddress) {
                        Text("Choose a global").tag(Optional<UInt64>.none)
                        ForEach(globals) { Text($0.name).tag(Optional($0.staticAddress)) }
                    }
                }
            }
        }.padding(.vertical, 4)
    }
}

struct NativeExecutionResultView: View {
    let result: NativeFunctionCallResult

    var body: some View {
        GroupBox("Result · \(result.outcome.rawValue)") {
            VStack(alignment: .leading, spacing: 10) {
                if let value = result.returnValue {
                    Text("Returned \(value.type.rawValue)").fontWeight(.semibold)
                    Text(value.hexadecimal).monospaced().textSelection(.enabled)
                    if let decimal = value.decimal { Text(decimal).textSelection(.enabled) }
                } else if result.outcome == .completed { Text("Returned void") }
                if let address = result.runtimeFunctionAddress {
                    Text("Runtime function: 0x\(String(address, radix: 16))").font(.caption).monospaced()
                    Text("Context: loader and constructors completed; stopped before main.").font(.caption).foregroundStyle(.secondary)
                }
                if let pc = result.faultProgramCounter { Text("Fault PC: 0x\(String(pc, radix: 16))").monospaced() }
                ForEach(Array(result.diagnostics.enumerated()), id: \.offset) { _, text in Text(text).foregroundStyle(.red).textSelection(.enabled) }
                if !result.cleanupConfirmed { Text("Process cleanup could not be confirmed. Further calls are blocked.").foregroundStyle(.red) }
                if !result.memory.isEmpty {
                    Text("Observed memory changes").fontWeight(.semibold)
                    Text("Snapshots cover the selected regions. Writes that restore the original bytes are not visible.").font(.caption).foregroundStyle(.secondary)
                    ForEach(result.memory) { region in
                        DisclosureGroup("\(region.label) · \(region.changedRanges.reduce(0) { $0 + $1.count }) changed bytes") {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("Address: 0x\(String(region.runtimeAddress, radix: 16))").monospaced()
                                Text("Before").fontWeight(.semibold)
                                Text(region.before.map(hex) ?? "Unavailable").monospaced().textSelection(.enabled)
                                Text("After").fontWeight(.semibold)
                                Text(region.after.map(hex) ?? "Unavailable").monospaced().textSelection(.enabled)
                                if let diagnostic = region.diagnostic { Text(diagnostic).foregroundStyle(.red) }
                                if let after = region.after, let text = String(data: Data(after.prefix { $0 != 0 }), encoding: .utf8), !text.isEmpty {
                                    Text("UTF-8: \(text)").textSelection(.enabled)
                                }
                            }.font(.caption).padding(8)
                        }
                    }
                }
            }.frame(maxWidth: .infinity, alignment: .leading).padding(8)
        }
    }

    private func hex(_ bytes: Data) -> String { bytes.map { String(format: "%02x", $0) }.joined(separator: " ") }
}
