import Foundation

enum NativeExecutionError: Error, LocalizedError, Equatable, Sendable {
    case unavailable(String)
    case invalidRequest(String)
    case invalidResponse(String)
    case busy
    case cleanupUnresolved

    var errorDescription: String? {
        switch self {
        case .unavailable(let message), .invalidRequest(let message), .invalidResponse(let message): message
        case .busy: "Another function call is still running."
        case .cleanupUnresolved: "The previous execution process could not be confirmed closed. Restart MacScope before another call."
        }
    }
}

struct NativeExecutionImageRegion: Hashable, Sendable {
    let name: String
    let staticAddress: UInt64
    let byteCount: UInt64
    let permissions: UInt8

    func contains(_ address: UInt64, count: UInt64 = 1) -> Bool {
        count > 0 && address >= staticAddress && byteCount >= count
            && address - staticAddress <= byteCount - count
    }
}

struct NativeExecutionImage: Sendable {
    let binaryID: UUID
    let canonicalPath: String
    let uuid: UUID
    let selectedSliceSHA256: String
    let selectedSliceOffset: UInt64
    let selectedSliceByteCount: UInt64
    let entryAddress: UInt64
    let regions: [NativeExecutionImageRegion]
    let fileStamp: NativeExecutionFileStamp
}

struct NativeExecutionObservedGlobal: Hashable, Sendable, Identifiable {
    let name: String
    let staticAddress: UInt64
    let byteCount: Int
    var id: UInt64 { staticAddress }
}

enum NativeFunctionArgument: Equatable, Sendable {
    case integer(Data)
    case nullPointer
    case buffer(Data)
    case imageRegion(NativeExecutionObservedGlobal)
}

struct NativeFunctionCallRequest: Sendable {
    static let maximumArguments = 16
    static let maximumObservedRegions = 16
    static let maximumObservedBytes = 64 * 1_024
    let id: UUID
    let image: NativeExecutionImage
    let staticFunctionAddress: UInt64
    let prototype: NativeFunctionPrototype
    let arguments: [NativeFunctionArgument]
    let globals: [NativeExecutionObservedGlobal]
    let timeoutSeconds: Double

    init(id: UUID = UUID(), image: NativeExecutionImage, staticFunctionAddress: UInt64,
         prototype: NativeFunctionPrototype, arguments: [NativeFunctionArgument],
         globals: [NativeExecutionObservedGlobal] = [], timeoutSeconds: Double = 2) throws {
        self.id = id
        self.image = image
        self.staticFunctionAddress = staticFunctionAddress
        self.prototype = prototype
        self.arguments = arguments
        self.globals = globals
        self.timeoutSeconds = timeoutSeconds
        try validate()
    }

    func validate() throws {
        guard timeoutSeconds.isFinite, (0.1...10).contains(timeoutSeconds),
              arguments.count == prototype.parameterTypes.count,
              arguments.count <= Self.maximumArguments else {
            throw NativeExecutionError.invalidRequest("The argument count or execution time limit is invalid.")
        }
        guard staticFunctionAddress.isMultiple(of: 4),
              image.regions.filter({ $0.permissions & 4 != 0 && $0.contains(staticFunctionAddress, count: 4) }).count == 1,
              image.regions.filter({ $0.permissions & 4 != 0 && $0.contains(image.entryAddress, count: 4) }).count == 1 else {
            throw NativeExecutionError.invalidRequest("Function and startup addresses must map uniquely to executable image memory.")
        }
        var ownedByteCount = 0
        var ownedRegionCount = 0
        for (type, argument) in zip(prototype.parameterTypes, arguments) {
            switch argument {
            case .integer(let bytes):
                guard type != .pointer, type != .void, bytes.count == type.byteCount else {
                    throw NativeExecutionError.invalidRequest("An integer argument does not match its declared type.")
                }
            case .nullPointer:
                guard type == .pointer else { throw NativeExecutionError.invalidRequest("NULL requires a pointer parameter.") }
            case .buffer(let bytes):
                guard type == .pointer, !bytes.isEmpty, bytes.count <= Self.maximumObservedBytes else {
                    throw NativeExecutionError.invalidRequest("A pointer buffer must contain between 1 and 65,536 bytes.")
                }
                ownedByteCount += bytes.count
                ownedRegionCount += 1
            case .imageRegion(let region):
                guard type == .pointer else { throw NativeExecutionError.invalidRequest("An image region requires a pointer parameter.") }
                try validateGlobal(region)
            }
        }
        for region in globals { try validateGlobal(region) }
        let normalized = try normalizedGlobals()
        let total = normalized.reduce(ownedByteCount) { $0 + $1.byteCount }
        guard normalized.count + ownedRegionCount <= Self.maximumObservedRegions,
              total <= Self.maximumObservedBytes else {
            throw NativeExecutionError.invalidRequest("Observe at most 16 memory regions and 65,536 bytes per call.")
        }
    }

    private func validateGlobal(_ region: NativeExecutionObservedGlobal) throws {
        guard region.byteCount > 0, region.byteCount <= Self.maximumObservedBytes,
              !region.name.isEmpty, region.name.utf8.count <= 256,
              image.regions.filter({ $0.permissions & 1 != 0
                  && $0.contains(region.staticAddress, count: UInt64(region.byteCount)) }).count == 1 else {
            throw NativeExecutionError.invalidRequest("An observed global must fit in one readable image segment.")
        }
    }

    /// Union selected static ranges so aliases do not consume the budget twice.
    func normalizedGlobals() throws -> [NativeExecutionObservedGlobal] {
        let referenced = arguments.compactMap { argument -> NativeExecutionObservedGlobal? in
            if case .imageRegion(let value) = argument { return value }
            return nil
        }
        let ordered = (globals + referenced).sorted {
            $0.staticAddress == $1.staticAddress ? $0.byteCount < $1.byteCount : $0.staticAddress < $1.staticAddress
        }
        var merged: [NativeExecutionObservedGlobal] = []
        for region in ordered {
            try validateGlobal(region)
            let end = region.staticAddress.addingReportingOverflow(UInt64(region.byteCount))
            guard !end.overflow else { throw NativeExecutionError.invalidRequest("Observed memory range overflows.") }
            if let last = merged.last {
                let lastEnd = last.staticAddress + UInt64(last.byteCount)
                if region.staticAddress < lastEnd {
                    let size = max(lastEnd, end.partialValue) - last.staticAddress
                    guard size <= Self.maximumObservedBytes else {
                        throw NativeExecutionError.invalidRequest("Observed memory range exceeds the byte limit.")
                    }
                    merged[merged.count - 1] = NativeExecutionObservedGlobal(
                        name: last.name, staticAddress: last.staticAddress, byteCount: Int(size))
                    continue
                }
            }
            merged.append(region)
        }
        return merged
    }
}

struct NativeMemoryObservation: Equatable, Sendable, Identifiable {
    let id: Int
    let label: String
    let runtimeAddress: UInt64
    let before: Data?
    let after: Data?
    let diagnostic: String?

    var changedRanges: [Range<Int>] {
        guard let before, let after, before.count == after.count else { return [] }
        let old = Array(before), new = Array(after)
        var ranges: [Range<Int>] = []
        var start: Int?
        for index in old.indices {
            if old[index] != new[index] { if start == nil { start = index } }
            else if let lower = start { ranges.append(lower..<index); start = nil }
        }
        if let start { ranges.append(start..<old.count) }
        return ranges
    }
}

enum NativeExecutionOutcome: String, Sendable { case completed, crashed, timedOut, cancelled, failed }

struct NativeFunctionCallResult: Sendable {
    let requestID: UUID
    let imageUUID: UUID
    let outcome: NativeExecutionOutcome
    let runtimeFunctionAddress: UInt64?
    let returnValue: NativeFunctionTypedValue?
    let memory: [NativeMemoryObservation]
    let diagnostics: [String]
    let faultProgramCounter: UInt64?
    let cleanupConfirmed: Bool
}
