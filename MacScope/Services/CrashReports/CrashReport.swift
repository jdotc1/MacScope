import Foundation

/// A bounded, read-only projection of an Apple JSON crash report. Source indices remain
/// intact; report addresses never become authority for the currently loaded binary.
struct CrashReport: Sendable {
    let processName: String
    let exceptionSummary: String
    let threads: [CrashReportThread]
    let images: [CrashReportImage]
    /// Documented `osVersion` object (build, train, releaseType). Absent in legacy reports.
    /// Informational only until a later slice compares it with the host; never authority here.
    var osVersion: CrashReportOSVersion? = nil

    enum ParseError: Error, LocalizedError {
        case inputTooLarge, malformed, resourceLimit, invalidImageRange
        /// A newly decoded optional field is present but invalid. Absent fields never raise this.
        case invalidField(String)

        var errorDescription: String? {
            switch self {
            case .inputTooLarge: return "The crash report exceeds the 16 MiB limit."
            case .malformed: return "The crash report is not a supported JSON crash report."
            case .resourceLimit: return "The crash report exceeds the thread, frame, or image limit."
            case .invalidImageRange: return "The crash report contains an invalid image address range."
            case .invalidField(let key): return "The crash report field '\(key)' is present but invalid."
            }
        }
    }

    static func parse(_ data: Data) throws -> CrashReport {
        guard data.count <= 16 * 1_024 * 1_024 else { throw ParseError.inputTooLarge }
        let decoder = JSONDecoder()
        let body: Body
        var metadata: Metadata?
        if let single = try? decoder.decode(Body.self, from: data) {
            body = single
        } else {
            // Apple's .ips envelope is one metadata object on the first line, followed
            // by a separate JSON object. Never scan for a convenient inner object.
            guard let newline = data.firstIndex(of: 10),
                  let header = try? decoder.decode(Metadata.self, from: Data(data[..<newline])),
                  let payload = try? decoder.decode(Body.self, from: Data(data[data.index(after: newline)...]))
            else { throw ParseError.malformed }
            metadata = header
            body = payload
        }
        guard body.threads.count <= 1_024, body.usedImages.count <= 20_000 else {
            throw ParseError.resourceLimit
        }
        var frameCount = 0
        let threads = try body.threads.enumerated().map { index, thread in
            guard thread.frames.count <= 100_000 - frameCount else { throw ParseError.resourceLimit }
            frameCount += thread.frames.count
            return CrashReportThread(id: index, name: thread.name ?? thread.queue,
                triggered: thread.triggered ?? (body.faultingThread == index),
                frames: try thread.frames.enumerated().map { offset, frame in
                    guard frame.imageIndex.map({ $0 >= 0 }) ?? true else { throw ParseError.malformed }
                    return CrashReportFrame(id: offset, imageIndex: frame.imageIndex,
                        imageOffset: frame.imageOffset, reportedSymbol: frame.symbol,
                        symbolLocation: frame.symbolLocation)
                }, registers: thread.threadState?.registers ?? [],
                registerFlavor: thread.threadState?.flavor)
        }
        let images = try body.usedImages.map { image in
            guard !image.base.addingReportingOverflow(image.size).overflow else {
                throw ParseError.invalidImageRange
            }
            var source: CrashReportImageSource?
            if let raw = image.source {
                guard let parsed = CrashReportImageSource(rawValue: raw) else {
                    throw ParseError.invalidField("usedImages.source")
                }
                source = parsed
            }
            if let path = image.path, path.utf8.count > 4_096 { throw ParseError.invalidField("usedImages.path") }
            if let arch = image.arch, arch.utf8.count > 64 { throw ParseError.invalidField("usedImages.arch") }
            return CrashReportImage(name: image.name ?? "Unknown image", uuid: image.uuid,
                base: image.base, size: image.size, path: image.path, arch: image.arch, source: source)
        }
        var osVersion: CrashReportOSVersion?
        if let details = body.osVersion {
            for (key, value) in [("osVersion.build", details.build), ("osVersion.train", details.train),
                                 ("osVersion.releaseType", details.releaseType)] {
                if let value, value.isEmpty || value.utf8.count > 128 { throw ParseError.invalidField(key) }
            }
            osVersion = CrashReportOSVersion(build: details.build, train: details.train,
                releaseType: details.releaseType)
        }
        let exception = [body.exception?.type, body.exception?.signal, body.exception?.subtype]
            .compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
        return CrashReport(processName: body.procName ?? metadata?.app_name ?? "Unknown process",
            exceptionSummary: exception.isEmpty ? "Exception not reported" : exception,
            threads: threads, images: images, osVersion: osVersion)
    }

    func runtimeAddress(of frame: CrashReportFrame) -> UInt64? {
        guard let index = frame.imageIndex, images.indices.contains(index),
              let offset = frame.imageOffset, offset < images[index].size else { return nil }
        let result = images[index].base.addingReportingOverflow(offset)
        return result.overflow ? nil : result.partialValue
    }

    /// Duplicate UUID candidates cannot select a workspace image by collection order.
    func match(_ frame: CrashReportFrame, contexts: [CrashReportImageContext]) -> CrashReportImageMatch {
        guard let index = frame.imageIndex, images.indices.contains(index),
              let uuid = Self.canonicalUUID(images[index].uuid) else {
            return CrashReportImageMatch(contextIndex: nil,
                resolved: CrashReportResolvedFrame(address: nil, symbol: nil, diagnostic: "No valid image UUID"))
        }
        let candidates = contexts.indices.filter { Self.canonicalUUID(contexts[$0].uuid) == uuid }
        guard candidates.count == 1, let candidate = candidates.first else {
            return CrashReportImageMatch(contextIndex: nil, resolved: CrashReportResolvedFrame(
                address: nil, symbol: nil, diagnostic: candidates.isEmpty
                    ? "Load the binary with this UUID, then reopen the report"
                    : "Multiple loaded images have this UUID; the target is ambiguous"))
        }
        return CrashReportImageMatch(contextIndex: candidate, resolved: resolve(frame, against: contexts[candidate]))
    }

    func resolve(_ frame: CrashReportFrame, against context: CrashReportImageContext?) -> CrashReportResolvedFrame {
        func unresolved(_ reason: String) -> CrashReportResolvedFrame {
            CrashReportResolvedFrame(address: nil, symbol: nil, diagnostic: reason)
        }
        guard let index = frame.imageIndex, images.indices.contains(index),
              let offset = frame.imageOffset else { return unresolved("No image-relative address") }
        let image = images[index]
        guard let context else { return unresolved("Open the matching image to navigate") }
        guard let reportedUUID = Self.canonicalUUID(image.uuid),
              let loadedUUID = Self.canonicalUUID(context.uuid), reportedUUID == loadedUUID else {
            return unresolved("Image UUID does not match the open image")
        }
        guard offset < image.size else { return unresolved("Frame offset is outside the reported image") }
        let (address, overflow) = context.preferredBase.addingReportingOverflow(offset)
        guard !overflow, context.mappedRanges.contains(where: { $0.contains(address) }) else {
            return unresolved("Frame address is outside the open image")
        }
        // An exact label is known, but an unbounded preceding label is not a function.
        var symbol: CrashReportSymbol?
        for candidate in context.symbols {
            if candidate.address == address {
                symbol = candidate
                break
            }
            if let end = candidate.endAddress, candidate.address < end,
               candidate.address <= address, address < end,
               symbol.map({ $0.address < candidate.address }) ?? true {
                symbol = candidate
            }
        }
        return CrashReportResolvedFrame(address: address, symbol: symbol?.name, diagnostic: nil)
    }

    private static func canonicalUUID(_ value: String?) -> String? {
        guard let value else { return nil }
        let compact = value.replacingOccurrences(of: "-", with: "").lowercased()
        guard compact.utf8.count == 32,
              compact.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { return nil }
        return compact
    }

    private struct Metadata: Decodable { let app_name: String? }
    private struct Body: Decodable {
        let procName: String?
        let exception: ExceptionDetails?
        let faultingThread: Int?
        let threads: [ThreadDetails]
        let usedImages: [ImageDetails]
        let osVersion: OSVersionDetails?
    }
    private struct OSVersionDetails: Decodable { let build: String?; let train: String?; let releaseType: String? }
    private struct ExceptionDetails: Decodable { let type: String?; let signal: String?; let subtype: String? }
    private struct ThreadDetails: Decodable {
        let name: String?
        let queue: String?
        let triggered: Bool?
        let frames: [FrameDetails]
        let threadState: CrashReportThreadState?
    }
    private struct FrameDetails: Decodable { let imageIndex: Int?; let imageOffset: UInt64?; let symbol: String?; let symbolLocation: UInt64? }
    private struct ImageDetails: Decodable { let name: String?; let uuid: String?; let base: UInt64; let size: UInt64
        let path: String?; let arch: String?; let source: String? }
}

struct CrashReportThread: Identifiable, Sendable {
    let id: Int
    let name: String?
    let triggered: Bool
    let frames: [CrashReportFrame]
    var registers: [CrashReportRegister] = []
    var registerFlavor: String? = nil
}

struct CrashReportRegister: Identifiable, Sendable {
    var id: String { name }
    let name: String
    let value: UInt64
}

/// Decode only register-bearing keys. Diagnostic strings and matchesCrashFrame are not registers.
private struct CrashReportThreadState: Decodable {
    let flavor: String?
    let registers: [CrashReportRegister]
    private struct Key: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
        init(_ value: String) { stringValue = value }
    }
    private struct Value: Decodable { let value: UInt64 }
    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: Key.self)
        guard values.allKeys.count <= 256 else { throw CrashReport.ParseError.resourceLimit }
        flavor = try values.decodeIfPresent(String.self, forKey: Key("flavor"))
        var result: [CrashReportRegister] = []
        if let general = try values.decodeIfPresent([Value].self, forKey: Key("x")) {
            guard general.count <= 29 else { throw CrashReport.ParseError.resourceLimit }
            result += general.enumerated().map { CrashReportRegister(name: "x\($0.offset)", value: $0.element.value) }
        }
        let names = ["fp", "lr", "sp", "pc", "cpsr", "esr", "far",
                     "rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "rflags", "cr2", "err", "trap", "cpu"]
        for name in names {
            if let value = try values.decodeIfPresent(Value.self, forKey: Key(name)) {
                result.append(CrashReportRegister(name: name, value: value.value))
            }
        }
        registers = result
    }
}

struct CrashReportImageMatch: Sendable {
    let contextIndex: Int?
    let resolved: CrashReportResolvedFrame
}

struct CrashReportFrame: Identifiable, Sendable {
    let id: Int
    let imageIndex: Int?
    let imageOffset: UInt64?
    let reportedSymbol: String?
    /// Documented `symbolLocation`: bytes from the symbol entry the report writer chose. A claim
    /// of the report, never used as authority.
    var symbolLocation: UInt64? = nil
}

struct CrashReportImage: Sendable {
    let name: String
    let uuid: String?
    let base: UInt64
    let size: UInt64
    /// Documented binary-image keys `path`, `arch` and `source`. Absent in legacy reports.
    var path: String? = nil
    var arch: String? = nil
    var source: CrashReportImageSource? = nil
}

/// Documented `usedImages[].source` region-type characters.
enum CrashReportImageSource: String, Sendable {
    case process = "P", sharedCache = "S", sharedCacheLibrary = "C", kernel = "K"
    case kernelCache = "U", kernelTextExec = "T", absolute = "A"
}

/// Documented `osVersion` object keys `build`, `train` and `releaseType`.
struct CrashReportOSVersion: Sendable, Equatable {
    let build: String?
    let train: String?
    let releaseType: String?
}

struct CrashReportImageContext: Sendable {
    let uuid: String
    let preferredBase: UInt64
    let mappedRanges: [Range<UInt64>]
    let symbols: [CrashReportSymbol]
}

struct CrashReportSymbol: Sendable {
    let name: String
    let address: UInt64
    let endAddress: UInt64?
}

struct CrashReportResolvedFrame: Sendable {
    let address: UInt64?
    let symbol: String?
    let diagnostic: String?
}
