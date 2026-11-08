import Foundation

struct SwiftOutcomeValidatorSection: Equatable {
    let segment: String
    let name: String
    let address: UInt64
    let size: UInt64
    let fileOffset: UInt64
    let flags: UInt32
}

// Admission retains values, not a caller-supplied receipt. The presentation path
// deliberately does not participate in custody (types.py:82–113).
final class SwiftOutcomeValidatorImage {
    let data: Data
    let path: String
    let sliceSHA256: String
    let containerSHA256: String
    let architecture: String
    let cpuSubtype: Int
    let uuid: String?
    let fileType: Int
    let preferredBase: UInt64
    let sliceOffset: UInt64
    let sliceSize: UInt64
    let sliceIndex: Int?
    let containerSliceCount: Int?
    let sections: [SwiftOutcomeValidatorSection]
    let functions: [SwiftErrorFlowFunction]
    private let seal: Seal?

    private struct Parts: Equatable {
        let data: Data
        let sliceSHA256: String, containerSHA256: String, architecture: String
        let cpuSubtype: Int
        let uuid: String?
        let fileType: Int
        let preferredBase: UInt64, sliceOffset: UInt64, sliceSize: UInt64
        let sliceIndex: Int?, containerSliceCount: Int?
        let sections: [SwiftOutcomeValidatorSection]
        let functions: [SwiftErrorFlowFunction]
    }
    private final class Seal {
        let parts: Parts
        init(_ parts: Parts) { self.parts = parts }
    }
    private var parts: Parts {
        Parts(data: data, sliceSHA256: sliceSHA256, containerSHA256: containerSHA256,
              architecture: architecture, cpuSubtype: cpuSubtype, uuid: uuid, fileType: fileType,
              preferredBase: preferredBase, sliceOffset: sliceOffset, sliceSize: sliceSize,
              sliceIndex: sliceIndex, containerSliceCount: containerSliceCount,
              sections: sections, functions: functions)
    }
    var hasValidAdmission: Bool {
        guard let seal else { return false }
        return sliceSize == UInt64(data.count) && seal.parts == parts
    }
    private init(parts p: Parts, path: String, seal: Seal?) {
        data = p.data; self.path = path; sliceSHA256 = p.sliceSHA256
        containerSHA256 = p.containerSHA256; architecture = p.architecture
        cpuSubtype = p.cpuSubtype; uuid = p.uuid; fileType = p.fileType
        preferredBase = p.preferredBase; sliceOffset = p.sliceOffset; sliceSize = p.sliceSize
        sliceIndex = p.sliceIndex; containerSliceCount = p.containerSliceCount
        sections = p.sections; functions = p.functions; self.seal = seal
    }
    static func admit(data: Data, path: String, sliceSHA256: String, containerSHA256: String,
                      architecture: String, cpuSubtype: Int, uuid: String?, fileType: Int,
                      preferredBase: UInt64, sliceOffset: UInt64, sliceSize: UInt64,
                      sliceIndex: Int?, containerSliceCount: Int?,
                      sections: [SwiftOutcomeValidatorSection], functions: [SwiftErrorFlowFunction]) -> SwiftOutcomeValidatorImage {
        let p = Parts(data: data, sliceSHA256: sliceSHA256, containerSHA256: containerSHA256,
                      architecture: architecture, cpuSubtype: cpuSubtype, uuid: uuid, fileType: fileType,
                      preferredBase: preferredBase, sliceOffset: sliceOffset, sliceSize: sliceSize,
                      sliceIndex: sliceIndex, containerSliceCount: containerSliceCount,
                      sections: sections, functions: functions)
        return SwiftOutcomeValidatorImage(parts: p, path: path,
                                         seal: sliceSize == UInt64(data.count) ? Seal(p) : nil)
    }
    static func unadmitted(data: Data, path: String, sliceSHA256: String, containerSHA256: String,
                           architecture: String, cpuSubtype: Int, uuid: String?, fileType: Int,
                           preferredBase: UInt64, sliceOffset: UInt64, sliceSize: UInt64,
                           sliceIndex: Int?, containerSliceCount: Int?,
                           sections: [SwiftOutcomeValidatorSection], functions: [SwiftErrorFlowFunction]) -> SwiftOutcomeValidatorImage {
        let p = Parts(data: data, sliceSHA256: sliceSHA256, containerSHA256: containerSHA256,
                      architecture: architecture, cpuSubtype: cpuSubtype, uuid: uuid, fileType: fileType,
                      preferredBase: preferredBase, sliceOffset: sliceOffset, sliceSize: sliceSize,
                      sliceIndex: sliceIndex, containerSliceCount: containerSliceCount,
                      sections: sections, functions: functions)
        return SwiftOutcomeValidatorImage(parts: p, path: path, seal: nil)
    }
    func copy(path: String? = nil, data: Data? = nil) -> SwiftOutcomeValidatorImage {
        let p = Parts(data: data ?? self.data, sliceSHA256: sliceSHA256, containerSHA256: containerSHA256,
                      architecture: architecture, cpuSubtype: cpuSubtype, uuid: uuid, fileType: fileType,
                      preferredBase: preferredBase, sliceOffset: sliceOffset, sliceSize: sliceSize,
                      sliceIndex: sliceIndex, containerSliceCount: containerSliceCount,
                      sections: sections, functions: functions)
        return SwiftOutcomeValidatorImage(parts: p, path: path ?? self.path, seal: seal)
    }
}
