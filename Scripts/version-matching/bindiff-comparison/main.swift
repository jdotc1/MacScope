import Foundation

func item(_ id: String, _ address: UInt64, _ name: String, _ size: UInt64, _ body: String, _ semantic: String, _ count: Int) -> FunctionVersionFingerprint {
    FunctionVersionFingerprint(id: id, address: address, symbolName: name, size: size,
                               basicBlockCount: 1, edgeCount: 0, cfgShapeHash: nil,
                               normalizedBodyHash: body, semanticBodyHash: semantic,
                               instructionCount: count, calleeIDs: [], importedCalleeNames: [], stringReferences: [])
}
let old = [item("old.alpha", 0x1000, "_alpha", 12, "alpha", "alpha", 3),
           item("old.beta", 0x1100, "_beta", 12, "beta-shape", "beta-2", 3),
           item("old.removed", 0x1200, "_removed", 8, "removed-shape", "removed", 2)]
let new = [item("new.alpha", 0x2000, "_alpha", 12, "alpha", "alpha", 3),
           item("new.beta", 0x2100, "_beta", 12, "beta-shape", "beta-3", 3),
           item("new.added", 0x2200, "_added", 16, "added-shape", "added", 4)]
let result = try FunctionVersionMatcher(old: old, new: new).match()
let encoder = JSONEncoder()
encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
let data = try encoder.encode(result)
FileHandle.standardOutput.write(data)
print("")
