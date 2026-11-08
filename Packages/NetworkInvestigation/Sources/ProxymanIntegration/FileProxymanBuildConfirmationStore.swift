import Foundation
import ProxymanInstallation

/// Remembers at most 256 bridge cdhashes, oldest first, in sorted-key UTF-8 JSON:
/// {"cdhashes":["<40 lowercase hexadecimal characters>"],"version":1}.
/// An absent or unreadable file reads as empty. Persistence failures retain consent
/// in memory for this instance; the file is never deleted to recover from failure.
public actor FileProxymanBuildConfirmationStore: ProxymanBuildConfirmationStoring {
    private let fileURL: URL
    private var loaded = false
    private var hashes: [String] = []
    private static let capacity = 256
    private static let byteLimit = 65_536

    public init(fileURL: URL) {
        self.fileURL = fileURL.standardizedFileURL
    }

    public func isConfirmed(cdhash: String) async -> Bool {
        loadOnce()
        return Self.isValid(cdhash) && hashes.contains(cdhash)
    }

    public func confirm(cdhash: String) async {
        loadOnce()
        guard Self.isValid(cdhash), !hashes.contains(cdhash) else { return }
        hashes.append(cdhash)
        if hashes.count > Self.capacity { hashes.removeFirst() }
        persist()
    }

    private static func isValid(_ value: String) -> Bool {
        value.utf8.count == 40 && value.utf8.allSatisfy {
            (48...57).contains($0) || (97...102).contains($0)
        }
    }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        do {
            guard fileURL.isFileURL, try hasSafeAncestors(),
                  try itemType(at: fileURL) == .typeRegular,
                  let size = try FileManager.default.attributesOfItem(atPath: fileURL.path)[.size] as? NSNumber,
                  size.uint64Value <= UInt64(Self.byteLimit) else { return }
            let handle = try FileHandle(forReadingFrom: fileURL)
            defer { try? handle.close() }
            let data = try handle.read(upToCount: Self.byteLimit + 1) ?? Data()
            guard data.count <= Self.byteLimit else { return }
            var parser = DocumentParser(bytes: Array(data))
            guard let entries = parser.parse(), entries.count <= Self.capacity,
                  entries.allSatisfy(Self.isValid) else { return }
            var seen = Set<String>()
            hashes = entries.filter { seen.insert($0).inserted }
        } catch {
            // An unreadable file grants no persistent trust.
        }
    }

    private struct Document: Encodable {
        let cdhashes: [String]
        let version = 1
    }

    private func persist() {
        let manager = FileManager.default
        var temporary: URL?
        defer {
            if let temporary { try? manager.removeItem(at: temporary) }
        }
        do {
            guard fileURL.isFileURL, try hasSafeAncestors() else { return }
            let existing = try itemType(at: fileURL)
            guard existing == nil || existing == .typeRegular else { return }
            let parent = fileURL.deletingLastPathComponent()
            try ensureDirectory(parent)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let data = try encoder.encode(Document(cdhashes: hashes))
            let candidate = parent.appendingPathComponent(".confirmation-\(UUID().uuidString).tmp")
            guard try itemType(at: candidate) == nil else { return }
            guard manager.createFile(atPath: candidate.path, contents: nil,
                                     attributes: [.posixPermissions: 0o600]) else { return }
            temporary = candidate
            try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: candidate.path)
            let handle = try FileHandle(forWritingTo: candidate)
            do {
                try handle.write(contentsOf: data)
                try handle.close()
            } catch {
                try? handle.close()
                throw error
            }
            // Check again immediately before replacement. The target is never
            // opened for writing, and replacement never preserves old permissions.
            guard try hasSafeAncestors() else { return }
            let current = try itemType(at: fileURL)
            guard current == nil || current == .typeRegular else { return }
            if current == .typeRegular {
                _ = try manager.replaceItemAt(fileURL, withItemAt: candidate,
                    backupItemName: nil, options: [.usingNewMetadataOnly])
            } else {
                try manager.moveItem(at: candidate, to: fileURL)
            }
            temporary = nil
        } catch {
            // The explicit confirmation remains valid for this instance.
        }
    }

    private func itemType(at url: URL) throws -> FileAttributeType? {
        do {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            guard let type = attributes[.type] as? FileAttributeType else {
                throw CocoaError(.fileReadUnknown)
            }
            return type
        } catch let error as NSError where error.domain == NSCocoaErrorDomain
            && error.code == NSFileReadNoSuchFileError {
            return nil
        }
    }

    static func isTrustedSystemLink(path: String, ownerID: UInt64?) -> Bool {
        ownerID == 0 && path != "/" && URL(fileURLWithPath: path).deletingLastPathComponent().path == "/"
    }

    private func hasSafeAncestors() throws -> Bool {
        var ancestor = fileURL.deletingLastPathComponent()
        while true {
            // Local change to the dot's code: only a root-owned symlink directly under "/"
            // (such as /var or /tmp) is exempt; every other ancestor symlink is refused.
            let owner = (try? FileManager.default.attributesOfItem(atPath: ancestor.path)[.ownerAccountID]) as? NSNumber
            let exempt = Self.isTrustedSystemLink(path: ancestor.path, ownerID: owner?.uint64Value)
            if let type = try itemType(at: ancestor), type != .typeDirectory,
               !(exempt && type == .typeSymbolicLink) { return false }
            if ancestor.path == "/" { return true }
            let parent = ancestor.deletingLastPathComponent()
            if parent.path == ancestor.path { return true }
            ancestor = parent
        }
    }

    private func ensureDirectory(_ url: URL) throws {
        if let type = try itemType(at: url) {
            guard type == .typeDirectory else { throw CocoaError(.fileWriteInvalidFileName) }
            return
        }
        let parent = url.deletingLastPathComponent()
        guard url.path != "/", parent.path != url.path else { throw CocoaError(.fileWriteInvalidFileName) }
        try ensureDirectory(parent)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false,
                                               attributes: [.posixPermissions: 0o700])
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
    }

    /// Parses only the specified shape, preserving the distinction between an
    /// integer token and a boolean, fraction or exponent. JSONDecoder validates
    /// each string, including escapes and UTF-8; duplicate keys fail closed.
    private struct DocumentParser {
        let bytes: [UInt8]
        var index = 0

        mutating func parse() -> [String]? {
            guard take(123) else { return nil }
            var entries: [String]?
            var versionSeen = false
            while true {
                guard let key = string(), take(58) else { return nil }
                switch key {
                case "cdhashes":
                    guard entries == nil, take(91) else { return nil }
                    var values: [String] = []
                    if !take(93) {
                        repeat {
                            guard let value = string(), values.count < 256 else { return nil }
                            values.append(value)
                        } while take(44)
                        guard take(93) else { return nil }
                    }
                    entries = values
                case "version":
                    guard !versionSeen else { return nil }
                    skipWhitespace()
                    guard index < bytes.count, bytes[index] == 49 else { return nil }
                    index += 1
                    versionSeen = true
                default:
                    return nil
                }
                if take(125) { break }
                guard take(44) else { return nil }
            }
            skipWhitespace()
            guard index == bytes.count, versionSeen else { return nil }
            return entries
        }

        mutating func string() -> String? {
            skipWhitespace()
            let start = index
            guard index < bytes.count, bytes[index] == 34 else { return nil }
            index += 1
            while index < bytes.count {
                let byte = bytes[index]
                index += 1
                if byte == 34 {
                    return try? JSONDecoder().decode(String.self, from: Data(bytes[start..<index]))
                }
                if byte == 92 {
                    guard index < bytes.count else { return nil }
                    index += 1
                }
            }
            return nil
        }

        mutating func take(_ byte: UInt8) -> Bool {
            skipWhitespace()
            guard index < bytes.count, bytes[index] == byte else { return false }
            index += 1
            return true
        }

        mutating func skipWhitespace() {
            while index < bytes.count, [9, 10, 13, 32].contains(bytes[index]) { index += 1 }
        }
    }
}
