import Foundation

/// Reads the three regeneration files from an export folder. Read-only: it never writes into the
/// folder, never executes anything from it, and refuses symbolic links that leave the folder and
/// files over `maximumFileBytes`, each as its own per-file state.
struct RegenerationExportFolderLoader: Sendable {
    static let defaultMaximumFileBytes = 256 * 1024 * 1024

    let maximumFileBytes: Int

    init(maximumFileBytes: Int = RegenerationExportFolderLoader.defaultMaximumFileBytes) {
        self.maximumFileBytes = maximumFileBytes
    }

    func load(folder: URL) -> RegenerationLoadedExport {
        let root = Self.resolved(folder.path) ?? folder.standardizedFileURL.path
        var manifest: RegenerationProgressManifest?
        var dependencies: RegenerationProgressDependencies?
        var report: RegenerationProgressStructureReport?
        let files = [
            read(RegenerationLoadedExport.manifestFileName, folder: folder, root: root) {
                manifest = try RegenerationExportDecoder.manifest($0)
            },
            read(RegenerationLoadedExport.dependenciesFileName, folder: folder, root: root) {
                dependencies = try RegenerationExportDecoder.dependencies($0)
            },
            read(RegenerationLoadedExport.reportFileName, folder: folder, root: root) {
                report = try RegenerationExportDecoder.structureReport($0)
            },
        ]
        return RegenerationLoadedExport(files: files, manifest: manifest, dependencies: dependencies, report: report)
    }

    private func read(
        _ name: String, folder: URL, root: String,
        decode: ([String: Any]) throws -> Void
    ) -> RegenerationExportFile {
        RegenerationExportFile(name: name, state: state(of: name, folder: folder, root: root, decode: decode))
    }

    private func state(
        of name: String, folder: URL, root: String,
        decode: ([String: Any]) throws -> Void
    ) -> RegenerationFileState {
        let path = folder.appendingPathComponent(name).path
        var link = stat()
        guard lstat(path, &link) == 0 else {
            return errno == ENOENT ? .notProducedYet : .unreadable(file: name, message: String(cString: strerror(errno)))
        }
        guard let target = Self.resolved(path) else {
            return .unreadable(file: name, message: "path does not resolve")
        }
        guard target.hasPrefix(root.hasSuffix("/") ? root : root + "/") else {
            return .refusedSymlink(file: name, target: target)
        }
        var info = stat()
        guard stat(target, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG else {
            return .unreadable(file: name, message: "not a regular file")
        }
        guard Int(info.st_size) <= maximumFileBytes else {
            return .refusedOversize(file: name, bytes: Int(info.st_size), limit: maximumFileBytes)
        }
        let data: Data
        do {
            data = try Data(contentsOf: URL(fileURLWithPath: target))
        } catch {
            return .unreadable(file: name, message: error.localizedDescription)
        }
        do {
            try decode(try RegenerationExportDecoder.parse(data))
            return .loaded
        } catch let failure as RegenerationDecodeFailure {
            switch failure {
            case let .malformed(path, message): return .malformed(file: name, path: path, message: message)
            case let .unsupportedVersion(path, value): return .unsupportedVersion(file: name, field: path, value: value)
            case let .unsupportedValue(path, value): return .unsupportedValue(file: name, field: path, value: value)
            }
        } catch {
            return .unreadable(file: name, message: error.localizedDescription)
        }
    }

    private static func resolved(_ path: String) -> String? {
        guard let pointer = realpath(path, nil) else { return nil }
        defer { free(pointer) }
        return String(cString: pointer)
    }
}
