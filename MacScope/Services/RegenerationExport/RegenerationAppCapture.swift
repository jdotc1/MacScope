import Darwin
import Foundation

struct RegenerationCapturedApplication: Sendable {
    let applicationName: String
    let sourceLanguage: String
    let originalInfoPlist: Data
    let resources: [String: Data]
    let diagnostics: [String]
}

/// The selected executable is already captured by the analysis owner. These passive bundle
/// observations are stable during each read, but path agreement does not establish that they
/// belong to the historical captured image. Executable/provenance checks are not replayed.
enum RegenerationAppCapture {
    static func capture(app: URL, capturedExecutable: URL) throws -> RegenerationCapturedApplication {
        guard app.isFileURL, app.pathExtension.lowercased() == "app",
              app.path.hasPrefix("/"), !app.pathComponents.contains("..") else {
            throw RegenerationError.invalidPath("expected an absolute application bundle")
        }
        let directory = try RegenerationFileSystem.openOrdinaryDirectory(app)
        defer { close(directory) }
        let info = try read(relative: "Contents/Info.plist", root: directory, maximum: 4_194_304)
        guard let plist = try PropertyListSerialization.propertyList(from: info, format: nil) as? [String: Any],
              let executable = plist["CFBundleExecutable"] as? String,
              !executable.isEmpty, executable != ".", executable != "..",
              !executable.contains("/"), !executable.contains("\\"), !executable.contains("\0") else {
            throw RegenerationError.invalidInput("missing or invalid CFBundleExecutable")
        }
        let expected = app.appendingPathComponent("Contents/MacOS").appendingPathComponent(executable).standardizedFileURL
        guard expected.path == capturedExecutable.standardizedFileURL.path else {
            throw RegenerationError.invalidInput("bundle executable path differs from the selected image path")
        }
        let contents = openat(directory, "Contents", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard contents >= 0 else { throw failure("open application contents") }
        defer { close(contents) }
        let resourcesFD = openat(contents, "Resources", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        var files: [String: Data] = [:], budget = Budget()
        if resourcesFD >= 0 {
            defer { close(resourcesFD) }
            try walk(resourcesFD, prefix: "", depth: 0, files: &files, budget: &budget)
        } else if errno != ENOENT { throw failure("open resources") }
        let declaredLanguage = plist["CFBundleDevelopmentRegion"] as? String
        let language = declaredLanguage.flatMap { !$0.isEmpty && $0 != "Base" ? $0 : nil } ?? "en"
        let diagnostics = declaredLanguage == nil
            ? ["Development language is absent; editable localization candidates use explicit default en."] : []
        return .init(applicationName: app.deletingPathExtension().lastPathComponent, sourceLanguage: language,
                     originalInfoPlist: info, resources: files, diagnostics: diagnostics)
    }

    private struct Budget { var entries = 0; var bytes = 0 }

    private static func walk(_ directory: Int32, prefix: String, depth: Int,
                             files: inout [String: Data], budget: inout Budget) throws {
        guard depth <= 32 else { throw RegenerationError.invalidInput("resource nesting exceeds 32 levels") }
        var before = stat()
        guard fstat(directory, &before) == 0 else { throw failure("inspect resource directory") }
        let copy = dup(directory)
        guard copy >= 0 else { throw failure("duplicate resource directory") }
        guard let stream = fdopendir(copy) else { close(copy); throw failure("enumerate resources") }
        defer { closedir(stream) }
        var names: [String] = []
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw failure("read resource directory") }
                break
            }
            let length = Int(entry.pointee.d_namlen)
            let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
                pointer.withMemoryRebound(to: UInt8.self, capacity: length + 1) {
                    String(bytes: UnsafeBufferPointer(start: $0, count: length), encoding: .utf8)
                }
            }
            guard let name else { throw RegenerationError.invalidPath("non-UTF8 resource name cannot be represented") }
            if name == "." || name == ".." { continue }
            budget.entries += 1
            guard budget.entries <= 20_000 else { throw RegenerationError.invalidInput("resource inventory exceeds 20000 entries") }
            names.append(name)
        }
        for name in names.sorted() {
            try Task.checkCancellation()
            let path = prefix.isEmpty ? name : prefix + "/" + name
            guard RegenerationEncoding.relativePath(path) else { throw RegenerationError.invalidPath("resource name cannot be represented") }
            var entry = stat()
            guard fstatat(directory, name, &entry, AT_SYMLINK_NOFOLLOW) == 0 else { throw failure("inspect resource") }
            if entry.st_mode & mode_t(S_IFMT) == mode_t(S_IFDIR) {
                let child = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { throw failure("open resource package") }
                defer { close(child) }
                var opened = stat()
                guard fstat(child, &opened) == 0, opened.st_dev == entry.st_dev, opened.st_ino == entry.st_ino else {
                    throw RegenerationError.invalidInput("resource directory changed during capture")
                }
                try walk(child, prefix: path, depth: depth + 1, files: &files, budget: &budget)
            } else if entry.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG) {
                let bytes = try read(relative: name, root: directory, maximum: min(67_108_864, 536_870_912 - budget.bytes))
                budget.bytes += bytes.count
                files[path] = bytes
            } else {
                throw RegenerationError.invalidInput("resource symlink or special file is unsupported: " + RegenerationEncoding.annotation(path))
            }
        }
        var after = stat()
        guard fstat(directory, &after) == 0, same(before, after) else {
            throw RegenerationError.invalidInput("resource directory changed during capture")
        }
    }

    private static func read(relative: String, root: Int32, maximum: Int) throws -> Data {
        let components = relative.split(separator: "/").map(String.init)
        var parent = dup(root)
        guard parent >= 0 else { throw failure("duplicate input directory") }
        defer { close(parent) }
        for part in components.dropLast() {
            let next = openat(parent, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw failure("open input directory") }
            close(parent); parent = next
        }
        guard let name = components.last else { throw RegenerationError.invalidPath("empty input path") }
        let file = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard file >= 0 else { throw failure("open passive resource") }
        defer { close(file) }
        var before = stat()
        guard fstat(file, &before) == 0, before.st_mode & mode_t(S_IFMT) == mode_t(S_IFREG),
              before.st_size >= 0, before.st_size <= maximum else {
            throw RegenerationError.invalidInput("resource is not an ordinary file within the byte budget")
        }
        var result = Data(), buffer = [UInt8](repeating: 0, count: 65_536)
        while true {
            let count = Darwin.read(file, &buffer, buffer.count)
            if count < 0, errno == EINTR { continue }
            guard count >= 0 else { throw failure("read passive resource") }
            if count == 0 { break }
            guard count <= maximum - result.count else { throw RegenerationError.invalidInput("resource grew beyond capture budget") }
            result.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard fstat(file, &after) == 0, same(before, after), result.count == after.st_size else {
            throw RegenerationError.invalidInput("resource changed during capture")
        }
        return result
    }

    private static func same(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode && a.st_size == b.st_size
            && a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec
            && a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
    }

    private static func failure(_ operation: String) -> RegenerationError { .invalidPath("\(operation) failed (errno \(errno))") }
}
