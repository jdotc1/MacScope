import Darwin
import Foundation

enum RegenerationFileSystem {
    /// Publication uses RENAME_EXCL, so a competing destination cannot be overwritten.
    /// Failed staging is intentionally retained with an incomplete marker for diagnosis.
    static func publish(files: [String: Data], to destination: URL,
                        prepare: (URL) throws -> Void) throws {
        guard destination.isFileURL, destination.path.hasPrefix("/"),
              !destination.pathComponents.contains(".."),
              !destination.lastPathComponent.isEmpty, destination.lastPathComponent != "/",
              files.count <= 20_000, files.keys.allSatisfy(RegenerationEncoding.relativePath),
              files["EXPORT-INCOMPLETE.txt"] == nil else {
            throw RegenerationError.invalidPath("invalid destination or export file set")
        }
        var byteCount = 0
        for data in files.values {
            let next = byteCount.addingReportingOverflow(data.count)
            guard !next.overflow, next.partialValue <= 536_870_912 else {
                throw RegenerationError.invalidInput("export exceeds 512 MiB preparation budget")
            }
            byteCount = next.partialValue
        }
        let parent = destination.deletingLastPathComponent()
        let parentFD = try openDirectory(parent)
        defer { close(parentFD) }
        var existing = stat()
        let name = destination.lastPathComponent
        guard fstatat(parentFD, name, &existing, AT_SYMLINK_NOFOLLOW) != 0, errno == ENOENT else {
            throw RegenerationError.destinationExists
        }
        let stageName = "." + name + ".incomplete-" + UUID().uuidString.lowercased()
        guard mkdirat(parentFD, stageName, 0o700) == 0 else { throw ioFailure("create staging") }
        let stageFD = openat(parentFD, stageName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard stageFD >= 0 else { throw ioFailure("open staging") }
        defer { close(stageFD) }
        let stageURL = parent.appendingPathComponent(stageName, isDirectory: true)
        let marker = Data("INCOMPLETE: project export has not been published successfully.\n".utf8)
        try write(marker, relative: "EXPORT-INCOMPLETE.txt", root: stageFD)
        for path in files.keys.sorted() {
            try Task.checkCancellation()
            guard let data = files[path] else { continue }
            try write(data, relative: path, root: stageFD)
        }
        try requireSameDirectory(parent, descriptor: parentFD)
        try Task.checkCancellation()
        try prepare(stageURL)
        try requireSameDirectory(parent, descriptor: parentFD)
        try requireSameDirectory(stageURL, descriptor: stageFD)
        try validateTree(stageFD, remaining: 40_000)
        try Task.checkCancellation()
        guard unlinkat(stageFD, "EXPORT-INCOMPLETE.txt", 0) == 0 else { throw ioFailure("remove incomplete marker") }
        if renameatx_np(parentFD, stageName, parentFD, name, UInt32(RENAME_EXCL)) != 0 {
            let failure = errno
            try? write(marker, relative: "EXPORT-INCOMPLETE.txt", root: stageFD)
            if failure == EEXIST || failure == ENOTEMPTY { throw RegenerationError.destinationExists }
            throw RegenerationError.invalidPath("atomic publication failed (errno \(failure))")
        }
    }

    static func openOrdinaryDirectory(_ url: URL) throws -> Int32 {
        try openDirectory(url)
    }

    private static func openDirectory(_ url: URL) throws -> Int32 {
        var current = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard current >= 0 else { throw ioFailure("open filesystem root") }
        do {
            for part in url.pathComponents where part != "/" {
                guard part != ".", part != "..", !part.contains("\0") else {
                    throw RegenerationError.invalidPath("invalid directory component")
                }
                let next = openat(current, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw ioFailure("open ordinary parent directory") }
                close(current); current = next
            }
            return current
        } catch { close(current); throw error }
    }

    private static func requireSameDirectory(_ url: URL, descriptor: Int32) throws {
        let pathFD = try openDirectory(url)
        defer { close(pathFD) }
        var before = stat(), after = stat()
        guard fstat(descriptor, &before) == 0, fstat(pathFD, &after) == 0,
              before.st_dev == after.st_dev, before.st_ino == after.st_ino else {
            throw RegenerationError.invalidPath("directory identity changed during export")
        }
    }

    private static func write(_ data: Data, relative: String, root: Int32) throws {
        let components = relative.split(separator: "/").map(String.init)
        var directory = dup(root)
        guard directory >= 0 else { throw ioFailure("duplicate directory") }
        defer { close(directory) }
        for part in components.dropLast() {
            if mkdirat(directory, part, 0o700) != 0, errno != EEXIST { throw ioFailure("create output directory") }
            let next = openat(directory, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { throw ioFailure("open output directory") }
            close(directory); directory = next
        }
        guard let name = components.last else { throw RegenerationError.invalidPath("empty output name") }
        let file = openat(directory, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw ioFailure("create output file") }
        defer { close(file) }
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                guard let start = buffer.baseAddress else { break }
                let written = Darwin.write(file, start.advanced(by: offset), buffer.count - offset)
                if written < 0, errno == EINTR { continue }
                guard written > 0 else { throw ioFailure("write output") }
                offset += written
            }
        }
    }

    private static func validateTree(_ directory: Int32, remaining: Int) throws {
        var budget = remaining
        try walk(directory, budget: &budget)
    }

    private static func walk(_ directory: Int32, budget: inout Int) throws {
        let duplicate = dup(directory)
        guard duplicate >= 0 else { throw ioFailure("duplicate output inventory") }
        guard let stream = fdopendir(duplicate) else { close(duplicate); throw ioFailure("read output inventory") }
        defer { closedir(stream) }
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw ioFailure("read generated output inventory") }
                break
            }
            let nameLength = Int(entry.pointee.d_namlen) + 1
            let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: nameLength) { String(cString: $0) }
            }
            if name == "." || name == ".." { continue }
            budget -= 1
            guard budget >= 0 else { throw RegenerationError.invalidInput("generated output inventory exceeds budget") }
            var status = stat()
            guard fstatat(directory, name, &status, AT_SYMLINK_NOFOLLOW) == 0 else { throw ioFailure("inspect generated output") }
            switch status.st_mode & mode_t(S_IFMT) {
            case mode_t(S_IFREG): break
            case mode_t(S_IFDIR):
                let child = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard child >= 0 else { throw ioFailure("open generated directory") }
                defer { close(child) }
                try walk(child, budget: &budget)
            default: throw RegenerationError.invalidPath("generated output contains a symlink or special file")
            }
        }
    }

    private static func ioFailure(_ operation: String) -> RegenerationError {
        .invalidPath("\(operation) failed (errno \(errno))")
    }
}
