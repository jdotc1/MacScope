import Darwin
import Foundation

/// Metadata bound to the original disk read, reused without hashing accepted bytes again.
struct NativeExecutionFileStamp: Codable, Hashable, Sendable {
    let canonicalPath: String
    let device: UInt64
    let inode: UInt64
    let byteCount: UInt64
    let modifiedSeconds: Int64
    let modifiedNanoseconds: Int64
    let changedSeconds: Int64
    let changedNanoseconds: Int64

    static func capture(path: String) -> Self? {
        let canonical = URL(fileURLWithPath: path).resolvingSymlinksInPath().path
        let fd = Darwin.open(canonical, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { Darwin.close(fd) }
        var info = stat()
        guard Darwin.fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_size > 0, (info.st_mode & (S_ISUID | S_ISGID)) == 0 else { return nil }
        return Self(canonicalPath: canonical, device: UInt64(bitPattern: Int64(info.st_dev)), inode: UInt64(info.st_ino),
                    byteCount: UInt64(info.st_size), modifiedSeconds: Int64(info.st_mtimespec.tv_sec),
                    modifiedNanoseconds: Int64(info.st_mtimespec.tv_nsec),
                    changedSeconds: Int64(info.st_ctimespec.tv_sec), changedNanoseconds: Int64(info.st_ctimespec.tv_nsec))
    }
}
