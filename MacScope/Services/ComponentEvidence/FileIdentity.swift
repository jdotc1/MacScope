// Adapted from the AIRS component evidence core at donor commit fa5a2f3128da9134969055cebea145e2ca144214.
// Original relative path: native/Sources/AIRSCore/BatchHistory.swift (the ResumeFileIdentity value fields only).
// License: MIT, Copyright (c) 2026 Jeffrey D. Cooney; the notice is in ThirdParty/AIRS/LICENSE.
// Adaptations: built from an already-open descriptor's stat facts and exact path bytes; file mode added;
// the path-resolving capture and every batch, history and checkpoint type omitted; no hashing import.

import Darwin
import Foundation

extension ComponentEvidence {
    /// A filesystem change detector, not a content digest or an unwind identity.
    struct ResumeFileIdentity: Equatable, Sendable {
        let path: RelativePath
        let device: UInt64
        let inode: UInt64
        let mode: UInt32
        let size: Int64
        let modifiedSeconds: Int64
        let modifiedNanos: Int64
        let changedSeconds: Int64
        let changedNanos: Int64

        init(path: RelativePath, stat info: stat) {
            self.path = path
            device = UInt64(UInt32(bitPattern: info.st_dev))
            inode = info.st_ino
            mode = UInt32(info.st_mode)
            size = info.st_size
            modifiedSeconds = Int64(info.st_mtimespec.tv_sec)
            modifiedNanos = Int64(info.st_mtimespec.tv_nsec)
            changedSeconds = Int64(info.st_ctimespec.tv_sec)
            changedNanos = Int64(info.st_ctimespec.tv_nsec)
        }

        /// Device, inode, mode, size and both timestamps must all agree.
        func matches(_ info: stat) -> Bool {
            let other = ResumeFileIdentity(path: path, stat: info)
            return other == self
        }
    }

    /// Numeric physical identity. A symbolic link never shares one with its target.
    struct PhysicalFileKey: Hashable, Comparable, Sendable {
        let device: UInt64
        let inode: UInt64
        init(_ info: stat) { device = UInt64(UInt32(bitPattern: info.st_dev)); inode = info.st_ino }
        static func < (lhs: Self, rhs: Self) -> Bool { (lhs.device, lhs.inode) < (rhs.device, rhs.inode) }
    }
}
