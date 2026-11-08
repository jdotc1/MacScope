// Adapted from the AIRS component evidence core at donor commit fa5a2f3128da9134969055cebea145e2ca144214.
// Original relative path: native/Sources/AIRSCore/ComponentLoadDeclaration.swift.
// License: MIT, Copyright (c) 2026 Jeffrey D. Cooney; the notice is in ThirdParty/AIRS/LICENSE.
// Adaptations: internal access; exact architecture and path bytes; a command enum with the donor's fixed names;
// no Codable and no public or archive API commitment.

import Foundation

extension ComponentEvidence {
    /// One ordered load-command declaration row of one slice.
    struct ComponentLoadDeclaration: Sendable, Equatable {
        /// Donor-fixed command names, in the order they appear in the payload field `command`.
        enum Command: String, Sendable, Equatable, CaseIterable {
            case load, weak, reexport, upward, lazy, installName, rpath
        }
        let architecture: ExactUTF8Key
        let command: Command
        let path: ExactUTF8Key
        let currentVersion: String?
        let compatibilityVersion: String?
        let useFlags: UInt32?

        init(architecture: ExactUTF8Key, command: Command, path: ExactUTF8Key, currentVersion: String? = nil,
             compatibilityVersion: String? = nil, useFlags: UInt32? = nil) {
            self.architecture = architecture
            self.command = command
            self.path = path
            self.currentVersion = currentVersion
            self.compatibilityVersion = compatibilityVersion
            self.useFlags = useFlags
        }
    }
}
