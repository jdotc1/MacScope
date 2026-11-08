import Foundation
import Security
import XCTest

@testable import MacScope

final class PluginXPCPeerRequirementTests: XCTestCase {
    func testPeerRequirementsCompileAndBindFrozenIdentifiers() throws {
        XCTAssertEqual(
            PluginXPCPeerRequirement.app,
            "identifier \"com.jeff.machscope\" and "
                + "anchor apple generic and certificate leaf[subject.CN] = "
                + "\"Apple Development: Example Developer (CERTID0000)\" and "
                + "certificate leaf[subject.OU] = \"TEAMID0000\" and "
                + "certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */"
        )
        XCTAssertEqual(
            PluginXPCPeerRequirement.service,
            "identifier \"com.jeff.machscope.PluginXPCService\" and "
                + "anchor apple generic and certificate leaf[subject.CN] = "
                + "\"Apple Development: Example Developer (CERTID0000)\" and "
                + "certificate leaf[subject.OU] = \"TEAMID0000\" and "
                + "certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */"
        )

        try assertCompiles(PluginXPCPeerRequirement.app)
        try assertCompiles(PluginXPCPeerRequirement.service)
    }

    func testListenerAdmissionInstallsAppRequirementBeforeExportsAndResume() {
        var events: [String] = []

        PluginXPCListenerAdmission.accept(
            installRequirement: { events.append("requirement:\($0)") },
            exportInterface: { events.append("interface") },
            exportObject: { events.append("object") },
            resume: { events.append("resume") }
        )

        XCTAssertEqual(
            events,
            [
                "requirement:\(PluginXPCPeerRequirement.app)",
                "interface",
                "object",
                "resume",
            ]
        )
    }

    private func assertCompiles(_ expression: String) throws {
        var requirement: SecRequirement?
        let status = SecRequirementCreateWithString(expression as CFString, [], &requirement)
        XCTAssertEqual(status, errSecSuccess, "requirement must compile: \(expression)")
        XCTAssertNotNil(requirement)
    }
}
