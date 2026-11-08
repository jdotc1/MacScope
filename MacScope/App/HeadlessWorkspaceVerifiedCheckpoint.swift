import Darwin
import Foundation

/// VA4 slice D: the `verified-checkpoint` headless action. It opens the saved `.mscope` package
/// through the production reader in THIS process and judges it against a JSON expectation.
/// It never opens a store or session and never writes into the package; the only file it writes
/// is `result.json` in the new output directory. Only `.mscope` packages are admitted by
/// `Request.decode`; a raw-binary replay is override-only and carries no verified claim.
@MainActor
enum HeadlessWorkspaceVerifiedCheckpoint {
    static func run(_ request: HeadlessWorkspaceAcceptance.Request) throws -> ScriptValue {
        guard let expectationURL = request.expectation else {
            throw HeadlessWorkspaceAcceptance.Failure(description: "invalid-headless-workspace-expectation")
        }
        let report: VerifiedCheckpointReport
        let reader = VerifiedCheckpointReaderIdentity(
            installationID: UUID(), processID: ProcessInfo.processInfo.processIdentifier,
            executable: Bundle.main.executableURL?.path ?? "unknown")
        do {
            let expectation = try VerifiedCheckpointExpectation.decode(
                try boundedRead(expectationURL, maximumBytes: VerifiedCheckpointBounds.maximumRequestFileBytes))
            report = VerifiedCheckpoint.run(packageURL: request.workspace, expectation: expectation, reader: reader)
        } catch let invalid as VerifiedCheckpointInvalid {
            report = .failed(.expectationInvalid(reason: invalid.reason), reader: reader)
        } catch {
            report = .failed(.expectationInvalid(reason: "expectation-unreadable"), reader: reader)
        }
        guard case var .object(fields) = report.jsonValue() else {
            throw HeadlessWorkspaceAcceptance.Failure(description: "verified-checkpoint-report-shape")
        }
        fields["action"] = .string(request.action)
        fields["workspace"] = .string(request.workspace.path)
        fields["executable"] = .string(reader.executable)
        let result = ScriptValue.object(fields)
        try result.jsonData().write(to: request.output.appendingPathComponent("result.json"), options: .atomic)
        guard report.passed else {
            throw HeadlessWorkspaceAcceptance.Failure(description: "verified-checkpoint-not-passed")
        }
        return result
    }

    private static func boundedRead(_ url: URL, maximumBytes: Int) throws -> Data {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: maximumBytes + 1) ?? Data()
        guard data.count <= maximumBytes else { throw VerifiedCheckpointInvalid(reason: "expectation-too-large") }
        return data
    }
}
