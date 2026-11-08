import Foundation

/// Composition owns the sole manifest. Inputs are captured values; this service never reloads,
/// rehashes, or executes the target application and leaves compilation/acceptance to their evidence-owning stages.
struct RegenerationExportService {
    func prepare(input: RegenerationProjectInput, originalResources: [String: Data],
                 sourceLanguage: String, cBodies: RegenerationCBodyPacket? = nil) throws -> RegenerationRenderedProject {
        let resources = try ResourceRoundTripService().prepare(files: originalResources, sourceLanguage: sourceLanguage)
        var project = try RegenerationProjectRenderer.render(input, resources: resources.records)
        for (path, bytes) in resources.files {
            guard project.files[path] == nil else {
                throw RegenerationError.invalidInput("project/resource output collision")
            }
            project.files[path] = bytes
        }
        if let cBodies { try RegenerationCStubFill.apply(cBodies, to: &project) }
        return project
    }

    /// The caller supplies the admitted, allocated pinned generator. No build or launch occurs.
    func publish(_ project: RegenerationRenderedProject, to destination: URL,
                 generateProject: (URL) throws -> Void) throws {
        let target = RegenerationEncoding.identifier(project.manifest.applicationName)
        try RegenerationFileSystem.publish(files: project.files, to: destination) { stage in
            try generateProject(stage)
            let pbxproj = stage.appendingPathComponent(target + ".xcodeproj/project.pbxproj")
            let metadata = try pbxproj.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard metadata.isRegularFile == true, metadata.isSymbolicLink != true else {
                throw RegenerationError.toolFailed("XcodeGen did not produce the expected project")
            }
        }
    }
}
