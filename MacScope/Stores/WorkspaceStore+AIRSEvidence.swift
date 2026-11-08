import Foundation

extension WorkspaceStore {
    static func validateAIRSEvidencePayloads(_ envelope: AIRSEvidenceEnvelope, workspaceID: UUID) throws {
        try envelope.validate(workspaceID: workspaceID)
        for record in envelope.records {
            switch record.source {
            case .nativeUnwind:
                _ = try JSONDecoder().decode(UnwindAuditReport.self, from: record.rawPayload)
            case .importedHandoff:
                _ = try AIRSHandoffImport.parse(record.rawPayload)
            }
        }
    }

    func persistableAIRSEvidence() throws -> AIRSEvidenceEnvelope? {
        try Self.validateAIRSEvidencePayloads(airsEvidence, workspaceID: workspaceID)
        return airsEvidence.records.isEmpty ? nil : airsEvidence
    }

    @discardableResult
    func retainAIRSHandoff(_ handoff: AIRSHandoffImport, now: Date = Date()) throws -> UUID {
        let candidates = snapshot.binaries.filter { (try? handoff.destinationAddress(binary: $0)) != nil }
        let record = AIRSEvidenceRecord(id: UUID(), workspaceID: workspaceID,
            source: .importedHandoff, sourceImageID: candidates.count == 1 ? candidates.first?.id : nil,
            nativeRequestID: nil, createdAt: now, rawPayload: handoff.rawPayload)
        try retainAIRSEvidence(record)
        return record.id
    }

    /// Called synchronously only after the coordinator accepts a publication. The request
    /// supplies original lineage; current focus is never used to label a completed report.
    @discardableResult
    func retainNativeAIRSEvidence(
        _ report: UnwindAuditReport, request: UnwindAuditRequest
    ) -> Result<AIRSEvidenceRecord, Error> {
        do {
            try report.validate()
            guard report.identity == request.key.identity,
                  report.analysisModelVersion == request.key.modelID,
                  report.configuration == request.key.configuration else { throw AIRSEvidenceError.invalidRecord }
            if let existing = airsEvidence.records.first(where: { $0.nativeRequestID == request.id }) {
                guard existing.workspaceID == workspaceID, existing.source == .nativeUnwind,
                      existing.sourceImageID == request.key.imageID,
                      let retainedReport = try? JSONDecoder().decode(UnwindAuditReport.self, from: existing.rawPayload),
                      retainedReport == report else { throw AIRSEvidenceError.invalidRecord }
                airsEvidenceRetentionError = nil
                return .success(existing)
            }
            let record = AIRSEvidenceRecord(id: UUID(), workspaceID: workspaceID,
                source: .nativeUnwind, sourceImageID: request.key.imageID,
                nativeRequestID: request.id, createdAt: Date(), rawPayload: try JSONEncoder().encode(report))
            try retainAIRSEvidence(record)
            return .success(record)
        } catch {
            airsEvidenceRetentionError = error.localizedDescription
            return .failure(error)
        }
    }

    private func retainAIRSEvidence(_ record: AIRSEvidenceRecord) throws {
        do {
            var updated = airsEvidence
            try updated.append(record, workspaceID: workspaceID)
            try Self.validateAIRSEvidencePayloads(updated, workspaceID: workspaceID)
            airsEvidence = updated
            airsEvidenceRetentionError = nil
            markDocumentMutated()
        } catch {
            airsEvidenceRetentionError = error.localizedDescription
            throw error
        }
    }

    func airsEvidenceBinding(_ record: AIRSEvidenceRecord) -> AIRSEvidenceBinding {
        guard record.workspaceID == workspaceID else {
            return .init(binary: nil, unresolvedReason: "Evidence belongs to another workspace.")
        }
        let candidates = snapshot.binaries.filter { record.sourceImageID == nil || $0.id == record.sourceImageID }
        let matches = candidates.filter { binary in
            guard binary.artifactIntegrityState == .verified else { return false }
            switch record.source {
            case .importedHandoff:
                guard let handoff = try? AIRSHandoffImport.parse(record.rawPayload) else { return false }
                return (try? handoff.destinationAddress(binary: binary)) != nil
            case .nativeUnwind:
                guard let report = try? JSONDecoder().decode(UnwindAuditReport.self, from: record.rawPayload),
                      binary.artifactIdentity == report.identity,
                      let layout = binary.preferredSegmentLayout else { return false }
                return report.findings.allSatisfy { finding in
                    layout.records.contains { segment in
                        let end = segment.preferredVMStart.addingReportingOverflow(min(segment.preferredVMSize, segment.fileSize))
                        return segment.initialProtections & 4 != 0 && !end.overflow
                            && segment.preferredVMStart <= finding.function.address
                            && finding.endAddress <= end.partialValue
                    }
                }
            }
        }
        guard matches.count == 1, let binary = matches.first else {
            return .init(binary: nil, unresolvedReason: matches.count > 1
                ? "Multiple images match this evidence. Binding is unresolved."
                : "The source image is absent, unverified, or has a different slice identity or address mapping.")
        }
        return .init(binary: binary, unresolvedReason: nil)
    }

    func airsEvidenceSummary(_ record: AIRSEvidenceRecord) -> String {
        switch record.source {
        case .nativeUnwind:
            guard let report = try? JSONDecoder().decode(UnwindAuditReport.self, from: record.rawPayload) else { return "Invalid native evidence" }
            return "Native · \(report.findings.count) functions · \(report.analysisModelVersion)"
        case .importedHandoff:
            guard let handoff = try? AIRSHandoffImport.parse(record.rawPayload) else { return "Invalid imported evidence" }
            return "Imported · \(handoff.name) · \(handoff.verdict) · \(handoff.model)"
        }
    }

    func airsEvidenceDetails(_ record: AIRSEvidenceRecord) -> String {
        switch record.source {
        case .nativeUnwind:
            guard let report = try? JSONDecoder().decode(UnwindAuditReport.self, from: record.rawPayload) else { return "Invalid native evidence" }
            var lines = [
                "Native MacScope audit · request \(record.nativeRequestID?.uuidString ?? "unavailable")",
                "Slice \(report.identity.selectedSliceSHA256) · \(report.identity.selectedSliceByteCount) bytes",
                "Model \(report.analysisModelVersion) · \(report.identity.architectureVariant.rawValue) · CPU subtype \(report.identity.rawCPUSubtype)",
                "Limits: \(report.configuration.maxInstructions) instructions, \(report.configuration.maxSteps) steps, \(report.configuration.maxPaths) paths, \(report.configuration.maxObservations) observations, \(report.configuration.maxEvidence) evidence items"
            ]
            for finding in report.findings {
                lines.append("0x\(String(finding.function.address, radix: 16)): \(finding.verdict) · \(finding.coverage) · \(finding.scope)")
                lines.append("Reasons: " + finding.reasonCodes.joined(separator: ", "))
                for evidence in finding.evidence {
                    let address = evidence.address.map { " @ 0x" + String($0, radix: 16) } ?? ""
                    lines.append("\(evidence.code)\(address): \(evidence.message)")
                    if let expected = evidence.expected { lines.append("Expected: " + expected) }
                    if let observed = evidence.observed { lines.append("Observed: " + observed) }
                }
                lines.append("Checked PCs: " + finding.checkedPCs.map { "0x" + String($0, radix: 16) }.joined(separator: ", "))
                lines.append(contentsOf: finding.limitations)
            }
            return lines.joined(separator: "\n")
        case .importedHandoff:
            // Display original source text; decoding or formatting never replaces retained bytes.
            return String(data: record.rawPayload, encoding: .utf8) ?? "Imported source is not UTF-8 text."
        }
    }

    func airsEvidenceCanNavigate(_ record: AIRSEvidenceRecord) -> Bool {
        guard let binary = airsEvidenceBinding(record).binary else { return false }
        let address: UInt64
        switch record.source {
        case .nativeUnwind:
            guard let report = try? JSONDecoder().decode(UnwindAuditReport.self, from: record.rawPayload),
                  let first = report.findings.min(by: { $0.function.address < $1.function.address }) else { return false }
            address = first.function.address
        case .importedHandoff:
            guard let handoff = try? AIRSHandoffImport.parse(record.rawPayload),
                  let destination = try? handoff.destinationAddress(binary: binary) else { return false }
            address = destination
        }
        return snapshot.containsLoadedAddress(address, in: binary.slot)
    }

    @discardableResult
    func navigateToAIRSEvidence(_ record: AIRSEvidenceRecord) -> Bool {
        guard airsEvidence.records.contains(record), let binary = airsEvidenceBinding(record).binary else { return false }
        let address: UInt64
        switch record.source {
        case .importedHandoff:
            guard let handoff = try? AIRSHandoffImport.parse(record.rawPayload),
                  let destination = try? handoff.destinationAddress(binary: binary) else { return false }
            address = destination
        case .nativeUnwind:
            guard let report = try? JSONDecoder().decode(UnwindAuditReport.self, from: record.rawPayload),
                  let finding = report.findings.sorted(by: { $0.function.address < $1.function.address }).first else { return false }
            address = finding.function.address
        }
        guard snapshot.containsLoadedAddress(address, in: binary.slot) else { return false }
        focusImage(binary.slot)
        guard focusedBinary?.id == binary.id,
              selectAddress(ImageAddress(slot: binary.slot, address: address)),
              AIRSHandoffPresenter.selectionReadback(store: self, imageID: binary.id, address: address) else { return false }
        showMachOMetadata = false
        return true
    }
}
