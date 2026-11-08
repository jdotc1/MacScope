import Foundation
import ExternalMCP
import NetworkEvidenceCore

extension ProxymanAdapter {
    func prepareExperiment(action: ProxymanExperimentAction, scope: ProxymanReadScope, now: Date) async throws -> PreparedProxymanExperiment {
        guard let components = URLComponents(string: action.endpoint),
              let host = components.host.flatMap(ProxymanMinimizer.canonicalHost), scope.allowedHosts.contains(host),
              ["http", "https"].contains(components.scheme?.lowercased() ?? ""),
              components.user == nil, components.password == nil, components.query == nil, components.fragment == nil,
              components.port.map({ (1...65535).contains($0) }) ?? true,
              experimentPortIsValid(action.endpoint),
              action.endpoint.utf8.count <= 1024,
              !action.endpoint.contains(where: { "*[]{}^$|\\".contains($0) }),
              !components.path.contains(":redacted"), !components.path.contains(":unavailable"),
              ProxymanNormalization.isHTTPMethod(action.method), action.method != "ANY",
              ProxymanPrivacy.minimizedPath(components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath)
                == (components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath),
              now >= scope.start, now < scope.end else { throw ProxymanExperimentError.invalidTarget }
        let lease = try await bind(scope)
        guard let tool = descriptor(action.tool), let properties = tool.inputSchema.pObject?["properties"]?.pObject,
              ["url", "method", "include_paths", "action"].allSatisfy({ properties[$0] != nil }),
              let actionSchema = properties["action"],
              ProxymanSchemaValidator.supports(.string("block"), schema: actionSchema) else {
            throw ProxymanAdapterError.schemaIncompatible("literalMutationProfile")
        }
        var arguments: [String: MCPJSONValue] = ["url": .string(action.endpoint), "method": .string(action.method),
            "include_paths": .bool(false), "action": .string("block")]
        if let regexSchema = properties["use_regex"] {
            guard ProxymanSchemaValidator.supports(.bool(false), schema: regexSchema) else {
                throw ProxymanAdapterError.schemaIncompatible("literalMutationProfile")
            }
            arguments["use_regex"] = .bool(false)
        }
        let args: MCPJSONValue = .object(arguments)
        try ProxymanSchemaValidator.validate(args, against: tool.inputSchema, tool: action.tool)
        guard let inventory = descriptor("list_rules") else { throw ProxymanAdapterError.unsupportedCapability("rules") }
        let before = try await read("list_rules", arguments: ruleArguments(inventory), lease: lease)
        let previousIDs = Set(try ProxymanNormalization.rules(before).map(\.id))
        try await recheck(lease)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(args)
        guard let json = String(data: data, encoding: .utf8) else { throw ProxymanAdapterError.schemaIncompatible(action.tool) }
        let proposal = ProxymanExperimentProposal(id: UUID(), scopeID: scope.authorityID, connectionID: lease.connectionID,
            action: action, toolName: action.tool, argumentsJSON: json, argumentsSHA256: try ProxymanDigest.json(args), schemaDigest: tool.schemaDigest,
            createdAt: now, expiresAt: min(now.addingTimeInterval(ProxymanExperimentPolicy.lifetime), scope.end),
            expectedEffect: "Block the explicitly selected test endpoint and method; other endpoints must remain unaffected.",
            verificationPlan: "Re-list the created rule, then generate a new isolated test request and a nearby negative request. Rule inventory alone does not prove traffic effects. Verify the installed vendor matching semantics.",
            cleanupPlan: "In Proxyman, disable or delete only the newly created rule identified by the execution record, then verify fresh matching traffic is restored. No automatic cleanup or timer is promised.")
        return .init(proposal: proposal, lease: lease, arguments: args, schemaDigest: tool.schemaDigest, previousRuleIDs: previousIDs)
    }

    func executeExperiment(_ prepared: PreparedProxymanExperiment, now: Date,
                           authorizeDispatch: @Sendable () async -> Bool,
                           recordIntent: @Sendable () async throws -> Void) async throws -> ProxymanExperimentRecord {
        try await recheck(prepared.lease)
        guard prepared.proposal.expiresAt > now,
              ProxymanExperimentPolicy.permits(tool: prepared.proposal.toolName),
              ProxymanToolPolicy.reviewedMutations.contains(prepared.proposal.toolName),
              let tool = descriptor(prepared.proposal.toolName), tool.schemaDigest == prepared.schemaDigest,
              try ProxymanDigest.json(prepared.arguments) == prepared.proposal.argumentsSHA256 else {
            throw ProxymanExperimentError.invalidReview
        }
        try ProxymanSchemaValidator.validate(prepared.arguments, against: tool.inputSchema, tool: tool.name)
        guard await authorizeDispatch() else { throw ProxymanExperimentError.invalidReview }
        try checkCancellation()
        do { try await recordIntent() }
        catch { throw ProxymanExperimentError.auditUnavailable }
        let result: MCPToolOutcome
        do { result = try await client.invoke(tool: tool.name, arguments: prepared.arguments) }
        catch { return experimentRecord(prepared, now: now, verification: .outcomeUnknown, code: "mutationResultUnavailable") }
        var createdRuleID: String?
        do {
            try await recheck(prepared.lease)
            guard result.connectionID == prepared.lease.connectionID, result.toolName == tool.name else { throw ProxymanAdapterError.staleReference }
            let payload = try ProxymanNormalization.payload(result)
            guard let object = payload.pObject else { return experimentRecord(prepared, now: now, verification: .outcomeUnknown, code: "mutationEnvelopeUnsupported") }
            let rule = object["rule"]?.pObject ?? object
            let id = ProxymanMinimizer.identifier(rule.first(["id", "rule_id", "ruleId"]))
            createdRuleID = id
            guard let id, !prepared.previousRuleIDs.contains(id), let inventory = descriptor("list_rules") else {
                return experimentRecord(prepared, now: now, id: id, verification: .unverified, code: "createdRuleIdentityUnverified")
            }
            let after = try await read("list_rules", arguments: ruleArguments(inventory), lease: prepared.lease)
            let listed = try ProxymanNormalization.rules(after).contains {
                $0.id == id && $0.kind == prepared.proposal.action.kind && $0.enabled == .yes
                    && $0.host == URLComponents(string: prepared.proposal.action.endpoint)?.host.flatMap(ProxymanMinimizer.canonicalHost)
            }
            return experimentRecord(prepared, now: now, id: id, verification: listed ? .ruleListed : .unverified,
                code: listed ? nil : "ruleVerificationIncomplete")
        } catch {
            // The mutation may already have occurred. Do not retry or claim it was rolled back.
            return experimentRecord(prepared, now: now, id: createdRuleID, verification: .outcomeUnknown, code: "postMutationVerificationUnavailable")
        }
    }

    func cleanupState(record: ProxymanExperimentRecord, scope: ProxymanReadScope) async throws -> ProxymanExperimentCleanupState {
        guard record.scopeID == scope.authorityID else { throw ProxymanExperimentError.invalidReview }
        guard ProxymanExperimentPolicy.permits(tool: record.toolName) else { throw ProxymanExperimentError.invalidReview }
        guard let id = record.createdRuleID else { return .unverifiable }
        let lease = try await bind(scope)
        guard let inventory = descriptor("list_rules") else { throw ProxymanAdapterError.unsupportedCapability("rules") }
        let payload = try await read("list_rules", arguments: ruleArguments(inventory), lease: lease)
        let rules = try ProxymanNormalization.rules(payload)
        guard let rule = rules.first(where: { $0.id == id }) else { return .ruleRemoved }
        let host = URLComponents(string: record.action.endpoint)?.host.flatMap(ProxymanMinimizer.canonicalHost)
        guard rule.kind == "blacklist", rule.host == host else { return .unverifiable }
        switch rule.enabled {
        case .yes: return .ruleStillActive
        case .no: return .ruleDisabled
        case .unknown: return .unverifiable
        }
    }

    private func experimentPortIsValid(_ endpoint: String) -> Bool {
        guard let scheme = endpoint.range(of: "://") else { return false }
        let authority = endpoint[scheme.upperBound...].prefix { $0 != "/" }
        guard let colon = authority.firstIndex(of: ":") else { return true }
        let port = authority[authority.index(after: colon)...]
        guard (1...5).contains(port.utf8.count),
              port.utf8.allSatisfy({ (48...57).contains($0) }),
              let value = Int(port), (1...65535).contains(value) else { return false }
        return true
    }

    private func experimentRecord(_ prepared: PreparedProxymanExperiment, now: Date, id: String? = nil,
                                  verification: ProxymanExperimentVerification, code: String?) -> ProxymanExperimentRecord {
        .init(proposalID: prepared.proposal.id, action: prepared.proposal.action,
            toolName: prepared.proposal.toolName, connectionID: prepared.proposal.connectionID,
            scopeID: prepared.proposal.scopeID, argumentsJSON: prepared.proposal.argumentsJSON,
            argumentsSHA256: prepared.proposal.argumentsSHA256, schemaDigest: prepared.schemaDigest,
            executedAt: now, createdRuleID: id, verification: verification,
            cleanupInstructions: prepared.proposal.cleanupPlan, diagnosticCode: code)
    }
}
