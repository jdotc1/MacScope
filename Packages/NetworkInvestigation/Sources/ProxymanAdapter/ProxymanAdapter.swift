import Foundation
import ExternalMCP
import NetworkEvidenceCore

public actor ProxymanAdapter: ProxymanInvestigating {
    let client: any ExternalMCPClient
    let clock: @Sendable () -> Date
    private let maximumAnchors: Int
    private var catalog: [String: MCPToolDescriptor] = [:]
    private var catalogConnectionID: UUID?
    private var catalogRevision: UInt64 = 0
    private var scopes: [UUID: ScopeBinding] = [:]
    private var revokedScopes: Set<UUID> = []
    private var revocationCapacityExhausted = false
    private var anchors: [NetworkFlowReference: NetworkFlowSummary] = [:]
    private var anchorOrder: [NetworkFlowReference] = []

    struct ScopeBinding { let scope: ProxymanReadScope; let connectionID: UUID }
    struct ScopeLease: Sendable {
        let scope: ProxymanReadScope
        let connectionID: UUID
        let catalogRevision: UInt64
    }

    public init(client: any ExternalMCPClient, now: @escaping @Sendable () -> Date = { Date() }, maximumAnchors: Int = 2048) {
        self.client = client; self.clock = now
        self.maximumAnchors = max(1, min(4096, maximumAnchors))
    }

    public func capabilities() async throws -> ProxymanCapabilities {
        let state = try await refreshCatalog()
        guard let id = state.connectionID else { throw ProxymanAdapterError.notConnected }
        let supported = Set(ProxymanCapability.allCases.filter { supports($0) })
        let unknown = catalog.keys.filter { ProxymanToolPolicy.classification(of: $0) == .deniedUnknown }.count
        let latest = await client.snapshot()
        guard latest.state == .connected, latest.connectionID == id,
              latest.toolCatalogRevision == state.toolCatalogRevision else { throw ProxymanAdapterError.staleReference }
        try checkCancellation()
        return .init(connectionID: id, supported: supported,
            unavailable: ProxymanCapability.allCases.filter { !supported.contains($0) }, unknownToolCount: unknown)
    }

    public func status(scope: ProxymanReadScope) async throws -> ProxymanEnvironmentStatus {
        let lease = try await bind(scope)
        var version: String?
        var build: String?
        if supports(.version) {
            let response = try await read("get_version", arguments: .object([:]), lease: lease)
            guard let object = response.pObject else { throw ProxymanAdapterError.malformedResponse("versionEnvelope") }
            version = ProxymanMinimizer.version(object.first(["version", "app_version", "appVersion"]))
            build = ProxymanMinimizer.version(object.first(["build", "build_number", "buildNumber"]))
        }
        guard supports(.proxyStatus) else { throw ProxymanAdapterError.unsupportedCapability("proxyStatus") }
        let proxy = try await read("get_proxy_status", arguments: .object([:]), lease: lease)
        guard let object = proxy.pObject else { throw ProxymanAdapterError.malformedResponse("proxyStatusEnvelope") }
        let recording = object.first(["recording", "is_recording", "isRecording"])?.pBool
        var ssl = object.first(["ssl_proxying_enabled", "sslProxyingEnabled", "isSSLProxyingEnabled"])?.pBool
        if supports(.sslStatus) {
            let payload = try await read("get_ssl_proxying_list", arguments: .object([:]), lease: lease)
            guard let object = payload.pObject else { throw ProxymanAdapterError.malformedResponse("sslStatusEnvelope") }
            ssl = object.first(["enabled", "isEnabled", "ssl_proxying_enabled"])?.pBool ?? ssl
        }
        var trusted: Bool?
        if supports(.certificateStatus) {
            let payload = try await read("get_certificate_status", arguments: .object([:]), lease: lease)
            guard let object = payload.pObject else { throw ProxymanAdapterError.malformedResponse("certificateEnvelope") }
            trusted = object.first(["trusted", "is_trusted", "isTrusted"])?.pBool
        }
        try await recheck(lease)
        return .init(connectionID: lease.connectionID, observedAt: clock(), version: version, build: build,
            recording: recording.map { $0 ? .recording : .stopped } ?? .unknown,
            sslProxying: ssl.map { $0 ? .yes : .no } ?? .unknown,
            certificateTrusted: trusted.map { $0 ? .yes : .no } ?? .unknown,
            limitations: [.captureSessionIdentityUnavailable, .archiveVisibilityUnverified])
    }

    public func findFlows(query: ProxymanFlowQuery, scope: ProxymanReadScope) async throws -> ProxymanFlowBatch {
        try validate(query, scope: scope)
        let lease = try await bind(scope)
        guard supports(.flows), let descriptor = catalog["get_flows"] else {
            throw ProxymanAdapterError.unsupportedCapability("flows")
        }
        let properties = descriptor.inputSchema.pObject?["properties"]?.pObject ?? [:]
        if let pid = query.processID {
            guard let schema = properties["pid_filter"],
                  ProxymanSchemaValidator.supports(.int(pid), schema: schema) else {
                throw ProxymanAdapterError.schemaIncompatible("get_flows")
            }
        }
        let id = UUID()
        let observedAt = clock()
        let hosts = query.host.map { [$0] } ?? scope.allowedHosts.sorted()
        var rows: [ProxymanParsedFlow] = []
        var seenIdentities: [String: String] = [:]
        var limitReached = false
        var totalFetched = 0
        // Total vendor results, including post-filter rejections, never exceed the scope cap.
        for host in hosts {
            let remaining = min(query.limit - rows.count, scope.maximumFlows - totalFetched)
            if remaining <= 0 { limitReached = true; break }
            var arguments: [String: MCPJSONValue] = ["limit": .int(remaining), "host_filter": .string(host)]
            if let pid = query.processID { arguments["pid_filter"] = .int(pid) }
            if let method = query.method, properties["method_filter"] != nil { arguments["method_filter"] = .string(method) }
            if let status = query.statusCode, let schema = properties["status_filter"] {
                if ProxymanSchemaValidator.supports(.int(status), schema: schema) { arguments["status_filter"] = .int(status) }
                else if ProxymanSchemaValidator.supports(.string(String(status)), schema: schema) { arguments["status_filter"] = .string(String(status)) }
                else { throw ProxymanAdapterError.schemaIncompatible("get_flows") }
            }
            let result = try await read("get_flows", arguments: .object(arguments), lease: lease)
            let values = try ProxymanNormalization.flows(result, maximum: remaining)
            totalFetched += values.count
            if values.count == remaining { limitReached = true }
            for value in values {
                let parsed = try ProxymanNormalization.flow(value, connectionID: lease.connectionID,
                    batchID: id, scope: scope, observedAt: observedAt)
                let summary = parsed.summary
                guard scope.allowedHosts.contains(summary.host), summary.host == host,
                      summary.requestTime >= scope.start, summary.requestTime <= scope.end,
                      query.method.map({ $0 == summary.method }) ?? true,
                      query.statusCode.map({ $0 == summary.statusCode }) ?? true,
                      !query.onlyErrors || summary.statusCode.map({ $0 >= 400 }) == true,
                      query.pathContains.map({ parsed.rawPath.contains($0) }) ?? true,
                      query.clientName.map({ $0 == parsed.rawSourceName }) ?? true,
                      query.processID.map({ requested in
                          if case .vendorReported(_, let pid) = summary.source { return pid == requested }
                          return false
                      }) ?? true else { continue }
                if let prior = seenIdentities[summary.reference.vendorFlowID] {
                    guard prior == summary.reference.identityDigest else {
                        throw ProxymanAdapterError.malformedResponse("duplicateFlowIdentity")
                    }
                } else {
                    seenIdentities[summary.reference.vendorFlowID] = summary.reference.identityDigest
                    rows.append(parsed)
                }
            }
        }
        try await recheck(lease)
        let ordered = rows.map(\.summary).sorted {
            if $0.requestTime != $1.requestTime { return $0.requestTime > $1.requestTime }
            return $0.reference.vendorFlowID < $1.reference.vendorFlowID
        }
        for summary in ordered { remember(summary) }
        var limitations: [NetworkObservationLimitation] = [.boundedSnapshot, .filtersAppliedLocally,
            .captureSessionIdentityUnavailable, .sourceAttributionUnverified, .sensitiveContentOmitted,
            .archiveVisibilityUnverified]
        if limitReached { limitations.append(.limitReached) }
        if ordered.contains(where: { $0.tlsVisibility == .unknown }) { limitations.append(.tlsVisibilityUnknown) }
        if ordered.contains(where: { $0.ruleInfluence == .unknown }) { limitations.append(.ruleInfluenceUnknown) }
        return .init(id: id, connectionID: lease.connectionID, observedAt: observedAt,
            flows: ordered, limitations: limitations)
    }

    public func inspectFlow(reference: NetworkFlowReference, scope: ProxymanReadScope) async throws -> NetworkFlowDetail {
        let lease = try await bind(scope)
        guard reference.scopeID == scope.authorityID else { throw ProxymanAdapterError.scopeMismatch }
        guard reference.connectionID == lease.connectionID, anchors[reference] != nil else {
            throw ProxymanAdapterError.staleReference
        }
        guard let descriptor = catalog["get_flow_detail"] else { throw ProxymanAdapterError.unsupportedCapability("flowDetail") }
        let arguments = try detailArguments(id: reference.vendorFlowID, descriptor: descriptor)
        let result = try await read("get_flow_detail", arguments: arguments, lease: lease)
        let parsed = try ProxymanNormalization.flow(ProxymanNormalization.detailObject(result),
            connectionID: lease.connectionID, batchID: reference.batchID, scope: scope, observedAt: clock())
        try await recheck(lease)
        guard anchors[reference] != nil, parsed.summary.reference == reference,
              scope.allowedHosts.contains(parsed.summary.host),
              parsed.summary.requestTime >= scope.start, parsed.summary.requestTime <= scope.end else {
            anchors.removeValue(forKey: reference)
            anchorOrder.removeAll { $0 == reference }
            throw ProxymanAdapterError.staleReference
        }
        return .init(summary: parsed.summary, queryKeyNames: parsed.queryKeys,
            responseFieldNames: parsed.responseKeys, requestHeaderNames: parsed.requestHeaders,
            responseHeaderNames: parsed.responseHeaders,
            limitations: [.captureSessionIdentityUnavailable, .sourceAttributionUnverified,
                          .sensitiveContentOmitted, .archiveVisibilityUnverified])
    }

    public func rules(scope: ProxymanReadScope) async throws -> ProxymanRuleSnapshot {
        let lease = try await bind(scope)
        guard let descriptor = catalog["list_rules"] else { throw ProxymanAdapterError.unsupportedCapability("rules") }
        let payload = try await read("list_rules", arguments: ruleArguments(descriptor), lease: lease)
        var items = try ProxymanNormalization.rules(payload)
        for (capability, tool, kind) in [
            (ProxymanCapability.reverseProxies, "list_reverse_proxies", "reverse_proxy"),
            (.dnsRules, "list_dns_spoofing", "dns_spoofing")
        ] where supports(capability) {
            let payload = try await read(tool, arguments: .object([:]), lease: lease)
            items += try ProxymanNormalization.rules(payload, defaultKind: kind)
        }
        if supports(.toolStatus) {
            let value = try await read("list_tool_status", arguments: .object([:]), lease: lease)
            guard let object = value.pObject else { throw ProxymanAdapterError.malformedResponse("toolStatusEnvelope") }
            let states = object["tools"]?.pObject ?? object
            for (name, value) in states {
                guard let kind = ProxymanNormalization.normalizedRuleKind(name), let enabled = value.pBool else { continue }
                items.append(.init(id: "global-" + kind, kind: "global." + kind, enabled: enabled ? .yes : .no))
            }
        }
        if supports(.externalProxy) {
            let value = try await read("get_external_proxy", arguments: .object([:]), lease: lease)
            guard let object = value.pObject else { throw ProxymanAdapterError.malformedResponse("externalProxyEnvelope") }
            let enabled = object.first(["enabled", "isEnabled"])?.pBool
            items.append(.init(id: "external-proxy", kind: "external_proxy", enabled: enabled.map { $0 ? .yes : .no } ?? .unknown))
        }
        guard items.count <= 512 else { throw ProxymanAdapterError.responseLimitExceeded }
        try await recheck(lease)
        // Global inventory is a point-in-time snapshot, not proof of per-flow influence or
        // a guaranteed exhaustive list across changing vendor versions.
        return .init(connectionID: lease.connectionID, observedAt: clock(), rules: items,
            isComplete: false, limitations: [.ruleInfluenceUnknown, .sensitiveContentOmitted])
    }

    public func invalidate(scopeID: UUID) async {
        scopes.removeValue(forKey: scopeID)
        if revokedScopes.count < 2048 { revokedScopes.insert(scopeID) }
        else { revocationCapacityExhausted = true }
        anchors = anchors.filter { $0.key.scopeID != scopeID }
        anchorOrder.removeAll { $0.scopeID == scopeID }
    }

    private func refreshCatalog() async throws -> MCPConnectionSnapshot {
        try checkCancellation()
        let before = await client.snapshot()
        guard before.state == .connected, let connectionID = before.connectionID else {
            anchors.removeAll(); anchorOrder.removeAll()
            throw ProxymanAdapterError.notConnected
        }
        let tools: [MCPToolDescriptor]
        do { tools = try await client.discoverTools() }
        catch { try checkCancellation(); throw ProxymanAdapterError.vendorFailure("tools/list") }
        let after = await client.snapshot()
        guard after.state == .connected, after.connectionID == connectionID else { throw ProxymanAdapterError.staleReference }
        guard tools.count <= 256, Set(tools.map(\.name)).count == tools.count else { throw ProxymanAdapterError.responseLimitExceeded }
        if catalogConnectionID != connectionID || catalogRevision != after.toolCatalogRevision {
            anchors.removeAll(); anchorOrder.removeAll()
        }
        catalog = Dictionary(uniqueKeysWithValues: tools.map { ($0.name, $0) })
        catalogConnectionID = connectionID; catalogRevision = after.toolCatalogRevision
        try checkCancellation()
        return after
    }

    func bind(_ scope: ProxymanReadScope) async throws -> ScopeLease {
        try scope.validate()
        guard !revocationCapacityExhausted, !revokedScopes.contains(scope.authorityID) else { throw ProxymanAdapterError.scopeRevoked }
        let snapshot = try await refreshCatalog()
        guard let id = snapshot.connectionID else { throw ProxymanAdapterError.notConnected }
        guard !revocationCapacityExhausted, !revokedScopes.contains(scope.authorityID) else { throw ProxymanAdapterError.scopeRevoked }
        if let existing = scopes[scope.authorityID] {
            guard existing.scope == scope else { throw ProxymanAdapterError.scopeMismatch }
            guard existing.connectionID == id else { throw ProxymanAdapterError.scopeRevoked }
        } else {
            guard scopes.count < 128 else { throw ProxymanAdapterError.responseLimitExceeded }
            scopes[scope.authorityID] = .init(scope: scope, connectionID: id)
        }
        return .init(scope: scope, connectionID: id, catalogRevision: snapshot.toolCatalogRevision)
    }

    func recheck(_ lease: ScopeLease) async throws {
        try checkCancellation()
        let state = await client.snapshot()
        guard !revocationCapacityExhausted, !revokedScopes.contains(lease.scope.authorityID) else { throw ProxymanAdapterError.scopeRevoked }
        guard let active = scopes[lease.scope.authorityID], active.scope == lease.scope,
              active.connectionID == lease.connectionID else { throw ProxymanAdapterError.scopeMismatch }
        guard state.state == .connected, state.connectionID == lease.connectionID,
              state.toolCatalogRevision == lease.catalogRevision,
              catalogConnectionID == lease.connectionID, catalogRevision == lease.catalogRevision else {
            throw ProxymanAdapterError.staleReference
        }
        try checkCancellation()
    }

    func read(_ tool: String, arguments: MCPJSONValue, lease: ScopeLease) async throws -> MCPJSONValue {
        guard ProxymanToolPolicy.implementedReads.contains(tool) else { throw ProxymanAdapterError.unsupportedCapability(tool) }
        return try await call(tool, arguments: arguments, lease: lease)
    }

    func call(_ tool: String, arguments: MCPJSONValue, lease: ScopeLease) async throws -> MCPJSONValue {
        try await recheck(lease)
        guard let descriptor = catalog[tool] else { throw ProxymanAdapterError.unsupportedCapability(tool) }
        try ProxymanSchemaValidator.validate(arguments, against: descriptor.inputSchema, tool: tool)
        let result: MCPToolOutcome
        do { result = try await client.invoke(tool: tool, arguments: arguments) }
        catch { try checkCancellation(); throw ProxymanAdapterError.vendorFailure(tool) }
        try await recheck(lease)
        guard result.connectionID == lease.connectionID, result.toolName == tool else { throw ProxymanAdapterError.staleReference }
        return try ProxymanNormalization.payload(result)
    }

    func descriptor(_ tool: String) -> MCPToolDescriptor? { catalog[tool] }

    private func supports(_ capability: ProxymanCapability) -> Bool {
        let map: [ProxymanCapability: String] = [.version: "get_version", .proxyStatus: "get_proxy_status",
            .flowDetail: "get_flow_detail", .rules: "list_rules", .toolStatus: "list_tool_status",
            .sslStatus: "get_ssl_proxying_list", .certificateStatus: "get_certificate_status",
            .reverseProxies: "list_reverse_proxies", .dnsRules: "list_dns_spoofing", .externalProxy: "get_external_proxy"]
        if capability == .advancedFiltering { return false } // No verified live filter-object schema profile yet.
        if capability == .flows {
            guard let tool = catalog["get_flows"],
                  let properties = tool.inputSchema.pObject?["properties"]?.pObject,
                  properties["limit"] != nil, properties["host_filter"] != nil else { return false }
            return ProxymanSchemaValidator.supports(.object(["limit": .int(1), "host_filter": .string("example.invalid")]), schema: tool.inputSchema)
        }
        guard let name = map[capability], let tool = catalog[name] else { return false }
        if capability == .flowDetail { return (try? detailArguments(id: "1", descriptor: tool)) != nil }
        if capability == .rules { return (try? ruleArguments(tool)) != nil }
        return ProxymanSchemaValidator.supports(.object([:]), schema: tool.inputSchema)
    }

    private func detailArguments(id: String, descriptor: MCPToolDescriptor) throws -> MCPJSONValue {
        let properties = descriptor.inputSchema.pObject?["properties"]?.pObject ?? [:]
        guard let name = ["flow_id", "id"].first(where: { properties[$0] != nil }), let schema = properties[name] else {
            throw ProxymanAdapterError.schemaIncompatible("get_flow_detail")
        }
        let value: MCPJSONValue
        if ProxymanSchemaValidator.supports(.string(id), schema: schema) { value = .string(id) }
        else if let number = Int(id), number >= 0, ProxymanSchemaValidator.supports(.int(number), schema: schema) { value = .int(number) }
        else { throw ProxymanAdapterError.schemaIncompatible("get_flow_detail") }
        let result: MCPJSONValue = .object([name: value])
        try ProxymanSchemaValidator.validate(result, against: descriptor.inputSchema, tool: "get_flow_detail")
        return result
    }

    func ruleArguments(_ descriptor: MCPToolDescriptor) throws -> MCPJSONValue {
        if ProxymanSchemaValidator.supports(.object([:]), schema: descriptor.inputSchema) { return .object([:]) }
        let properties = descriptor.inputSchema.pObject?["properties"]?.pObject ?? [:]
        for name in ["rule_type", "type"] where properties[name] != nil {
            let result: MCPJSONValue = .object([name: .string("all")])
            if ProxymanSchemaValidator.supports(result, schema: descriptor.inputSchema) { return result }
        }
        throw ProxymanAdapterError.schemaIncompatible("list_rules")
    }

    private func validate(_ query: ProxymanFlowQuery, scope: ProxymanReadScope) throws {
        try scope.validate()
        guard (1...scope.maximumFlows).contains(query.limit), query.host.map({ scope.allowedHosts.contains($0) }) ?? true,
              query.method.map(ProxymanNormalization.isHTTPMethod) ?? true,
              query.statusCode.map({ (100...599).contains($0) }) ?? true,
              query.processID.map({ (1...2147483647).contains($0) }) ?? true,
              query.pathContains.map({ !$0.isEmpty && $0.utf8.count <= 512 && !$0.contains(where: \.isNewline) && !$0.utf8.contains(0) }) ?? true,
              query.clientName.map({ ProxymanMinimizer.sourceName($0) == $0 }) ?? true else { throw ProxymanAdapterError.invalidQuery }
    }

    private func remember(_ summary: NetworkFlowSummary) {
        let ref = summary.reference
        anchors[ref] = summary; anchorOrder.append(ref)
        while anchorOrder.count > maximumAnchors { anchors.removeValue(forKey: anchorOrder.removeFirst()) }
    }

    func checkCancellation() throws { if Task.isCancelled { throw ProxymanAdapterError.cancelled } }
}
