import Foundation

enum Phase2AIWorkerPeerRequirement {
    private static let certificate =
        "anchor apple generic and certificate leaf[subject.CN] = \"Apple Development: Example Developer (CERTID0000)\" and certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */"

    static let app = "identifier \"com.jeff.machscope\" and \(certificate)"
    static let worker = "identifier \"com.jeff.machscope.AIAgentWorker\" and \(certificate)"
}

@objc protocol Phase2AIWorkerEventSinkXPCProtocol: Sendable {
    func receive(eventData: Data, with reply: @escaping (Bool) -> Void)
    func finish(resultData: Data)
}

@objc protocol Phase2AIWorkerXPCProtocol: NSObjectProtocol {
    func handshake(with reply: @escaping (Data) -> Void)
    @objc optional func handshake(
        protocolManifestIdentity: String,
        with reply: @escaping (Data) -> Void
    )
    func configure(configurationData: Data, with reply: @escaping (Data) -> Void)
    func discoverModels(
        requestData: Data,
        requestID: UUID,
        with reply: @escaping (Data) -> Void
    )
    func cancelModelDiscovery(requestID: UUID)
    func performModelLifecycle(
        requestData: Data,
        requestID: UUID,
        with reply: @escaping (Data) -> Void
    )
    func cancelModelLifecycle(requestID: UUID)
    func run(
        requestData: Data,
        requestID: UUID,
        eventSink: Phase2AIWorkerEventSinkXPCProtocol
    )
    func cancel(requestID: UUID)
}
