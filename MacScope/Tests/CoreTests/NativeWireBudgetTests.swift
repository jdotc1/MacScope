import Foundation
import XCTest
@testable import MacScope
@testable import MacScopeAnalysisCore
@testable import MacScopeDebuggerCore
final class NativeWireBudgetTests: XCTestCase {
 func testMaximumNativeUploadsFitExistingTransportBudget() throws {
  let markers = try LLDBCLIExchangeMarkers(token: String(repeating:"b",count:64))
  let old = "script __ms_native_source+='"+String(repeating:"A",count:2048)+"'"
  let oldCount = PersistentLLDBCLIAdapter.encodedWirePayload(semanticCommands:[old],markers:markers).count
  precondition(oldCount > LLDBCLITranscriptDecoder.maximumCommandBytes)
  let stamp = NativeExecutionFileStamp(canonicalPath:"/synthetic",device:1,inode:1,byteCount:4096,modifiedSeconds:1,modifiedNanoseconds:0,changedSeconds:1,changedNanoseconds:0)
  let image = NativeExecutionImage(binaryID:UUID(),canonicalPath:"/synthetic",uuid:UUID(),selectedSliceSHA256:String(repeating:"0",count:64),selectedSliceOffset:0,selectedSliceByteCount:4096,entryAddress:4096,regions:[.init(name:"__TEXT",staticAddress:4096,byteCount:4096,permissions:5)],fileStamp:stamp)
  let prototype = try NativeFunctionPrototype(returnType:.void,parameterTypes:[.pointer],provenance:.userOverride)
  let request = try NativeFunctionCallRequest(image:image,staticFunctionAddress:4096,prototype:prototype,arguments:[.buffer(Data(repeating:255,count:65536))])
  let start = DebuggerProcessStartIdentity(seconds:1,microseconds:0)!
  let anchor = DebuggerLocalProcessInstanceKey(processID:1234,startTime:start)
  let install = try NativeLLDBCallProgram(source:Data(repeating:32,count:65536)).installationCommands
  let upload = try NativeLLDBCallProgram.requestCommands(request,anchor:anchor,token:String(repeating:"a",count:64))
  let commands=install+upload
  let maximum=commands.map{PersistentLLDBCLIAdapter.encodedWirePayload(semanticCommands:[$0],markers:markers).count}.max()!
  precondition(maximum <= LLDBCLITranscriptDecoder.maximumCommandBytes && upload.count-1 <= 512)
  print("PASS native maximum source and64KiB argument upload: oldchunkwire=\(oldCount), newmaxwire=\(maximum), boundedcommands=\(commands.count)")
 }
 // The watchdog is cancelled when its interrupted exchange returns. Retirement
 // must retain an uncancelled context until the owned adapter has exited and reaped.
 func testCancelledWatchdogPreservesAdapterExitAndReap() async {
  let directProcess = CancellationSensitiveOwnedProcess()
  let direct = PersistentLLDBCLIAdapter(epoch: DebuggerSessionEpoch(), channel: RetirementChannel(), retainedProcess: directProcess)
  let directGate = RetirementGate()
  let control = Task { await directGate.wait(); return await direct.retireRetainedAdapterWithoutDebuggerCommand() }
  control.cancel(); await directGate.open()
  let refused = await control.value
  XCTAssertFalse(refused.didExit)
  XCTAssertFalse(refused.didReap)
  let process = CancellationSensitiveOwnedProcess()
  let adapter = PersistentLLDBCLIAdapter(epoch: DebuggerSessionEpoch(), channel: RetirementChannel(), retainedProcess: process)
  let gate = RetirementGate()
  let watchdog = Task {
   await gate.wait()
   precondition(Task.isCancelled)
   return await NativeExecutionCoordinator.retireOwnedAdapter(adapter)
  }
  watchdog.cancel(); await gate.open()
  let receipt = await watchdog.value
  let cancellationObserved = await process.sawCancellation
  let reaped = await process.reaped
  XCTAssertTrue(receipt.didExit)
  XCTAssertTrue(receipt.didReap)
  XCTAssertTrue(reaped)
  XCTAssertFalse(cancellationObserved)

 }
}

private actor RetirementGate {
 var isOpen = false
 var waiter: CheckedContinuation<Void, Never>?
 func wait() async { if isOpen { return }; await withCheckedContinuation { waiter = $0 } }
 func open() { isOpen = true; waiter?.resume(); waiter = nil }
}
private actor RetirementChannel: PersistentLLDBCLIByteChannel {
 func write(_ data: Data) async throws { }
 func nextBytes() async throws -> Data? { nil }
 func closeInput() async { }
 func closeHandles() async { }
}
private actor CancellationSensitiveOwnedProcess: PersistentLLDBCLIRetainedProcess {
 private(set) var sawCancellation = false
 private(set) var reaped = false
 func waitForExit(maximumDuration: Duration) async -> Bool {
  sawCancellation = sawCancellation || Task.isCancelled
  do { try await Task.sleep(for: .milliseconds(5)) } catch { return false }
  return !Task.isCancelled
 }
 func terminateRetainedAdapter() async { }
 func killRetainedAdapterIfStillRunning() async -> Bool { true }
 func reapAndClose() async -> Bool {
  sawCancellation = sawCancellation || Task.isCancelled
  reaped = !Task.isCancelled
  return reaped
 }
}
