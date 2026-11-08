#include "MacScopeNativeDecompiler/Backend.hpp"
#include "GhidraMultistageTestSeam.hpp"
#include "GhidraArchitectureInternal.hpp"
#include <ghidra/stringmanage.hh>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace macscope::native_decompiler::detail {
namespace {

void requireProbe(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

std::vector<std::uint8_t> dataV4() {
    return {0x61, 0x62, 0x63, 0x00};
}

std::vector<std::uint8_t> dataV32() {
    auto bytes = dataV4();
    bytes.resize(std::size_t{32}, std::uint8_t{0x00});
    return bytes;
}

std::vector<std::uint8_t> dataV40() {
    return std::vector<std::uint8_t>(std::size_t{40}, std::uint8_t{0x61});
}

AnalysisRequestView makeStringProbeRequest(std::size_t ordinal, const std::vector<std::uint8_t>& data) {
    std::vector<std::uint8_t> bytes = {0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
    while (bytes.size() < std::size_t{72}) bytes.insert(bytes.end(), {0x1f, 0x20, 0x03, 0xd5});
    auto raw = std::vector<std::uint8_t>(bytes.size(), std::uint8_t{0x00});
    const auto suffix = std::to_string(ordinal);
    AnalysisRequestView request(
        "request.stringprobe." + suffix, std::string(64, 'a'), "AARCH64:LE:64:AppleSilicon", "default",
        ImageIdentity{"image.stringprobe", "00000000-0000-0000-0000-000000000042", 0x1000},
        FunctionIdentity{"function.stringprobe." + suffix, "_stringprobe", 0x1000, 0x1008, {}},
        ByteProvider({MemoryRegion{"__text", 0x1000, "r-x", std::move(raw), std::move(bytes), {"patch000000"}},
                      MemoryRegion{"probe-data", 0x2000, "r--", data, data, {}}}),
        SymbolProvider({SymbolRecord{"image.stringprobe", 0x1000, "_stringprobe", "function"}}),
        TypeHintProvider({}), AnalysisBudgets{4096, 256, 4096, 4U * 1024U * 1024U, 10000});
    request.documentOnly = false;
    return request;
}

struct LoaderObservation final {
    std::size_t count = 0;
    bool countRecorded = false;
    bool latchChecked = false;
    bool latched = false;
    std::string latchText;
    bool unexpectedLatchException = false;
};

struct ProbeObservation final {
    bool called = false;
    bool returned = false;
    std::size_t dataSize = 0;
    std::vector<std::uint8_t> data;
    bool truncated = true;
    std::string typeRoute;
    bool unexpectedProbeException = false;
    LoaderObservation after;
};

struct DecompileObservation final {
    std::size_t hookCalls = 0;
    LoaderObservation before;
    std::array<ProbeObservation, 2> probes;
    LoaderObservation after;
    bool returned = false;
    bool contractError = false;
    bool unexpectedDecompileException = false;
    std::string outward;
    std::string suppressed;
    std::optional<StructuredResult> result;
};

void recordLoader(GhidraArchitecture& arch, LoaderObservation& observation) {
    try {
        observation.count = arch.boundedPartialEffectiveByteReadCount();
        observation.countRecorded = true;
    } catch (...) {
        observation.countRecorded = false;
    }
    try {
        arch.throwIfUnavailableEffectiveByteRead();
        observation.latchChecked = true;
    } catch (const ContractError& error) {
        observation.latched = true;
        observation.latchText = error.what();
        observation.latchChecked = true;
    } catch (...) {
        observation.unexpectedLatchException = true;
    }
}

void recordProbe(GhidraArchitecture& arch, Address offset, ProbeObservation& observation) {
    observation.truncated = true;
    try {
        ghidra::Datatype* charType = nullptr;
        try {
            charType = arch.typeFactory().getTypeChar(1);
            observation.typeRoute = "getTypeChar(1)";
        } catch (const ghidra::LowlevelError&) {
            charType = arch.typeFactory().getBase(1, ghidra::TYPE_INT, "int1");
            observation.typeRoute = "int1 fallback";
        }
        if (arch.stringManager != nullptr && charType != nullptr) {
            observation.called = true;
            const auto& data = arch.stringManager->getStringData(
                ghidra::Address(arch.getDefaultCodeSpace(), offset), charType, observation.truncated);
            observation.dataSize = data.size();
            observation.data.assign(data.begin(), data.end());
            observation.returned = true;
        }
    } catch (...) {
        observation.unexpectedProbeException = true;
    }
    recordLoader(arch, observation.after);
}

DecompileObservation observeDecompile(
    StructuredDecompilerBackend& backend,
    const AnalysisRequestView& request,
    const std::vector<Address>& offsets
) {
    DecompileObservation observation;
    MultistageTestHooks hooks;
    hooks.afterAction = [&](GhidraArchitecture& arch, ghidra::Funcdata&,
                            ghidra::int4&, std::chrono::steady_clock::time_point&) {
        ++observation.hookCalls;
        recordLoader(arch, observation.before);
        for (std::size_t index = 0; index < offsets.size() && index < observation.probes.size(); ++index) {
            recordProbe(arch, offsets[index], observation.probes[index]);
        }
        recordLoader(arch, observation.after);
    };
    {
        ScopedMultistageTestHooks scope(hooks);
        try {
            observation.result.emplace(backend.decompile(request, CancellationToken{}));
            observation.returned = true;
        } catch (const ContractError& error) {
            observation.contractError = true;
            observation.outward = error.what();
        } catch (...) {
            observation.unexpectedDecompileException = true;
        }
        observation.suppressed = std::string(lastSuppressedProviderFailureReason());
    }
    requireProbe(observation.hookCalls == std::size_t{1}, "string probe hook call count differs from one");
    requireProbe(offsets.size() <= std::size_t{2}, "string probe action count exceeds record capacity");
    return observation;
}

void requireLoaderRecorded(const LoaderObservation& observation) {
    requireProbe(observation.countRecorded == bool{true}, "string probe counter was not recorded");
    requireProbe(observation.latchChecked == bool{true}, "string probe latch was not recorded");
    requireProbe(observation.unexpectedLatchException == bool{false}, "string probe latch check threw unexpectedly");
}

void requireUnlatched(const LoaderObservation& observation) {
    requireLoaderRecorded(observation);
    requireProbe(observation.latched == bool{false}, "string probe unexpectedly latched");
    requireProbe(observation.latchText == std::string{""}, "string probe has unexpected latch text");
}

void requireCommon(const DecompileObservation& observation) {
    requireProbe(observation.hookCalls == std::size_t{1}, "string probe hook call count differs from one");
    requireProbe(observation.unexpectedDecompileException == bool{false}, "string probe decompile threw unexpectedly");
    requireUnlatched(observation.before);
    requireProbe(observation.before.count == std::size_t{0}, "string probe has prior bounded reads");
    requireLoaderRecorded(observation.after);
}

void requireReturned(const DecompileObservation& observation) {
    requireCommon(observation);
    requireProbe(observation.returned == bool{true}, "string probe decompile did not return");
    requireProbe(observation.contractError == bool{false}, "string probe decompile threw a contract error");
    requireProbe(observation.outward == std::string{""}, "string probe has unexpected outward error");
    requireProbe(observation.suppressed == std::string{""}, "string probe has unexpected suppressed reason");
    requireProbe(observation.result.has_value() == bool{true}, "string probe result is absent");
    requireUnlatched(observation.after);
}

void requireProbeReturned(const ProbeObservation& observation) {
    requireProbe(observation.called == bool{true}, "native string probe was not called");
    requireProbe(observation.returned == bool{true}, "native string probe did not return");
    requireProbe(observation.unexpectedProbeException == bool{false}, "native string probe threw unexpectedly");
    requireProbe(observation.dataSize == observation.data.size(), "string probe byte record has inconsistent size");
    requireProbe(observation.typeRoute == std::string{"getTypeChar(1)"} ||
                 observation.typeRoute == std::string{"int1 fallback"}, "string probe type route is absent");
    requireLoaderRecorded(observation.after);
    std::cout << "string probe type: " << observation.typeRoute << '\n';
}

void requireEmptyPartial(const ProbeObservation& observation) {
    requireProbeReturned(observation);
    requireProbe(observation.dataSize == std::size_t{0}, "partial string probe returned data");
    requireProbe(observation.truncated == bool{false}, "partial string probe marked truncation");
    requireProbe(observation.after.count == std::size_t{1}, "partial string probe was not counted once");
    requireUnlatched(observation.after);
}

void requireCompleteChunk(const ProbeObservation& observation) {
    requireProbeReturned(observation);
    requireProbe(observation.dataSize == std::size_t{32}, "complete string probe did not return the full chunk");
    requireProbe(observation.data[0] == std::uint8_t{0x61} && observation.data[1] == std::uint8_t{0x62} &&
                 observation.data[2] == std::uint8_t{0x63} && observation.data[3] == std::uint8_t{0x00},
                 "complete string probe prefix differs");
    requireProbe(std::all_of(observation.data.begin() + 4, observation.data.end(), [](std::uint8_t byte) {
        return byte == std::uint8_t{0x00};
    }) == bool{true}, "complete string probe padding differs");
    requireProbe(std::string(observation.data.begin(), observation.data.begin() + 3) == std::string{"abc"},
                 "complete string probe text differs");
    requireProbe(observation.truncated == bool{false}, "complete string probe marked truncation");
    requireProbe(observation.after.count == std::size_t{0}, "complete string probe changed the bounded count");
    requireUnlatched(observation.after);
}

void testUC01PartialFirstChunk(StructuredDecompilerBackend& backend) {
    const auto request = makeStringProbeRequest(std::size_t{1}, dataV4());
    const auto observation = observeDecompile(backend, request, {Address{0x2000}});
    requireReturned(observation);
    requireEmptyPartial(observation.probes[0]);
    const bool operationsEmpty = observation.result->operations.empty();
    const bool blocksEmpty = observation.result->blocks.empty();
    requireProbe(operationsEmpty == bool{false}, "UC01 result has no operations");
    requireProbe(blocksEmpty == bool{false}, "UC01 result has no blocks");
}

void testUC02CachedFailure(StructuredDecompilerBackend& backend) {
    const auto request = makeStringProbeRequest(std::size_t{2}, dataV4());
    const auto observation = observeDecompile(backend, request, {Address{0x2000}, Address{0x2000}});
    requireReturned(observation);
    requireEmptyPartial(observation.probes[0]);
    requireEmptyPartial(observation.probes[1]);
}

void testUC03MidRegion(StructuredDecompilerBackend& backend) {
    const auto request = makeStringProbeRequest(std::size_t{3}, dataV4());
    const auto observation = observeDecompile(backend, request, {Address{0x2002}});
    requireReturned(observation);
    requireEmptyPartial(observation.probes[0]);
}

void testUC04CompleteFirstChunk(StructuredDecompilerBackend& backend) {
    const auto request = makeStringProbeRequest(std::size_t{4}, dataV32());
    const auto observation = observeDecompile(backend, request, {Address{0x2000}});
    requireReturned(observation);
    requireCompleteChunk(observation.probes[0]);
}

void testUC05PartialSecondChunk(StructuredDecompilerBackend& backend) {
    const auto request = makeStringProbeRequest(std::size_t{5}, dataV40());
    const auto observation = observeDecompile(backend, request, {Address{0x2000}});
    requireReturned(observation);
    requireEmptyPartial(observation.probes[0]);
}

void testUC06UnmappedStart(StructuredDecompilerBackend& backend) {
    const auto request = makeStringProbeRequest(std::size_t{6}, dataV4());
    const auto observation = observeDecompile(backend, request, {Address{0x3000}});
    requireCommon(observation);
    const auto& probe = observation.probes[0];
    requireProbeReturned(probe);
    requireProbe(probe.dataSize == std::size_t{0}, "UC06 unmapped probe returned data");
    requireProbe(probe.truncated == bool{false}, "UC06 unmapped probe marked truncation");
    requireProbe(probe.after.count == std::size_t{0}, "UC06 unmapped probe changed bounded count");
    requireProbe(probe.after.latched == bool{true}, "UC06 unmapped probe did not latch");
    requireProbe(probe.after.latchText == std::string{"native-provider-effective-byte-read-unavailable"},
                 "UC06 latch reason differs");
    requireProbe(observation.returned == bool{false}, "UC06 latched decompile returned");
    requireProbe(observation.contractError == bool{true}, "UC06 did not throw ContractError");
    requireProbe(observation.outward == std::string{"structured provider execution failed"},
                 "UC06 outward failure differs");
    requireProbe(observation.suppressed == std::string{"native-provider-effective-byte-read-unavailable"},
                 "UC06 suppressed reason differs");
}

void testUC07IdenticalRequests(StructuredDecompilerBackend& backend) {
    const auto request = makeStringProbeRequest(std::size_t{7}, dataV4());
    const auto first = observeDecompile(backend, request, {Address{0x2000}});
    const auto second = observeDecompile(backend, request, {Address{0x2000}});
    requireReturned(first);
    requireReturned(second);
    requireEmptyPartial(first.probes[0]);
    requireEmptyPartial(second.probes[0]);
    requireProbe(first.result->requestId == second.result->requestId, "UC07 request ids differ");
    requireProbe(first.result->requestSha256 == second.result->requestSha256, "UC07 request hashes differ");
    const std::size_t firstOperations = first.result->operations.size();
    const std::size_t secondOperations = second.result->operations.size();
    const std::size_t firstBlocks = first.result->blocks.size();
    const std::size_t secondBlocks = second.result->blocks.size();
    const std::size_t firstTokens = first.result->tokens.size();
    const std::size_t secondTokens = second.result->tokens.size();
    requireProbe(firstOperations == secondOperations, "UC07 operation counts differ");
    requireProbe(firstBlocks == secondBlocks, "UC07 block counts differ");
    requireProbe(firstTokens == secondTokens, "UC07 token counts differ");
    const bool resultsEqual = *first.result == *second.result;
    requireProbe(resultsEqual == bool{true}, "UC07 whole results differ");
}

void testUC08NoProbeControl(StructuredDecompilerBackend& backend) {
    const auto request = makeStringProbeRequest(std::size_t{8}, dataV4());
    const auto observation = observeDecompile(backend, request, {});
    requireReturned(observation);
    requireProbe(observation.after.count == std::size_t{0}, "UC08 decompile without probe changed bounded count");
    requireProbe(observation.probes[0].called == bool{false} && observation.probes[1].called == bool{false},
                 "UC08 control called a probe");
}

void testUC09DataExtentControlPair(StructuredDecompilerBackend& backend) {
    const auto shortRequest = makeStringProbeRequest(std::size_t{9}, dataV4());
    const auto fullRequest = makeStringProbeRequest(std::size_t{10}, dataV32());
    const auto shortObservation = observeDecompile(backend, shortRequest, {Address{0x2000}});
    const auto fullObservation = observeDecompile(backend, fullRequest, {Address{0x2000}});
    requireReturned(shortObservation);
    requireReturned(fullObservation);
    requireEmptyPartial(shortObservation.probes[0]);
    requireCompleteChunk(fullObservation.probes[0]);
}

} // namespace

std::size_t runStringProbeBoundaryCases(StructuredDecompilerBackend& backend) {
    std::size_t completed = 0;
    testUC01PartialFirstChunk(backend);
    ++completed;
    testUC02CachedFailure(backend);
    ++completed;
    testUC03MidRegion(backend);
    ++completed;
    testUC04CompleteFirstChunk(backend);
    ++completed;
    testUC05PartialSecondChunk(backend);
    ++completed;
    testUC06UnmappedStart(backend);
    ++completed;
    testUC07IdenticalRequests(backend);
    ++completed;
    testUC08NoProbeControl(backend);
    ++completed;
    testUC09DataExtentControlPair(backend);
    ++completed;
    return completed;
}

} // namespace macscope::native_decompiler::detail
