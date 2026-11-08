#pragma once

#include "MacScopeNativeDecompiler/InputModel.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace macscope::native_decompiler::detail {

struct PacQualificationObservation final {
    TargetProfile target;
    std::vector<std::string> visibleOperations;
    std::vector<std::string> visibleDataflow;
    std::vector<std::string> hiddenOperations;
    std::vector<std::string> hiddenDataflow;
};

// Directly records native bits; this is a latch-lifetime control, not a test
// of either recovery catch or of the provider's publication gate.
struct MultistageLatchObservation final {
    std::uint32_t initial;
    std::uint32_t afterThunk;
    std::uint32_t afterClear;
    std::uint32_t afterLowlevel;
    std::uint32_t freshArchitecture;
};

[[nodiscard]] MultistageLatchObservation observeMultistageLatchForTesting(
    const AnalysisRequestView& request
);

[[nodiscard]] PacQualificationObservation observeHiddenPacProfileForTesting(
    const AnalysisRequestView& request,
    std::uint32_t rawCpuSubtype
);

} // namespace macscope::native_decompiler::detail
