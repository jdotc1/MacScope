#pragma once
#ifndef MACSCOPE_NATIVE_MULTISTAGE_TEST_SEAM
#error "Multistage hooks are restricted to the isolated test variant"
#endif
#include "GhidraArchitectureInternal.hpp"
#include <ghidra/funcdata.hh>
#include <chrono>
#include <functional>
#include <stdexcept>

namespace macscope::native_decompiler::detail {
struct MultistageTestHooks final {
    std::function<void(GhidraArchitecture&)> architectureReady;
    std::function<void(GhidraArchitecture&, ghidra::Funcdata&, ghidra::int4&,
                       std::chrono::steady_clock::time_point&)> afterAction;
    std::function<void(bool)> publicationEntered;
};
inline thread_local MultistageTestHooks* multistageTestHooks = nullptr;
class ScopedMultistageTestHooks final {
public:
    explicit ScopedMultistageTestHooks(MultistageTestHooks& hooks) {
        if (multistageTestHooks != nullptr) throw std::logic_error("nested multistage test hook");
        multistageTestHooks = &hooks;
    }
    ~ScopedMultistageTestHooks() { multistageTestHooks = nullptr; }
    ScopedMultistageTestHooks(const ScopedMultistageTestHooks&) = delete;
    ScopedMultistageTestHooks& operator=(const ScopedMultistageTestHooks&) = delete;
};
}
