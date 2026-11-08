#include "MacScopeNativeDecompiler/Backend.hpp"
#include "MacScopeNativeDecompiler/GhidraProvider.hpp"
#include "GhidraMultistageTestSeam.hpp"
#include "GhidraArchitectureInternal.hpp"
#include <ghidra/action.hh>
#include <ghidra/block.hh>
#include <ghidra/comment.hh>
#include <ghidra/database.hh>
#include <ghidra/funcdata.hh>
#include <ghidra/jumptable.hh>
#include <ghidra/loadimage.hh>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstddef>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace macscope::native_decompiler::detail {
std::size_t runEffectiveByteReadBoundaryCases(ghidra::AddrSpace* ramSpace);
std::size_t runStringProbeBoundaryCases(StructuredDecompilerBackend& backend);
}

using namespace macscope::native_decompiler;
namespace detail = macscope::native_decompiler::detail;
namespace {
void require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }
enum class Stage { thunk, lowlevel, success };
enum class Conflict { none, loader, cancel, wall, incomplete, loaderCancel };

class WitnessAction final : public ghidra::Action {
public:
    WitnessAction(Stage stage, int& visits, bool& witnessed, const char*& step)
        : Action(0, "ms-witness", "ms-witness"), stage_(stage), visits_(visits), witnessed_(witnessed), step_(step) {}
    ghidra::Action* clone(const ghidra::ActionGroupList&) const override { return nullptr; }
    ghidra::int4 apply(ghidra::Funcdata& fd) override {
        ++visits_;
        auto* arch = fd.getArch();
        const ghidra::uint4 expected = stage_ == Stage::thunk ? 1U : stage_ == Stage::lowlevel ? 2U : 0U;
        if (visits_ == 2) {
            step_ = "restart-second-visit";
            require(fd.numJumpTables() == 0 && !fd.isProcStarted() && !fd.hasRestartPending(), "restart did not clear native state");
            require(arch->getMacscopeMultistageRestore() == expected, "restart lost native latch");
            return 0;
        }
        require(visits_ == 1, "unexpected restart visit count");
        const ghidra::Address branchAddress(fd.getAddress().getSpace(), 0x2004);
        auto* jt = fd.installJumpTable(branchAddress);
        require(!jt->isOverride() && !fd.isProcStarted(), "pre-flow table installation");
        step_ = "scratch-start-processing";
        fd.startProcessing();
        step_ = "scratch-linked-indirect";
        require(fd.numJumpTables() == 1, "scratch table survived flow processing");
        jt = fd.getJumpTable(0);
        require(jt != nullptr && jt->getOpAddress() == branchAddress, "scratch table identity");
        auto* op = jt->getIndirectOp();
        require(op && op->code() == ghidra::CPUI_BRANCHIND && op->getAddr() == branchAddress,
                "scratch indirect branch linked to table");
        const ghidra::Address prior(fd.getAddress().getSpace(), 0x2008);
        step_ = "first-stage-postconditions";
        require(jt->numEntries() == 1 && jt->getAddressByIndex(0) == prior && jt->isRecovered() &&
                !jt->isPartial() && !jt->isOverride() && jt->getRecoverCount() == 1 &&
                arch->getMacscopeMultistageRestore() == 0, "first-stage table");
        fd.getOverride().insertMultistageJump(op->getAddr());
        step_ = "multistage-override";
        require(jt->checkForMultistage(&fd) && jt->isPartial(), "multistage override");
        ghidra::Varnode* second = nullptr;
        if (stage_ == Stage::lowlevel) {
            second = fd.newUnique(8);
            require(!second->isWritten() && !second->isConstant() && !second->isReadOnly() &&
                    !second->isAnnotation() && arch->max_jumptable_size != 0, "free target preconditions");
        } else {
            second = fd.newConstant(8, stage_ == Stage::thunk ? 0 : fd.getAddress().getOffset());
        }
        fd.opSetInput(op, second, 0);
        jt->incrementRecoveryCount();
        step_ = "second-stage-recover-multistage";
        jt->recoverMultistage(&fd);
        step_ = "second-stage-postconditions";
        require(arch->getMacscopeMultistageRestore() == expected && jt->numEntries() == 1 &&
                jt->getAddressByIndex(0).getOffset() == (stage_ == Stage::success ? 0x2000 : 0x2008) &&
                jt->isRecovered() && !jt->isPartial() && !jt->isOverride() && jt->getRecoverCount() == 2,
                "second-stage outcome");
        witnessed_ = true;
        fd.setRestartPending(true);
        return 0;
    }
private:
    Stage stage_;
    int& visits_;
    bool& witnessed_;
    const char*& step_;
};

AnalysisRequestView makeRequest(int ordinal, bool document) {
    std::vector<std::uint8_t> bytes = {0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
    while (bytes.size() < 72U) bytes.insert(bytes.end(), {0x1f, 0x20, 0x03, 0xd5});
    auto raw = std::vector<std::uint8_t>(bytes.size(), 0U);
    // Separate scratch code: movz x0,#0x2008; br x0; ret. The preinstalled
    // table is recovered during real flow tracing, before the second stage.
    std::vector<std::uint8_t> scratch = {0x00, 0x01, 0x84, 0xd2, 0x00, 0x00, 0x1f, 0xd6, 0xc0, 0x03, 0x5f, 0xd6};
    while (scratch.size() < 76U) scratch.insert(scratch.end(), {0x1f, 0x20, 0x03, 0xd5});
    auto scratchRaw = std::vector<std::uint8_t>(scratch.size(), 0U);
    const auto suffix = std::to_string(ordinal);
    AnalysisRequestView request(
        "request.multistage." + suffix, std::string(64, 'a'), "AARCH64:LE:64:AppleSilicon", "default",
        ImageIdentity{"image.multistage", "00000000-0000-0000-0000-000000000042", 0x1000},
        FunctionIdentity{"function.multistage." + suffix, "_multistage", 0x1000, 0x1008, {}},
        ByteProvider({MemoryRegion{"__text", 0x1000, "r-x", std::move(raw), std::move(bytes), {"patch000000"}},
                      MemoryRegion{"__scratch", 0x2000, "r-x", std::move(scratchRaw), std::move(scratch), {"patch000001"}}}),
        SymbolProvider({SymbolRecord{"image.multistage", 0x1000, "_multistage", "function"}}),
        TypeHintProvider({}), AnalysisBudgets{4096, 256, 4096, 4U * 1024U * 1024U, 10000});
    request.documentOnly = document;
    return request;
}

void runCase(StructuredDecompilerBackend& backend, int ordinal, bool document, Stage stage, Conflict conflict) {
    auto request = makeRequest(ordinal, document);
    std::atomic_bool cancelled{false};
    detail::GhidraArchitecture* seen = nullptr;
    bool witnessed = false;
    int visits = 0, publications = 0;
    const char* step = "before-provider";
    std::string hookError;
    const auto captureHook = [&](const auto& callback) {
        try { callback(); }
        catch (const ghidra::JumptableThunkError& error) { hookError = "JumptableThunkError: " + error.explain; throw; }
        catch (const ghidra::DataUnavailError& error) { hookError = "DataUnavailError: " + error.explain; throw; }
        catch (const ghidra::LowlevelError& error) { hookError = "LowlevelError: " + error.explain; throw; }
        catch (const std::exception& error) { hookError = std::string("std::exception: ") + error.what(); throw; }
        catch (...) { hookError = "unknown exception"; throw; }
    };
    detail::MultistageTestHooks hooks;
    hooks.architectureReady = [&](detail::GhidraArchitecture& arch) {
        step = "architecture-ready";
        captureHook([&] {
        require(seen == nullptr && arch.getMacscopeMultistageRestore() == 0, "request architecture not fresh");
        seen = &arch;
        });
    };
    hooks.afterAction = [&](detail::GhidraArchitecture& arch, ghidra::Funcdata& function,
                            ghidra::int4& result, std::chrono::steady_clock::time_point& started) {
        step = "after-action-preconditions";
        captureHook([&] {
        require(seen == &arch && function.getArch() == &arch && result >= 0 && function.isProcComplete() &&
                !function.hasBadData() && !function.hasUnimplemented(), "main action preconditions");
        // Scratch uses a separate address; retain the main-function comment
        // assertions so its diagnostic state cannot be silently altered.
        require(arch.commentdb->beginComment(function.getAddress()) ==
                arch.commentdb->endComment(function.getAddress()), "main comments would be altered by scratch restart");
        auto* scratchScope = function.getScopeLocal()->getParent();
        const ghidra::Address scratchAddress(arch.getDefaultCodeSpace(), 0x2000);
        require(scratchScope->queryFunction(scratchAddress) == nullptr, "scratch address already occupied");
        {
            // The native flow creates a symbol-less partial function at this same
            // address. Give the scratch function a symbol-backed scope ID so the
            // partial function's address-derived scope ID cannot collide with it.
            step = "scratch-symbol-install";
            auto* symbol = scratchScope->addFunction(scratchAddress, "__ms_witness");
            struct ScratchSymbolOwner {
                ghidra::Scope* scope;
                ghidra::FunctionSymbol* symbol;
                ~ScratchSymbolOwner() { scope->removeSymbol(symbol); }
            } owner{scratchScope, symbol};
            constexpr ghidra::uint8 partialScopeId = (ghidra::uint8{0x57AB12CD} << 32) | 0x2000;
            require(symbol->getId() != partialScopeId, "scratch symbol scope ID collides with partial function");
            step = "scratch-function-construct";
            auto* scratch = symbol->getFunction();
            require(scratch != nullptr && scratch->getArch() == &arch, "scratch architecture mismatch");
            ghidra::ActionRestartGroup restart(0, "ms-restart", 1);
            restart.addAction(new WitnessAction(stage, visits, witnessed, step));
            restart.reset(*scratch);
            step = "restart-perform";
            require(restart.perform(*scratch) >= 0 && visits == 2 && witnessed, "native restart witness");
        }
        step = "scratch-destroyed";
        require(scratchScope->queryFunction(scratchAddress) == nullptr, "scratch symbol was not removed");
        require(function.isProcComplete(), "scratch changed main processing");
        require(arch.commentdb->beginComment(function.getAddress()) ==
                arch.commentdb->endComment(function.getAddress()), "scratch left comments on main function");
        if (conflict == Conflict::loader || conflict == Conflict::loaderCancel) {
            std::uint8_t byte = 0;
            bool caught = false;
            try { arch.loader->loadFill(&byte, 1, ghidra::Address(arch.getDefaultCodeSpace(), 0)); }
            catch (const ghidra::DataUnavailError&) { caught = true; }
            require(caught, "loader did not report unavailable data");
        }
        if (conflict == Conflict::cancel || conflict == Conflict::loaderCancel) cancelled.store(true);
        if (conflict == Conflict::wall)
            started = std::chrono::steady_clock::now() - std::chrono::milliseconds(request.budgets.maxWallTimeMilliseconds + 1);
        if (conflict == Conflict::incomplete) result = -1;
        step = "after-action-complete";
        });
    };
    hooks.publicationEntered = [&](bool enteredDocument) {
        step = "publication-entered";
        captureHook([&] {
        require(enteredDocument == document, "wrong publication branch");
        ++publications;
        });
    };
    detail::ScopedMultistageTestHooks scope(hooks);
    bool returned = false;
    std::string outward;
    try {
        auto result = backend.decompile(request, CancellationToken(&cancelled));
        returned = true;
        validateStructuredResult(request, result);
        require(stage == Stage::success && conflict == Conflict::none && publications == 1, "unexpected success");
        if (document) require(result.operations.empty() && result.blocks.empty() && result.pseudocodeDocument &&
                              result.pseudocodeDocument->isComplete && !result.pseudocodeDocument->isTruncated, "document control");
        else require(!result.operations.empty() && !result.blocks.empty(), "graph control");
    } catch (const ContractError& error) { outward = error.what(); }
    if (seen == nullptr || !witnessed || visits != 2) {
        const auto sanitize = [](std::string value) {
            if (value.size() > 512) value.resize(512);
            for (auto& character : value)
                if (static_cast<unsigned char>(character) < 32U || static_cast<unsigned char>(character) > 126U) character = '?';
            return value;
        };
        std::cerr << "witness diagnostic: request=" << ordinal << " stage=" << step
                  << " architecture-seen=" << (seen != nullptr) << " witnessed=" << witnessed
                  << " visits=" << visits << " publications=" << publications
                  << " outward=" << sanitize(outward)
                  << " suppressed=" << sanitize(std::string(lastSuppressedProviderFailureReason()))
                  << " hook-error=" << sanitize(hookError) << '\n';
    }
    require(seen != nullptr && witnessed && visits == 2, "witness not completed");
    if (stage == Stage::success && conflict == Conflict::none) {
        require(returned && outward.empty() && publications == 1, "success control failed");
        return;
    }
    require(!returned && publications == 0, "failure published output");
    const bool cancellation = conflict == Conflict::cancel || conflict == Conflict::loaderCancel;
    require(outward == (cancellation ? "analysis was cancelled" : "structured provider execution failed"), "outward refusal");
    if (conflict != Conflict::cancel) {
        const std::string_view expected = conflict == Conflict::loader || conflict == Conflict::loaderCancel
            ? "native-provider-effective-byte-read-unavailable" : conflict == Conflict::wall
            ? "native-provider-wall-time-budget-exceeded" : conflict == Conflict::incomplete
            ? "native-provider-decompile-incomplete" : "native-provider-jumptable-recovery-incomplete";
        require(lastSuppressedProviderFailureReason() == expected, "suppressed refusal detail");
    }
}
}

void runEffectiveByteReadScenario(StructuredDecompilerBackend& backend) {
    const auto request = makeRequest(0, false);
    std::size_t hookCalls = 0;
    std::size_t completed = 0;
    detail::MultistageTestHooks hooks;
    hooks.afterAction = [&](detail::GhidraArchitecture& arch, ghidra::Funcdata&,
                            ghidra::int4&, std::chrono::steady_clock::time_point&) {
        ++hookCalls;
        require(hookCalls == std::size_t{1}, "effective-byte hook was repeated");
        require(arch.boundedPartialEffectiveByteReadCount() == std::size_t{0},
                "new architecture has bounded partial reads before loader cases");
        completed = detail::runEffectiveByteReadBoundaryCases(arch.getDefaultCodeSpace());
        require(arch.boundedPartialEffectiveByteReadCount() == std::size_t{0},
                "independent loader cases changed the architecture loader");
        arch.throwIfUnavailableEffectiveByteRead();
    };
    detail::ScopedMultistageTestHooks scope(hooks);
    const auto result = backend.decompile(request, CancellationToken{});
    validateStructuredResult(request, result);
    require(hookCalls == std::size_t{1}, "effective-byte hook did not run");
    require(completed == std::size_t{8}, "effective-byte spec case count");
    require(result.operations.empty() == bool{false}, "effective-byte control has no operations");
    require(result.blocks.empty() == bool{false}, "effective-byte control has no blocks");
}

int main(int argc, char* argv[]) {
    if (argc != 3 || std::string_view(argv[1]) != "--scenario") return EXIT_FAILURE;
    const std::string_view scenario = argv[2];
    if (scenario != "multistage-real-catches-and-publication" &&
        scenario != "effective-byte-read-boundary" &&
        scenario != "string-probe-boundary") return EXIT_FAILURE;
    try {
        GhidraBackendConfiguration configuration{MACSCOPE_TEST_SLEIGH_PACKAGE_ROOT,
            MACSCOPE_TEST_SLEIGH_MANIFEST_SHA256, MACSCOPE_TEST_SLEIGH_PROCESSOR_SPEC_ROOT,
            "AARCH64:LE:64:AppleSilicon", "default"};
        auto backend = makeValidatedProviderBackend(makeGhidraProvider(std::move(configuration)));
        if (scenario == "effective-byte-read-boundary") {
            runEffectiveByteReadScenario(*backend);
            std::cout << "effective-byte read boundary: 8 spec cases passed\n";
            return EXIT_SUCCESS;
        }
        if (scenario == "string-probe-boundary") {
            const auto completed = detail::runStringProbeBoundaryCases(*backend);
            require(completed == std::size_t{9}, "string probe boundary spec case count");
            std::cout << "string probe boundary: 9 spec cases passed\n";
            return EXIT_SUCCESS;
        }
        int ordinal = 0;
        for (auto stage : {Stage::thunk, Stage::lowlevel, Stage::success})
            for (bool document : {false, true}) runCase(*backend, ++ordinal, document, stage, Conflict::none);
        for (auto conflict : {Conflict::loader, Conflict::cancel, Conflict::wall, Conflict::incomplete, Conflict::loaderCancel})
            for (bool document : {false, true}) runCase(*backend, ++ordinal, document, Stage::lowlevel, conflict);
        require(ordinal == 16, "scenario count");
        std::cout << "multistage witness: 16 cases passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "multistage witness failed: " << error.what() << '\n';
    } catch (...) { std::cerr << "multistage witness failed with native exception\n"; }
    return EXIT_FAILURE;
}
