#include "GhidraArchitectureInternal.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace macscope::native_decompiler::detail {
namespace {

void requireRead(bool value, const char* message) {
    if (!value) {
        throw std::runtime_error(message);
    }
}

class ReadCheckpoint final : public GhidraRequestCheckpoint {
public:
    void checkpoint() const override {}
};

MemoryRegion readRegion(std::string name, Address start, std::vector<std::uint8_t> bytes) {
    return MemoryRegion{std::move(name), start, "r--", bytes, bytes, {}};
}

MemoryRegion stringRegion() {
    return readRegion("string", 0x2000, {0x61, 0x62, 0x63, 0x00});
}

struct ReadFixture final {
    ReadCheckpoint checkpoint;
    ByteProvider bytes;
    EffectiveByteLoadImage image;

    ReadFixture(ghidra::AddrSpace* ramSpace, std::vector<MemoryRegion> regions)
        : bytes(std::move(regions)),
          image(bytes, checkpoint, "AARCH64:LE:64:AppleSilicon") {
        image.attachToRamSpace(ramSpace);
    }
};

struct ReadOutcome final {
    bool caught = false;
    std::string reason;
};

ReadOutcome read(
    EffectiveByteLoadImage& image,
    ghidra::uint1* destination,
    ghidra::int4 size,
    const ghidra::Address& address
) {
    ReadOutcome outcome;
    try {
        image.loadFill(destination, size, address);
    } catch (const ghidra::DataUnavailError& error) {
        outcome.caught = true;
        outcome.reason = error.explain;
    }
    return outcome;
}

template <std::size_t N>
std::array<std::uint8_t, N> sentinelBuffer() {
    std::array<std::uint8_t, N> destination;
    destination.fill(std::uint8_t{0xEE});
    return destination;
}

template <std::size_t N, std::size_t M>
void requirePrefixAndSentinel(
    const std::array<std::uint8_t, N>& destination,
    const std::array<std::uint8_t, M>& prefix
) {
    static_assert(M <= N);
    requireRead(std::equal(prefix.begin(), prefix.end(), destination.begin()) == bool{true},
                "served prefix differs from effective bytes");
    requireRead(std::all_of(destination.begin() + static_cast<std::ptrdiff_t>(M),
                            destination.end(), [](std::uint8_t byte) {
                                return byte == std::uint8_t{0xEE};
                            }) == bool{true},
                "read overwrote an unserved destination byte");
}

void requirePartial(const ReadOutcome& outcome, const EffectiveByteLoadImage& image) {
    requireRead(outcome.caught == bool{true}, "bounded partial read did not throw");
    requireRead(outcome.reason == std::string{"effective-byte-read-partial"},
                "bounded partial read reason changed");
    requireRead(image.hadUnavailableRead() == bool{false}, "bounded partial read latched");
    requireRead(image.boundedPartialReadCount() == std::size_t{1},
                "bounded partial read was not counted once");
}

void testC03WidePartial(ghidra::AddrSpace* ramSpace) {
    ReadFixture fixture(ramSpace, {stringRegion()});
    auto destination = sentinelBuffer<32>();
    const auto outcome = read(fixture.image, destination.data(), ghidra::int4{32},
                              ghidra::Address(ramSpace, 0x2000));
    requirePartial(outcome, fixture.image);
    requirePrefixAndSentinel(destination, std::array<std::uint8_t, 4>{0x61, 0x62, 0x63, 0x00});
}

void testC04ExactRegion(ghidra::AddrSpace* ramSpace) {
    ReadFixture fixture(ramSpace, {stringRegion()});
    auto destination = sentinelBuffer<4>();
    const auto outcome = read(fixture.image, destination.data(), ghidra::int4{4},
                              ghidra::Address(ramSpace, 0x2000));
    requireRead(outcome.caught == bool{false}, "exact-region read threw");
    requireRead(outcome.reason == std::string{""}, "exact-region read has a refusal reason");
    requireRead(destination == std::array<std::uint8_t, 4>{0x61, 0x62, 0x63, 0x00},
                "exact-region bytes differ");
    requireRead(fixture.image.hadUnavailableRead() == bool{false}, "exact-region read latched");
    requireRead(fixture.image.boundedPartialReadCount() == std::size_t{0},
                "exact-region read changed bounded count");
}

void testC05AdjacentRegions(ghidra::AddrSpace* ramSpace) {
    ReadFixture fixture(ramSpace, {
        stringRegion(), readRegion("adjacent", 0x2004, {0x64, 0x65, 0x66, 0x00}),
    });
    auto destination = sentinelBuffer<8>();
    const auto outcome = read(fixture.image, destination.data(), ghidra::int4{8},
                              ghidra::Address(ramSpace, 0x2000));
    requireRead(outcome.caught == bool{false}, "adjacent-region read threw");
    requireRead(destination == std::array<std::uint8_t, 8>{
                    0x61, 0x62, 0x63, 0x00, 0x64, 0x65, 0x66, 0x00},
                "adjacent-region bytes differ");
    requireRead(fixture.image.hadUnavailableRead() == bool{false}, "adjacent-region read latched");
    requireRead(fixture.image.boundedPartialReadCount() == std::size_t{0},
                "adjacent-region read changed bounded count");
}

void testC06HoleStopsCopy(ghidra::AddrSpace* ramSpace) {
    ReadFixture fixture(ramSpace, {
        stringRegion(), readRegion("after-hole", 0x2008, {0x64, 0x65, 0x66, 0x00}),
    });
    auto destination = sentinelBuffer<32>();
    const auto outcome = read(fixture.image, destination.data(), ghidra::int4{32},
                              ghidra::Address(ramSpace, 0x2000));
    requirePartial(outcome, fixture.image);
    requirePrefixAndSentinel(destination, std::array<std::uint8_t, 4>{0x61, 0x62, 0x63, 0x00});
}

void testC08UnmappedStart(ghidra::AddrSpace* ramSpace) {
    ReadFixture fixture(ramSpace, {stringRegion()});
    auto destination = sentinelBuffer<4>();
    const auto outcome = read(fixture.image, destination.data(), ghidra::int4{4},
                              ghidra::Address(ramSpace, 0x3000));
    requireRead(outcome.caught == bool{true}, "unmapped read did not throw");
    requireRead(outcome.reason == std::string{"effective-byte-read-unmapped"},
                "unmapped read reason changed");
    requirePrefixAndSentinel(destination, std::array<std::uint8_t, 0>{});
    requireRead(fixture.image.hadUnavailableRead() == bool{true}, "unmapped read did not latch");
    requireRead(fixture.image.boundedPartialReadCount() == std::size_t{0},
                "unmapped read counted as bounded");
}

void testC09SmallPartial(ghidra::AddrSpace* ramSpace) {
    ReadFixture fixture(ramSpace, {stringRegion()});
    auto destination = sentinelBuffer<4>();
    const auto outcome = read(fixture.image, destination.data(), ghidra::int4{4},
                              ghidra::Address(ramSpace, 0x2002));
    requireRead(outcome.caught == bool{true}, "small partial read did not throw");
    requireRead(outcome.reason == std::string{"effective-byte-read-unmapped"},
                "small partial read reason changed");
    requirePrefixAndSentinel(destination, std::array<std::uint8_t, 2>{0x63, 0x00});
    requireRead(fixture.image.hadUnavailableRead() == bool{true}, "small partial read did not latch");
    requireRead(fixture.image.boundedPartialReadCount() == std::size_t{0},
                "small partial read counted as bounded");
}

void testC10InvalidArguments(ghidra::AddrSpace* ramSpace) {
    ReadFixture fixture(ramSpace, {stringRegion()});
    const auto nullOutcome = read(fixture.image, nullptr, ghidra::int4{4},
                                  ghidra::Address(ramSpace, 0x2000));
    requireRead(nullOutcome.caught == bool{true}, "null destination did not throw");
    requireRead(nullOutcome.reason == std::string{"effective-byte-read-invalid"},
                "null destination reason changed");
    requireRead(fixture.image.hadUnavailableRead() == bool{true}, "null destination did not latch");
    auto destination = sentinelBuffer<4>();
    const auto negativeOutcome = read(fixture.image, destination.data(), ghidra::int4{-1},
                                      ghidra::Address(ramSpace, 0x2000));
    requireRead(negativeOutcome.caught == bool{true}, "negative size did not throw");
    requireRead(negativeOutcome.reason == std::string{"effective-byte-read-invalid"},
                "negative size reason changed");
    requireRead(fixture.image.hadUnavailableRead() == bool{true}, "negative size lost the latch");
    requirePrefixAndSentinel(destination, std::array<std::uint8_t, 0>{});
    requireRead(fixture.image.boundedPartialReadCount() == std::size_t{0},
                "invalid arguments changed bounded count");

    ReadFixture fresh(ramSpace, {stringRegion()});
    const auto freshNegative = read(fresh.image, destination.data(), ghidra::int4{-1},
                                    ghidra::Address(ramSpace, 0x2000));
    requireRead(freshNegative.caught == bool{true}, "fresh negative size did not throw");
    requireRead(freshNegative.reason == std::string{"effective-byte-read-invalid"},
                "fresh negative size reason changed");
    requireRead(fresh.image.hadUnavailableRead() == bool{true}, "negative size did not independently latch");
    requireRead(fresh.image.boundedPartialReadCount() == std::size_t{0},
                "fresh negative size changed bounded count");
}

void testC12CounterLifetime(ghidra::AddrSpace* ramSpace) {
    ReadFixture fixture(ramSpace, {stringRegion()});
    auto destination = sentinelBuffer<32>();
    const auto partial = read(fixture.image, destination.data(), ghidra::int4{32},
                              ghidra::Address(ramSpace, 0x2000));
    requirePartial(partial, fixture.image);
    const auto exact = read(fixture.image, destination.data(), ghidra::int4{4},
                            ghidra::Address(ramSpace, 0x2000));
    requireRead(exact.caught == bool{false}, "exact read after bounded read threw");
    requireRead(fixture.image.boundedPartialReadCount() == std::size_t{1},
                "exact read changed the bounded count");
    requireRead(fixture.image.hadUnavailableRead() == bool{false}, "exact read after bounded read latched");
    requirePrefixAndSentinel(destination, std::array<std::uint8_t, 4>{0x61, 0x62, 0x63, 0x00});

    ReadFixture fresh(ramSpace, {stringRegion()});
    auto smallDestination = sentinelBuffer<4>();
    const auto small = read(fresh.image, smallDestination.data(), ghidra::int4{4},
                            ghidra::Address(ramSpace, 0x2002));
    requireRead(small.caught == bool{true}, "fresh small partial read did not throw");
    requireRead(small.reason == std::string{"effective-byte-read-unmapped"},
                "fresh small partial read reason changed");
    requireRead(fresh.image.boundedPartialReadCount() == std::size_t{0},
                "fresh image inherited or counted a bounded read");
    requireRead(fresh.image.hadUnavailableRead() == bool{true}, "fresh small partial read did not latch");
    requirePrefixAndSentinel(smallDestination, std::array<std::uint8_t, 2>{0x63, 0x00});
}

void testBoundaryAndPriorFailureControls(ghidra::AddrSpace* ramSpace) {
    {
        // Sleigh::resolve fetches 16 bytes per instruction: a refused fetch
        // near the region end must keep the latched, unmapped classification.
        ReadFixture fixture(ramSpace, {stringRegion()});
        auto destination = sentinelBuffer<16>();
        const auto outcome = read(fixture.image, destination.data(), ghidra::int4{16},
                                  ghidra::Address(ramSpace, 0x2000));
        requireRead(outcome.caught == bool{true}, "instruction-fetch-size partial read did not throw");
        requireRead(outcome.reason == std::string{"effective-byte-read-unmapped"},
                    "instruction-fetch-size partial read reason changed");
        requireRead(fixture.image.hadUnavailableRead() == bool{true},
                    "instruction-fetch-size partial read did not latch");
        requireRead(fixture.image.boundedPartialReadCount() == std::size_t{0},
                    "instruction-fetch-size partial read counted as bounded");
        requirePrefixAndSentinel(destination, std::array<std::uint8_t, 4>{0x61, 0x62, 0x63, 0x00});
    }
    {
        ReadFixture fixture(ramSpace, {stringRegion()});
        auto destination = sentinelBuffer<9>();
        const auto outcome = read(fixture.image, destination.data(), ghidra::int4{9},
                                  ghidra::Address(ramSpace, 0x2000));
        requireRead(outcome.caught == bool{true}, "size-nine partial read did not throw");
        requireRead(outcome.reason == std::string{"effective-byte-read-unmapped"},
                    "size-nine partial read reason changed");
        requireRead(fixture.image.hadUnavailableRead() == bool{true}, "size-nine partial read did not latch");
        requireRead(fixture.image.boundedPartialReadCount() == std::size_t{0},
                    "size-nine partial read counted as bounded");
        requirePrefixAndSentinel(destination, std::array<std::uint8_t, 4>{0x61, 0x62, 0x63, 0x00});
    }
    {
        ReadFixture fixture(ramSpace, {stringRegion()});
        auto destination = sentinelBuffer<17>();
        const auto outcome = read(fixture.image, destination.data(), ghidra::int4{17},
                                  ghidra::Address(ramSpace, 0x2000));
        requirePartial(outcome, fixture.image);
        requirePrefixAndSentinel(destination, std::array<std::uint8_t, 4>{0x61, 0x62, 0x63, 0x00});
    }
    {
        ReadFixture fixture(ramSpace, {stringRegion()});
        auto destination = sentinelBuffer<32>();
        const auto unmapped = read(fixture.image, destination.data(), ghidra::int4{32},
                                   ghidra::Address(ramSpace, 0x3000));
        requireRead(unmapped.caught == bool{true}, "wide unmapped read did not throw");
        requireRead(unmapped.reason == std::string{"effective-byte-read-unmapped"},
                    "wide unmapped read reason changed");
        requireRead(fixture.image.hadUnavailableRead() == bool{true}, "wide unmapped read did not latch");
        requireRead(fixture.image.boundedPartialReadCount() == std::size_t{0},
                    "wide unmapped read counted as bounded");
        requirePrefixAndSentinel(destination, std::array<std::uint8_t, 0>{});
        const auto partial = read(fixture.image, destination.data(), ghidra::int4{32},
                                   ghidra::Address(ramSpace, 0x2000));
        requireRead(partial.caught == bool{true}, "partial read after old failure did not throw");
        requireRead(partial.reason == std::string{"effective-byte-read-partial"},
                    "partial read after old failure reason changed");
        requireRead(fixture.image.hadUnavailableRead() == bool{true}, "bounded read cleared an older latch");
        requireRead(fixture.image.boundedPartialReadCount() == std::size_t{1},
                    "partial read after old failure was not counted");
        requirePrefixAndSentinel(destination, std::array<std::uint8_t, 4>{0x61, 0x62, 0x63, 0x00});
    }
    {
        ReadFixture fixture(ramSpace, {stringRegion()});
        auto destination = sentinelBuffer<4>();
        const auto zero = read(fixture.image, destination.data(), ghidra::int4{0}, ghidra::Address());
        requireRead(zero.caught == bool{false}, "zero-length read changed its early return");
        requireRead(fixture.image.hadUnavailableRead() == bool{false}, "zero-length read latched");
        const auto invalid = read(fixture.image, destination.data(), ghidra::int4{4}, ghidra::Address());
        requireRead(invalid.caught == bool{true}, "invalid address did not throw");
        requireRead(invalid.reason == std::string{"effective-byte-read-invalid-address"},
                    "invalid-address reason changed");
        requireRead(fixture.image.hadUnavailableRead() == bool{true}, "invalid address did not latch");
        requireRead(fixture.image.boundedPartialReadCount() == std::size_t{0},
                    "invalid address counted as bounded");
        requirePrefixAndSentinel(destination, std::array<std::uint8_t, 0>{});
    }
    {
        ReadFixture fixture(ramSpace, {stringRegion()});
        const auto invalid = read(fixture.image, nullptr, ghidra::int4{0}, ghidra::Address());
        requireRead(invalid.caught == bool{true}, "null zero-length read did not throw");
        requireRead(invalid.reason == std::string{"effective-byte-read-invalid"},
                    "null zero-length argument precedence changed");
        requireRead(fixture.image.hadUnavailableRead() == bool{true}, "null zero-length read did not latch");
        requireRead(fixture.image.boundedPartialReadCount() == std::size_t{0},
                    "null zero-length read counted as bounded");
    }
    {
        ReadFixture fixture(ramSpace, {stringRegion()});
        auto destination = sentinelBuffer<32>();
        const auto overflow = read(fixture.image, destination.data(), ghidra::int4{32},
            ghidra::Address(ramSpace, std::numeric_limits<Address>::max() - Address{1}));
        requireRead(overflow.caught == bool{true}, "overflow read did not throw");
        requireRead(overflow.reason == std::string{"effective-byte-read-overflow"},
                    "overflow reason changed");
        requireRead(fixture.image.hadUnavailableRead() == bool{true}, "overflow read did not latch");
        requireRead(fixture.image.boundedPartialReadCount() == std::size_t{0},
                    "overflow read counted as bounded");
        requirePrefixAndSentinel(destination, std::array<std::uint8_t, 0>{});
    }
}

} // namespace

std::size_t runEffectiveByteReadBoundaryCases(ghidra::AddrSpace* ramSpace) {
    std::size_t completed = 0;
    testC03WidePartial(ramSpace);
    ++completed;
    testC04ExactRegion(ramSpace);
    ++completed;
    testC05AdjacentRegions(ramSpace);
    ++completed;
    testC06HoleStopsCopy(ramSpace);
    ++completed;
    testC08UnmappedStart(ramSpace);
    ++completed;
    testC09SmallPartial(ramSpace);
    ++completed;
    testC10InvalidArguments(ramSpace);
    ++completed;
    testC12CounterLifetime(ramSpace);
    ++completed;
    testBoundaryAndPriorFailureControls(ramSpace);
    return completed;
}

} // namespace macscope::native_decompiler::detail
