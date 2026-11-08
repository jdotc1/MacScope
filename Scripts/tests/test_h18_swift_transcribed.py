"""Differential test: Swift FunctionSignatureMatcher XCTest cases transcribed against refmatch.py.

Every matcher-level / validation-level XCTest method from the Swift suites below is transcribed
literally (same inputs, same expected results, reason sets and counts). Expectations are NOT
adjusted to fit the Python port; a failure here is either a transcription error or a port
deviation from the Swift source of truth:
  MacScope/Services/FunctionSignatures/FunctionSignature.swift
  MacScope/Services/FunctionSignatures/FunctionSignatureMatcher.swift

Transcribed Swift files:
  MacScope/Tests/CoreTests/FunctionSignatureMatcherTests.swift       (10 methods)
  MacScope/Tests/CoreTests/FunctionSignatureMatcherEdgeTests.swift   (10 methods)
  MacScope/Tests/CoreTests/FunctionSignatureValidationTests.swift    (21 methods)
  MacScope/Tests/CoreTests/FunctionSignatureLibraryPackTests.swift   (2 methods)

Notes:
  - FunctionSignatureDatabase has no Python type; `Matcher(signatures, schema_version)` stands in.
  - FunctionSignaturePrefixIndexKey.make(for:) has no public Python API; its transcription uses the
    port's private `_first_anchor_offset` and builds the key exactly as `Matcher.__init__` does.

Skipped (none contains a direct matcher-only construction/match/validation assertion; every
assertion observes AnalysisEngine / LoadedBinary / decoded-instruction / app behaviour):
  FunctionSignatureIntegrationTests.swift
    testUniqueMatchRenamesExistingFallbackAndProjectsLibrarySymbol - AnalysisEngine.analyze over a LoadedBinary fixture.
  FunctionSignatureIntegrationEdgeTests.swift
    testSchemaV1SubtypeEligibilityNormalizesOnlyCapabilityBits - AnalysisEngine.functionSignatureArchitecture(for: LoadedBinary).
    testCandidateRequiresCompleteContiguousFourByteRows - AnalysisEngine.functionSignatureCandidate from DecodedInstruction rows.
    testCandidateDoesNotTreatNormalFlowBranchTargetAsImportedReference - candidate building from DecodedInstruction flow.
    testCandidateAbstainsForGapDuplicateShortOrOverlappingRows - candidate building from DecodedInstruction rows.
    testCandidateAbstainsBeforeMaterializingRangeOverMaximum - candidate building from FunctionSummary/DecodedInstruction.
    testProjectionHonorsAuthoritativeAndExistingNamePrecedenceAndPreservesIdentity - AnalysisEngine.projectFunctionSignatureMatches over FunctionSummary.
    testAmbiguousMatchDoesNotMutateFunctionOrEmitSymbol - AnalysisEngine.projectFunctionSignatureMatches over FunctionSummary.
    testSyntheticLibrarySymbolsHaveDeterministicAddressOrder - AnalysisEngine.projectFunctionSignatureMatches symbol ordering.
    testStructuredRealAndStubReferencesMatchButConflictingRawNamesAbstain - AnalysisEngine.analyze with symbols/indirect stubs.
    testExportAddressSuppressesCompetingSyntheticStub - AnalysisEngine.analyze symbol table (empty matcher only).
  FunctionSignaturePipelineTests.swift
    testEffectivePatchCanEnableSignatureMatch - AnalysisEngine.analyze with AddressOverride byte patches.
    testEffectivePatchCanDisableSignatureMatch - AnalysisEngine.analyze with AddressOverride byte patches.
    testDataOverrideGapAbstainsInsteadOfMatchingPartialBytes - AnalysisEngine.analyze with data override.
    testUndefinedOverrideGapAbstainsInsteadOfMatchingPartialBytes - AnalysisEngine.analyze with undefined override.
    testStructuredBranchTargetToRealSymbolSuppliesReferenceEvidence - AnalysisEngine.analyze + decoder branch targets.
    testStructuredBranchTargetToEligibleStubSuppliesReferenceEvidence - AnalysisEngine.analyze + indirect stubs.
    testOperandStringWithoutStructuredBranchTargetIsNotReferenceEvidence - AnalysisEngine.analyze + decoder operands.
    testConflictingRealAndIndirectNamesMakeReferenceEvidenceAmbiguous - AnalysisEngine.analyze + symbol/stub conflict.
    testEntryAndTextGeneratedNamesRemainProtected - AnalysisEngine.analyze generated-name protection.
    testCustomOverrideWinsAcrossListingSymbolizedLabelAndPseudocodeHeader - snapshot display, listing and PseudocodePrinter.
    testEmptyStandardMatcherPreservesNormalizedAnalysisBytes - AnalysisEngine + GoldenOutput JSON.

Run: cd <repo> && python3 -m unittest discover -s Scripts/tests -p test_h18_swift_transcribed.py -v
Python 3.9+, standard library only.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "Scripts" / "research"))

from h18_known_library import refmatch  # noqa: E402

Signature = refmatch.Signature
MaskedPattern = refmatch.MaskedPattern
ChecksumSpan = refmatch.ChecksumSpan
TailRun = refmatch.TailRun
ImportedReference = refmatch.ImportedReference
Candidate = refmatch.Candidate
Identity = refmatch.Identity
Matcher = refmatch.Matcher
crc32 = refmatch.crc32_iso_hdlc

ARM64 = refmatch.ARCH_ARM64
CURRENT_SCHEMA_VERSION = 1  # FunctionSignatureDatabase.currentSchemaVersion
UINT32_MAX = 0xFFFF_FFFF

_UNSET = object()


def _make_matcher(signatures, schema_version=CURRENT_SCHEMA_VERSION):
    return Matcher(list(signatures), schema_version=schema_version)


def _reasons(matcher):
    return [issue.reason for issue in matcher.validation_issues]


class _ResultAssertions(unittest.TestCase):
    def assertNoMatch(self, result, msg=None):
        self.assertEqual(result.kind, "noMatch", msg)
        self.assertEqual(tuple(result.identities), (), msg)

    def assertUnique(self, result, name, library_name, msg=None):
        self.assertEqual(result.kind, "unique", msg)
        self.assertEqual(tuple(result.identities), (Identity(name, library_name),), msg)

    def assertAmbiguous(self, result, pairs, msg=None):
        self.assertEqual(result.kind, "ambiguous", msg)
        self.assertEqual(tuple(result.identities), tuple(Identity(n, l) for n, l in pairs), msg)


# ---------------------------------------------------------------------------------------------
# FunctionSignatureMatcherTests.swift
# ---------------------------------------------------------------------------------------------

def _mt_make_valid_signature(
    name="___divti3",
    library_name="compiler-rt",
    total_length=64,
    prefix_bytes=bytes([0xA5] * 32),
    prefix_mask=bytes([0xFF] * 32),
    checksum=ChecksumSpan(32, 8, 0),
    tail_runs=(),
    references=(),
):
    return Signature(
        name=name,
        library_name=library_name,
        total_length=total_length,
        prefix=MaskedPattern(bytes(prefix_bytes), bytes(prefix_mask)),
        checksum=checksum,
        tail_runs=tuple(tail_runs),
        references=tuple(references),
        architecture=ARM64,
    )


def _mt_make_matching_signature(data, name="___divti3", library_name="compiler-rt", tail_offset=40):
    prefix_bytes = bytearray(data[:32])
    prefix_mask = bytearray([0xFF] * 32)
    prefix_bytes[4:8] = bytes(4)
    prefix_mask[4:8] = bytes(4)
    checksum_bytes = bytes(data[32:40])
    tail_start = tail_offset
    return Signature(
        name=name,
        library_name=library_name,
        total_length=len(data),
        prefix=MaskedPattern(bytes(prefix_bytes), bytes(prefix_mask)),
        checksum=ChecksumSpan(32, 8, crc32(checksum_bytes)),
        tail_runs=(TailRun(tail_offset, bytes(data[tail_start:tail_start + 4]), bytes([0xFF] * 4)),),
        references=(ImportedReference(48, "_memcpy"),),
        architecture=ARM64,
    )


class FunctionSignatureMatcherTestsPort(_ResultAssertions):
    def test_FunctionSignatureMatcherTests_testValidatorAcceptsEmptyAndValidSchemaV1Databases(self):
        """FunctionSignatureMatcherTests.swift: testValidatorAcceptsEmptyAndValidSchemaV1Databases"""
        empty_matcher = _make_matcher([])
        self.assertEqual(empty_matcher.validated_signature_count, 0)
        self.assertEqual(empty_matcher.validation_issues, [])

        valid_matcher = _make_matcher([_mt_make_valid_signature()])
        self.assertEqual(valid_matcher.validated_signature_count, 1)
        self.assertEqual(valid_matcher.validation_issues, [])

    def test_FunctionSignatureMatcherTests_testUnsupportedSchemaDisablesTheEntireDatabase(self):
        """FunctionSignatureMatcherTests.swift: testUnsupportedSchemaDisablesTheEntireDatabase"""
        matcher = _make_matcher([_mt_make_valid_signature()], schema_version=CURRENT_SCHEMA_VERSION + 1)
        self.assertEqual(matcher.validated_signature_count, 0)
        self.assertEqual(_reasons(matcher), ["unsupportedSchemaVersion"])

    def test_FunctionSignatureMatcherTests_testValidatorQuarantinesMalformedRecordsWithoutDiscardingValidRecords(self):
        """FunctionSignatureMatcherTests.swift: testValidatorQuarantinesMalformedRecordsWithoutDiscardingValidRecords"""
        invalid_name = _mt_make_valid_signature(name=" bad")
        invalid_length = _mt_make_valid_signature(
            name="invalidLength",
            total_length=66,
            prefix_bytes=bytes([0xA5] * 32),
            prefix_mask=bytes([0xFF] * 32),
            checksum=ChecksumSpan(32, 8, 0),
        )
        invalid_mask = _mt_make_valid_signature(
            name="invalidMask",
            prefix_mask=bytes([0x7F] + [0xFF] * 31),
        )
        noncanonical_wildcard = _mt_make_valid_signature(
            name="noncanonicalWildcard",
            prefix_bytes=bytes([0xA5] + [0xA5] * 31),
            prefix_mask=bytes([0] + [0xFF] * 31),
        )
        invalid_checksum = _mt_make_valid_signature(
            name="invalidChecksum",
            checksum=ChecksumSpan(UINT32_MAX, 8, 0),
        )
        matcher = _make_matcher([
            invalid_checksum,
            _mt_make_valid_signature(),
            noncanonical_wildcard,
            invalid_mask,
            invalid_length,
            invalid_name,
        ])
        self.assertEqual(matcher.validated_signature_count, 1)
        self.assertEqual(
            set(_reasons(matcher)),
            {
                "invalidName",
                "invalidTotalLength",
                "invalidPrefixMask",
                "noncanonicalWildcardByte",
                "invalidChecksumRange",
            },
        )

    def test_FunctionSignatureMatcherTests_testEqualPredicatesRetainDistinctIdentities(self):
        """FunctionSignatureMatcherTests.swift: testEqualPredicatesRetainDistinctIdentities"""
        first = _mt_make_valid_signature(name="first", library_name="libA")
        second = _mt_make_valid_signature(name="second", library_name="libB")
        matcher = _make_matcher([second, first])
        self.assertEqual(matcher.validated_signature_count, 2)
        self.assertEqual(matcher.validation_issues, [])

    def test_FunctionSignatureMatcherTests_testMatcherRequiresEveryPredicateAndAllowsWildcardMutation(self):
        """FunctionSignatureMatcherTests.swift: testMatcherRequiresEveryPredicateAndAllowsWildcardMutation"""
        data = bytes(range(64))
        signature = _mt_make_matching_signature(data)
        matcher = _make_matcher([signature])
        name, lib = signature.name, signature.library_name

        self.assertFalse(matcher.is_empty)
        self.assertUnique(matcher.match(Candidate(data, {48: "_memcpy"}, ARM64)), name, lib)

        wildcard_mutation = bytearray(data)
        wildcard_mutation[4:8] = bytes([0xFF, 0xFE, 0xFD, 0xFC])
        self.assertUnique(
            matcher.match(Candidate(bytes(wildcard_mutation), {48: "_memcpy"}, ARM64)), name, lib
        )

        for mutation_offset in [0, 32, 40]:
            with self.subTest(mutation_offset=mutation_offset):
                mutation = bytearray(data)
                mutation[mutation_offset] ^= 0xFF
                self.assertNoMatch(matcher.match(Candidate(bytes(mutation), {48: "_memcpy"}, ARM64)))
        self.assertNoMatch(matcher.match(Candidate(data, {}, ARM64)))
        self.assertNoMatch(matcher.match(Candidate(data[:-1], {48: "_memcpy"}, ARM64)))

    def test_FunctionSignatureMatcherTests_testMatcherCoalescesOneIdentityAndPreservesStableAmbiguity(self):
        """FunctionSignatureMatcherTests.swift: testMatcherCoalescesOneIdentityAndPreservesStableAmbiguity"""
        data = bytes(range(64))
        first = _mt_make_matching_signature(data, name="alpha", library_name="libA")
        same_identity_variant = _mt_make_matching_signature(
            data, name="alpha", library_name="libA", tail_offset=44
        )
        self.assertUnique(
            _make_matcher([same_identity_variant, first]).match(Candidate(data, {48: "_memcpy"}, ARM64)),
            "alpha",
            "libA",
        )

        second_identity = _mt_make_matching_signature(
            data, name="beta", library_name="libB", tail_offset=44
        )
        candidate = Candidate(data, {48: "_memcpy"}, ARM64)
        expected = [("alpha", "libA"), ("beta", "libB")]
        self.assertAmbiguous(_make_matcher([second_identity, first]).match(candidate), expected)
        self.assertAmbiguous(_make_matcher([first, second_identity]).match(candidate), expected)

    def test_FunctionSignatureMatcherTests_testEmptyMatcherHasNoValidatedRecords(self):
        """FunctionSignatureMatcherTests.swift: testEmptyMatcherHasNoValidatedRecords"""
        empty = _make_matcher([])  # FunctionSignatureMatcher.empty
        self.assertTrue(empty.is_empty)
        self.assertNoMatch(empty.match(Candidate(bytes(16), {}, ARM64)))

    def test_FunctionSignatureMatcherTests_testSchemaV1ValueTypesPreserveFrozenFields(self):
        """FunctionSignatureMatcherTests.swift: testSchemaV1ValueTypesPreserveFrozenFields"""
        signature = Signature(
            architecture=ARM64,
            name="___divti3",
            library_name="compiler-rt",
            total_length=64,
            prefix=MaskedPattern(bytes([0xFF, 0, 0xAB, 0]), bytes([0xFF, 0, 0xFF, 0])),
            checksum=ChecksumSpan(32, 16, 0x1234_5678),
            tail_runs=(TailRun(48, bytes([0xCD, 0]), bytes([0xFF, 0])),),
            references=(ImportedReference(52, "_memcpy"),),
        )
        database_schema_version = CURRENT_SCHEMA_VERSION
        database_signatures = [signature]

        self.assertEqual(refmatch.SCHEMA_VERSION, 1)
        self.assertEqual(database_schema_version, 1)
        self.assertEqual(database_signatures, [signature])
        self.assertEqual(signature.architecture, ARM64)
        self.assertEqual(signature.name, "___divti3")
        self.assertEqual(signature.library_name, "compiler-rt")
        self.assertEqual(signature.total_length, 64)
        self.assertEqual(signature.prefix.bytes, bytes([0xFF, 0, 0xAB, 0]))
        self.assertEqual(signature.prefix.mask, bytes([0xFF, 0, 0xFF, 0]))
        self.assertEqual(signature.checksum.offset, 32)
        self.assertEqual(signature.checksum.byte_count, 16)
        self.assertEqual(signature.checksum.crc32, 0x1234_5678)
        self.assertEqual(signature.tail_runs[0].offset, 48)
        self.assertEqual(signature.references[0].instruction_offset, 52)
        self.assertEqual(signature.references[0].symbol_name, "_memcpy")

    def test_FunctionSignatureMatcherTests_testCRC32ISOHDLCMatchesCanonicalReferenceVector(self):
        """FunctionSignatureMatcherTests.swift: testCRC32ISOHDLCMatchesCanonicalReferenceVector"""
        self.assertEqual(crc32(b"123456789"), 0xCBF4_3926)

    def test_FunctionSignatureMatcherTests_testCRC32ISOHDLCEmptyInputIsZero(self):
        """FunctionSignatureMatcherTests.swift: testCRC32ISOHDLCEmptyInputIsZero"""
        self.assertEqual(crc32(b""), 0)


# ---------------------------------------------------------------------------------------------
# FunctionSignatureMatcherEdgeTests.swift
# ---------------------------------------------------------------------------------------------

def _edge_mask(exact_byte_count):
    assert 0 <= exact_byte_count <= 32
    return bytes([0xFF] * exact_byte_count + [0] * (32 - exact_byte_count))


def _edge_make_signature(
    name,
    total_length=64,
    prefix_mask=bytes([0xFF] * 32),
    checksum=ChecksumSpan(32, 8, 0),
    tail_runs=(),
    references=(),
):
    prefix_mask = bytes(prefix_mask)
    return Signature(
        architecture=ARM64,
        name=name,
        library_name="compiler-rt",
        total_length=total_length,
        prefix=MaskedPattern(bytes(0xA5 if m == 0xFF else 0 for m in prefix_mask), prefix_mask),
        checksum=checksum,
        tail_runs=tuple(tail_runs),
        references=tuple(references),
    )


def _edge_default_prefix_mask():
    value = bytearray([0xFF] * 32)
    value[4:8] = bytes(4)
    return bytes(value)


def _edge_make_matching_signature(data, name="matched", tail_offset=40, prefix_mask=None,
                                  imported_reference=_UNSET):
    if prefix_mask is None:
        prefix_mask = _edge_default_prefix_mask()
    if imported_reference is _UNSET:
        imported_reference = ImportedReference(48, "_memcpy")
    assert len(data) == 64
    assert len(prefix_mask) == 32
    prefix_bytes = bytes(b if m == 0xFF else 0 for b, m in zip(data[:32], prefix_mask))
    tail_start = tail_offset
    return Signature(
        architecture=ARM64,
        name=name,
        library_name="compiler-rt",
        total_length=len(data),
        prefix=MaskedPattern(prefix_bytes, bytes(prefix_mask)),
        checksum=ChecksumSpan(32, 8, crc32(bytes(data[32:40]))),
        tail_runs=(TailRun(tail_offset, bytes(data[tail_start:tail_start + 4]), bytes([0xFF] * 4)),),
        references=(imported_reference,) if imported_reference is not None else (),
    )


class FunctionSignatureMatcherEdgeTestsPort(_ResultAssertions):
    def test_FunctionSignatureMatcherEdgeTests_testMatcherRejectsCandidateLongerThanSignature(self):
        """FunctionSignatureMatcherEdgeTests.swift: testMatcherRejectsCandidateLongerThanSignature"""
        data = bytes(range(64))
        matcher = _make_matcher([_edge_make_matching_signature(data)])
        self.assertNoMatch(matcher.match(Candidate(data + bytes(4), {48: "_memcpy"}, ARM64)))

    def test_FunctionSignatureMatcherEdgeTests_testImportedReferenceMatchingPreservesExactMachOSpellingAndCase(self):
        """FunctionSignatureMatcherEdgeTests.swift: testImportedReferenceMatchingPreservesExactMachOSpellingAndCase"""
        data = bytes(range(64))
        matcher = _make_matcher([_edge_make_matching_signature(data)])
        for incorrect_name in ["memcpy", "_MEMCPY", "_memcpy "]:
            with self.subTest(incorrect_name=incorrect_name):
                self.assertNoMatch(
                    matcher.match(Candidate(data, {48: incorrect_name}, ARM64)),
                    "reference spelling %r must not be normalized" % incorrect_name,
                )

    def test_FunctionSignatureMatcherEdgeTests_testTailPredicatesDisambiguateOtherwiseIdenticalSignatures(self):
        """FunctionSignatureMatcherEdgeTests.swift: testTailPredicatesDisambiguateOtherwiseIdenticalSignatures"""
        first_bytes = bytearray(range(64))
        second_bytes = bytearray(first_bytes)
        first_bytes[40:44] = bytes([0xA1, 0xA2, 0xA3, 0xA4])
        second_bytes[40:44] = bytes([0xB1, 0xB2, 0xB3, 0xB4])
        first_bytes, second_bytes = bytes(first_bytes), bytes(second_bytes)

        first = _edge_make_matching_signature(first_bytes, name="firstTail", tail_offset=40,
                                              imported_reference=None)
        second = _edge_make_matching_signature(second_bytes, name="secondTail", tail_offset=40,
                                               imported_reference=None)
        matcher = _make_matcher([second, first])
        self.assertUnique(matcher.match(Candidate(first_bytes, {}, ARM64)), "firstTail", "compiler-rt")
        self.assertUnique(matcher.match(Candidate(second_bytes, {}, ARM64)), "secondTail", "compiler-rt")

    def test_FunctionSignatureMatcherEdgeTests_testChecksumEvidenceContributionIsCappedAtThirtyTwoBits(self):
        """FunctionSignatureMatcherEdgeTests.swift: testChecksumEvidenceContributionIsCappedAtThirtyTwoBits"""
        weak = _edge_make_signature(
            name="weakDespiteLongChecksum",
            total_length=160,
            prefix_mask=_edge_mask(11),
            checksum=ChecksumSpan(32, 100, 0),
        )
        weak_matcher = _make_matcher([weak])
        self.assertEqual(weak_matcher.validated_signature_count, 0)
        self.assertIn("insufficientEvidence", _reasons(weak_matcher))

        threshold = _edge_make_signature(
            name="thresholdWithLongChecksum",
            total_length=160,
            prefix_mask=_edge_mask(12),
            checksum=ChecksumSpan(32, 100, 0),
        )
        threshold_matcher = _make_matcher([threshold])
        self.assertEqual(threshold_matcher.validated_signature_count, 1)
        self.assertEqual(threshold_matcher.validation_issues, [])

    def test_FunctionSignatureMatcherEdgeTests_testTailEvidenceCountsExactBytesButNotWildcards(self):
        """FunctionSignatureMatcherEdgeTests.swift: testTailEvidenceCountsExactBytesButNotWildcards"""
        prefix_mask = _edge_mask(12)
        threshold = _edge_make_signature(
            name="thresholdTail",
            prefix_mask=prefix_mask,
            checksum=ChecksumSpan(32, 1, 0),
            tail_runs=[TailRun(36, bytes([0x11, 0x22, 0x33, 0]), bytes([0xFF, 0xFF, 0xFF, 0]))],
        )
        self.assertEqual(_make_matcher([threshold]).validated_signature_count, 1)

        wildcard_heavy = _edge_make_signature(
            name="wildcardsDoNotRaiseEvidence",
            prefix_mask=prefix_mask,
            checksum=ChecksumSpan(32, 1, 0),
            tail_runs=[TailRun(36, bytes([0x11, 0x22, 0, 0, 0, 0, 0, 0]),
                               bytes([0xFF, 0xFF, 0, 0, 0, 0, 0, 0]))],
        )
        wildcard_matcher = _make_matcher([wildcard_heavy])
        self.assertEqual(wildcard_matcher.validated_signature_count, 0)
        self.assertIn("insufficientEvidence", _reasons(wildcard_matcher))

    def test_FunctionSignatureMatcherEdgeTests_testImportedReferencesDoNotReduceByteEvidenceFloor(self):
        """FunctionSignatureMatcherEdgeTests.swift: testImportedReferencesDoNotReduceByteEvidenceFloor"""
        signature = _edge_make_signature(
            name="referenceCannotSubstituteForBytes",
            prefix_mask=_edge_mask(12),
            checksum=ChecksumSpan(32, 1, 0),
            references=[ImportedReference(40, "_memcpy")],
        )
        matcher = _make_matcher([signature])
        self.assertEqual(matcher.validated_signature_count, 0)
        self.assertIn("insufficientEvidence", _reasons(matcher))

    def test_FunctionSignatureMatcherEdgeTests_testValidatorRejectsTailRunThatExtendsBeyondFunctionEnd(self):
        """FunctionSignatureMatcherEdgeTests.swift: testValidatorRejectsTailRunThatExtendsBeyondFunctionEnd"""
        signature = _edge_make_signature(
            name="tailPastEnd",
            tail_runs=[TailRun(60, bytes([0xAB] * 8), bytes([0xFF] * 8))],
        )
        matcher = _make_matcher([signature])
        self.assertEqual(matcher.validated_signature_count, 0)
        self.assertIn("invalidTailRun", _reasons(matcher))

    def test_FunctionSignatureMatcherEdgeTests_testValidatorRejectsPartiallyWildcardedReferenceInstructionInPrefix(self):
        """FunctionSignatureMatcherEdgeTests.swift: testValidatorRejectsPartiallyWildcardedReferenceInstructionInPrefix"""
        prefix_mask = bytearray([0xFF] * 32)
        prefix_mask[28] = 0
        prefix_mask[29] = 0
        signature = _edge_make_signature(
            name="partialReferenceWildcard",
            prefix_mask=bytes(prefix_mask),
            references=[ImportedReference(28, "_memcpy")],
        )
        matcher = _make_matcher([signature])
        self.assertEqual(matcher.validated_signature_count, 0)
        self.assertIn("overlappingVerificationEvidence", _reasons(matcher))

    def test_FunctionSignatureMatcherEdgeTests_testIndexLookupVisitsDistinctAnchorOffsets(self):
        """FunctionSignatureMatcherEdgeTests.swift: testIndexLookupVisitsDistinctAnchorOffsets"""
        common_suffix = bytes(range(4, 64))
        offset_zero_bytes = bytes([0x11] * 4) + common_suffix
        offset_four_bytes = bytes([0x22] * 4) + common_suffix

        offset_zero = _edge_make_matching_signature(offset_zero_bytes, name="offsetZero",
                                                    imported_reference=None)
        offset_four_mask = bytearray([0xFF] * 32)
        offset_four_mask[0:4] = bytes(4)
        offset_four = _edge_make_matching_signature(offset_four_bytes, name="offsetFour",
                                                    prefix_mask=bytes(offset_four_mask),
                                                    imported_reference=None)
        matcher = _make_matcher([offset_four, offset_zero])
        self.assertEqual(matcher.validated_signature_count, 2)
        self.assertUnique(matcher.match(Candidate(offset_four_bytes, {}, ARM64)), "offsetFour", "compiler-rt")

    def test_FunctionSignatureMatcherEdgeTests_testSchemaV1Arm64DiscriminantAndFullCollisionTailShapeAreStable(self):
        """FunctionSignatureMatcherEdgeTests.swift: testSchemaV1Arm64DiscriminantAndFullCollisionTailShapeAreStable"""
        first_run = TailRun(40, bytes([0xAA, 0]), bytes([0xFF, 0]))
        second_run = TailRun(44, bytes([0xBB, 0xCC]), bytes([0xFF, 0xFF]))
        first_reference = ImportedReference(48, "_memcpy")
        second_reference = ImportedReference(52, "_abort")
        byte_runs = (first_run, second_run)
        imported_references = (first_reference, second_reference)

        self.assertEqual(refmatch.ARCH_ARM64, 1)
        self.assertEqual(byte_runs, (first_run, second_run))
        self.assertEqual(imported_references, (first_reference, second_reference))
        self.assertEqual(byte_runs[0].offset, 40)
        self.assertEqual(byte_runs[0].bytes, bytes([0xAA, 0]))
        self.assertEqual(byte_runs[0].mask, bytes([0xFF, 0]))
        self.assertEqual(imported_references[1].instruction_offset, 52)
        self.assertEqual(imported_references[1].symbol_name, "_abort")


# ---------------------------------------------------------------------------------------------
# FunctionSignatureValidationTests.swift
# ---------------------------------------------------------------------------------------------

def _val_make_signature(
    name="___divti3",
    library_name="compiler-rt",
    total_length=64,
    prefix_bytes=bytes([0xA5] * 32),
    prefix_mask=bytes([0xFF] * 32),
    checksum=ChecksumSpan(32, 8, 0),
    tail_runs=(),
    references=(),
):
    return Signature(
        architecture=ARM64,
        name=name,
        library_name=library_name,
        total_length=total_length,
        prefix=MaskedPattern(bytes(prefix_bytes), bytes(prefix_mask)),
        checksum=checksum,
        tail_runs=tuple(tail_runs),
        references=tuple(references),
    )


def _run(offset, data, mask):
    return TailRun(offset, bytes(data), bytes(mask))


def _reference(offset, name="_memcpy"):
    return ImportedReference(offset, name)


class FunctionSignatureValidationTestsPort(_ResultAssertions):
    def assertValid(self, signature):
        matcher = _make_matcher([signature])
        self.assertEqual(matcher.validated_signature_count, 1)
        self.assertTrue(not matcher.validation_issues, "%r" % (matcher.validation_issues,))

    def assertInvalid(self, signature, includes):
        matcher = _make_matcher([signature])
        actual = set(_reasons(matcher))
        self.assertEqual(matcher.validated_signature_count, 0)
        for reason in includes:
            self.assertIn(reason, actual, "expected %s, got %s" % (reason, sorted(actual)))

    def test_FunctionSignatureValidationTests_testRecordNamesRejectEmptyWhitespaceAndControlText(self):
        """FunctionSignatureValidationTests.swift: testRecordNamesRejectEmptyWhitespaceAndControlText"""
        invalid_names = ["", " leading", "trailing ", "line\nfeed", "nul\0byte"]
        for index, name in enumerate(invalid_names):
            with self.subTest(name=name):
                self.assertInvalid(_val_make_signature(name=name, library_name="lib%d" % index),
                                   {"invalidName"})
        invalid_libraries = ["", " leading", "trailing ", "line\nfeed", "nul\0byte"]
        for index, library_name in enumerate(invalid_libraries):
            with self.subTest(library_name=library_name):
                self.assertInvalid(_val_make_signature(name="function%d" % index, library_name=library_name),
                                   {"invalidLibraryName"})

    def test_FunctionSignatureValidationTests_testImportedReferenceNamesRejectEmptyWhitespaceAndControlText(self):
        """FunctionSignatureValidationTests.swift: testImportedReferenceNamesRejectEmptyWhitespaceAndControlText"""
        for invalid_name in ["", " _memcpy", "_memcpy ", "_mem\ncpy", "_mem\0cpy"]:
            with self.subTest(invalid_name=invalid_name):
                self.assertInvalid(
                    _val_make_signature(references=[ImportedReference(48, invalid_name)]),
                    {"invalidImportedReference"},
                )

    def test_FunctionSignatureValidationTests_testRecordAndReferenceTextIsPreservedVerbatimWhenValid(self):
        """FunctionSignatureValidationTests.swift: testRecordAndReferenceTextIsPreservedVerbatimWhenValid"""
        self.assertValid(_val_make_signature(
            name="___divti3",
            library_name="compiler-rt builtins",
            references=[ImportedReference(48, "_memcpy$VARIANT$armv81")],
        ))

    def test_FunctionSignatureValidationTests_testTotalLengthMustBePositiveAlignedAndAtMostOneMiB(self):
        """FunctionSignatureValidationTests.swift: testTotalLengthMustBePositiveAlignedAndAtMostOneMiB"""
        for length in [0, 2, 66, 1_048_580]:
            with self.subTest(length=length):
                self.assertInvalid(_val_make_signature(total_length=length), {"invalidTotalLength"})
        self.assertValid(_val_make_signature(total_length=1_048_576))

    def test_FunctionSignatureValidationTests_testPrefixLengthIsExactlyFunctionLengthCappedAtThirtyTwoBytes(self):
        """FunctionSignatureValidationTests.swift: testPrefixLengthIsExactlyFunctionLengthCappedAtThirtyTwoBytes"""
        short = _val_make_signature(
            total_length=16,
            prefix_bytes=bytes([0xA5] * 16),
            prefix_mask=bytes([0xFF] * 16),
            checksum=ChecksumSpan(16, 0, 0),
        )
        self.assertValid(short)
        self.assertInvalid(_val_make_signature(prefix_bytes=bytes([0xA5] * 31)),
                           {"invalidPrefixLength", "prefixMaskLengthMismatch"})
        self.assertInvalid(
            _val_make_signature(
                total_length=16,
                prefix_bytes=bytes([0xA5] * 32),
                prefix_mask=bytes([0xFF] * 32),
                checksum=ChecksumSpan(16, 0, 0),
            ),
            {"invalidPrefixLength"},
        )

    def test_FunctionSignatureValidationTests_testPrefixMasksRequireEqualCountsBinaryValuesAndCanonicalWildcards(self):
        """FunctionSignatureValidationTests.swift: testPrefixMasksRequireEqualCountsBinaryValuesAndCanonicalWildcards"""
        self.assertInvalid(_val_make_signature(prefix_mask=bytes([0xFF] * 31)), {"prefixMaskLengthMismatch"})

        invalid_mask = bytearray([0xFF] * 32)
        invalid_mask[8] = 0x7F
        self.assertInvalid(_val_make_signature(prefix_mask=bytes(invalid_mask)), {"invalidPrefixMask"})

        wildcard_mask = bytearray([0xFF] * 32)
        wildcard_mask[8] = 0
        self.assertInvalid(_val_make_signature(prefix_mask=bytes(wildcard_mask)), {"noncanonicalWildcardByte"})

        canonical_bytes = bytearray([0xA5] * 32)
        canonical_bytes[8] = 0
        self.assertValid(_val_make_signature(prefix_bytes=bytes(canonical_bytes), prefix_mask=bytes(wildcard_mask)))

    def test_FunctionSignatureValidationTests_testPrefixRequiresAnAlignedFullyExactFourByteAnchor(self):
        """FunctionSignatureValidationTests.swift: testPrefixRequiresAnAlignedFullyExactFourByteAnchor"""
        mask = bytearray(32)
        mask[1:5] = bytes([0xFF] * 4)
        data = bytes(0 if m == 0 else b for b, m in zip([0xA5] * 32, mask))
        self.assertInvalid(_val_make_signature(prefix_bytes=data, prefix_mask=bytes(mask)), {"missingExactAnchor"})

    def test_FunctionSignatureValidationTests_testPrefixIndexSelectsLowestAlignedExactWordAndKeepsByteOrder(self):
        """FunctionSignatureValidationTests.swift: testPrefixIndexSelectsLowestAlignedExactWordAndKeepsByteOrder

        FunctionSignaturePrefixIndexKey.make(for:) is mirrored with the port's private
        `_first_anchor_offset` and the key shape built in `Matcher.__init__`.
        """
        mask = bytearray(32)
        mask[4:8] = bytes([0xFF] * 4)
        mask[12:16] = bytes([0xFF] * 4)
        data = bytearray(32)
        data[4:8] = bytes([0x11, 0x22, 0x33, 0x44])
        data[12:16] = bytes([0xAA, 0xBB, 0xCC, 0xDD])
        signature = _val_make_signature(prefix_bytes=bytes(data), prefix_mask=bytes(mask))

        anchor = refmatch._first_anchor_offset(signature.prefix.mask)
        self.assertIsNotNone(anchor)
        key = (signature.architecture, anchor, bytes(signature.prefix.bytes[anchor:anchor + 4]))
        self.assertEqual(key[0], ARM64)
        self.assertEqual(key[1], 4)
        self.assertEqual(key[2][0], 0x11)
        self.assertEqual(key[2][1], 0x22)
        self.assertEqual(key[2][2], 0x33)
        self.assertEqual(key[2][3], 0x44)

    def test_FunctionSignatureValidationTests_testCanonicalZeroChecksumIsAcceptedOnlyWhenPrefixCoversTheFunction(self):
        """FunctionSignatureValidationTests.swift: testCanonicalZeroChecksumIsAcceptedOnlyWhenPrefixCoversTheFunction"""
        self.assertValid(_val_make_signature(total_length=32, checksum=ChecksumSpan(32, 0, 0)))
        self.assertInvalid(_val_make_signature(checksum=ChecksumSpan(64, 0, 0)), {"noncanonicalZeroChecksum"})
        self.assertInvalid(_val_make_signature(checksum=ChecksumSpan(64, 0, 1)), {"noncanonicalZeroChecksum"})
        self.assertInvalid(_val_make_signature(checksum=ChecksumSpan(60, 0, 0)), {"noncanonicalZeroChecksum"})

    def test_FunctionSignatureValidationTests_testNonemptyChecksumMayHaveZeroCRCButMustFollowPrefixAndFitFunction(self):
        """FunctionSignatureValidationTests.swift: testNonemptyChecksumMayHaveZeroCRCButMustFollowPrefixAndFitFunction"""
        self.assertValid(_val_make_signature(checksum=ChecksumSpan(32, 4, 0)))
        self.assertInvalid(_val_make_signature(checksum=ChecksumSpan(28, 4, 1)), {"invalidChecksumRange"})
        self.assertInvalid(_val_make_signature(checksum=ChecksumSpan(60, 8, 1)), {"invalidChecksumRange"})

    def test_FunctionSignatureValidationTests_testTailRunsMustBeNonemptySortedNonoverlappingAndAfterChecksum(self):
        """FunctionSignatureValidationTests.swift: testTailRunsMustBeNonemptySortedNonoverlappingAndAfterChecksum"""
        self.assertInvalid(_val_make_signature(tail_runs=[_run(40, [], [])]), {"invalidTailRun"})
        self.assertInvalid(_val_make_signature(tail_runs=[_run(39, [0xA5], [0xFF])]), {"invalidTailRun"})
        self.assertInvalid(
            _val_make_signature(tail_runs=[_run(44, [0xA5], [0xFF]), _run(40, [0xA5], [0xFF])]),
            {"invalidTailRun"},
        )
        self.assertInvalid(
            _val_make_signature(tail_runs=[_run(40, [1, 2, 3, 4], [0xFF] * 4), _run(43, [5], [0xFF])]),
            {"invalidTailRun"},
        )
        self.assertValid(
            _val_make_signature(tail_runs=[_run(40, [1, 2, 3, 4], [0xFF] * 4), _run(44, [5], [0xFF])])
        )

    def test_FunctionSignatureValidationTests_testTailRunMasksRequireEqualCountsBinaryValuesExactEvidenceAndCanonicalWildcards(self):
        """FunctionSignatureValidationTests.swift: testTailRunMasksRequireEqualCountsBinaryValuesExactEvidenceAndCanonicalWildcards"""
        self.assertInvalid(_val_make_signature(tail_runs=[_run(40, [0xA5], [])]), {"invalidTailRun"})
        self.assertInvalid(_val_make_signature(tail_runs=[_run(40, [0xA5], [0x7F])]), {"invalidTailRun"})
        self.assertInvalid(_val_make_signature(tail_runs=[_run(40, [0xA5], [0])]),
                           {"invalidTailRun", "noncanonicalWildcardByte"})
        self.assertInvalid(_val_make_signature(tail_runs=[_run(40, [0], [0])]), {"invalidTailRun"})

    def test_FunctionSignatureValidationTests_testTailRunCapsAllowEightRunsAndThirtyTwoConstrainedBytes(self):
        """FunctionSignatureValidationTests.swift: testTailRunCapsAllowEightRunsAndThirtyTwoConstrainedBytes"""
        eight_runs = [_run(40 + i, [i], [0xFF]) for i in range(8)]
        self.assertValid(_val_make_signature(tail_runs=eight_runs))

        nine_runs = [_run(40 + i, [i], [0xFF]) for i in range(9)]
        self.assertInvalid(_val_make_signature(tail_runs=nine_runs), {"tooManyTailRuns"})

        self.assertValid(_val_make_signature(total_length=80, tail_runs=[_run(40, [0xA5] * 32, [0xFF] * 32)]))
        self.assertInvalid(
            _val_make_signature(total_length=80, tail_runs=[_run(40, [0xA5] * 33, [0xFF] * 33)]),
            {"tooManyConstrainedTailBytes"},
        )

    def test_FunctionSignatureValidationTests_testImportedReferencesMustBeSortedUniqueAlignedAndWithinFunction(self):
        """FunctionSignatureValidationTests.swift: testImportedReferencesMustBeSortedUniqueAlignedAndWithinFunction"""
        self.assertInvalid(_val_make_signature(references=[_reference(44), _reference(40)]),
                           {"invalidImportedReference"})
        self.assertInvalid(_val_make_signature(references=[_reference(44), _reference(44)]),
                           {"invalidImportedReference"})
        self.assertInvalid(_val_make_signature(references=[_reference(42)]), {"invalidImportedReference"})
        self.assertInvalid(_val_make_signature(references=[_reference(64)]), {"invalidImportedReference"})
        self.assertValid(_val_make_signature(references=[_reference(40), _reference(44), _reference(48)]))

    def test_FunctionSignatureValidationTests_testImportedReferenceCapAllowsEightAndRejectsNine(self):
        """FunctionSignatureValidationTests.swift: testImportedReferenceCapAllowsEightAndRejectsNine"""
        eight = [_reference(40 + i * 4) for i in range(8)]
        self.assertValid(_val_make_signature(total_length=80, references=eight))
        nine = [_reference(40 + i * 4) for i in range(9)]
        self.assertInvalid(_val_make_signature(total_length=80, references=nine), {"tooManyImportedReferences"})

    def test_FunctionSignatureValidationTests_testImportedReferencesCannotOverlapChecksumExactTailOrExactPrefixBytes(self):
        """FunctionSignatureValidationTests.swift: testImportedReferencesCannotOverlapChecksumExactTailOrExactPrefixBytes"""
        self.assertInvalid(_val_make_signature(references=[_reference(36)]), {"overlappingVerificationEvidence"})
        self.assertInvalid(
            _val_make_signature(tail_runs=[_run(44, [0xA5], [0xFF])], references=[_reference(44)]),
            {"overlappingVerificationEvidence"},
        )
        self.assertInvalid(_val_make_signature(references=[_reference(4)]), {"overlappingVerificationEvidence"})

    def test_FunctionSignatureValidationTests_testImportedReferenceMayOverlapOnlyWildcardedPrefixOrTailBytes(self):
        """FunctionSignatureValidationTests.swift: testImportedReferenceMayOverlapOnlyWildcardedPrefixOrTailBytes"""
        prefix_bytes = bytearray([0xA5] * 32)
        prefix_mask = bytearray([0xFF] * 32)
        prefix_bytes[4:8] = bytes(4)
        prefix_mask[4:8] = bytes(4)
        self.assertValid(_val_make_signature(prefix_bytes=bytes(prefix_bytes), prefix_mask=bytes(prefix_mask),
                                             references=[_reference(4)]))
        self.assertValid(_val_make_signature(
            tail_runs=[_run(44, [0, 0, 0, 0, 0xA5], [0, 0, 0, 0, 0xFF])],
            references=[_reference(44)],
        ))

    def test_FunctionSignatureValidationTests_testEvidenceFloorRejectsOneHundredTwentyBitsAndAcceptsOneHundredTwentyEight(self):
        """FunctionSignatureValidationTests.swift: testEvidenceFloorRejectsOneHundredTwentyBitsAndAcceptsOneHundredTwentyEight"""
        fifteen_byte_mask = bytearray(32)
        fifteen_byte_mask[0:15] = bytes([0xFF] * 15)
        fifteen_byte_prefix = bytes(0 if m == 0 else 0xA5 for m in fifteen_byte_mask)
        self.assertInvalid(
            _val_make_signature(total_length=32, prefix_bytes=fifteen_byte_prefix,
                                prefix_mask=bytes(fifteen_byte_mask), checksum=ChecksumSpan(32, 0, 0)),
            {"insufficientEvidence"},
        )
        sixteen_byte_mask = bytearray(fifteen_byte_mask)
        sixteen_byte_mask[15] = 0xFF
        sixteen_byte_prefix = bytes(0 if m == 0 else 0xA5 for m in sixteen_byte_mask)
        self.assertValid(
            _val_make_signature(total_length=32, prefix_bytes=sixteen_byte_prefix,
                                prefix_mask=bytes(sixteen_byte_mask), checksum=ChecksumSpan(32, 0, 0))
        )

    def test_FunctionSignatureValidationTests_testOffsetArithmeticNearUInt32MaximumFailsClosedWithoutTrapping(self):
        """FunctionSignatureValidationTests.swift: testOffsetArithmeticNearUInt32MaximumFailsClosedWithoutTrapping"""
        self.assertInvalid(_val_make_signature(checksum=ChecksumSpan(UINT32_MAX - 1, 4, 1)), {"invalidChecksumRange"})
        self.assertInvalid(_val_make_signature(tail_runs=[_run(UINT32_MAX, [0xA5], [0xFF])]), {"invalidTailRun"})
        self.assertInvalid(_val_make_signature(references=[_reference(UINT32_MAX - 3)]), {"invalidImportedReference"})

    def test_FunctionSignatureValidationTests_testDuplicatePredicatesKeepOneCopyForSameIdentity(self):
        """FunctionSignatureValidationTests.swift: testDuplicatePredicatesKeepOneCopyForSameIdentity"""
        signature = _val_make_signature(name="same", library_name="sameLibrary")
        matcher = _make_matcher([signature, signature])
        self.assertEqual(matcher.validated_signature_count, 1)
        self.assertEqual(len(matcher.validation_issues), 1)
        self.assertEqual(_reasons(matcher), ["duplicatePredicate"])
        self.assertEqual([issue.identity for issue in matcher.validation_issues],
                         [Identity("same", "sameLibrary")] * 1)

    def test_FunctionSignatureValidationTests_testValidationIssuesAndAcceptedCountAreIndependentOfInputOrder(self):
        """FunctionSignatureValidationTests.swift: testValidationIssuesAndAcceptedCountAreIndependentOfInputOrder"""
        invalid_name = _val_make_signature(name=" bad", library_name="z")
        invalid_library = _val_make_signature(name="alpha", library_name=" bad")
        invalid_length = _val_make_signature(name="middle", library_name="m", total_length=66)
        valid = _val_make_signature(name="valid", library_name="a")

        forward = _make_matcher([invalid_name, invalid_library, invalid_length, valid])
        reverse = _make_matcher([valid, invalid_length, invalid_library, invalid_name])

        self.assertEqual(forward.validated_signature_count, 1)
        self.assertEqual(reverse.validated_signature_count, 1)
        self.assertEqual(forward.validation_issues, reverse.validation_issues)
        self.assertEqual(_reasons(forward), ["invalidLibraryName", "invalidName", "invalidTotalLength"])


# ---------------------------------------------------------------------------------------------
# FunctionSignatureLibraryPackTests.swift
# ---------------------------------------------------------------------------------------------

def _pack_record(name):
    data = bytes([0, 0, 0x80, 0xd2, 0x21, 0, 0x80, 0xd2, 0x42, 0, 0x80, 0xd2, 0xc0, 3, 0x5f, 0xd6])
    return Signature(
        architecture=ARM64,
        name=name,
        library_name="DOT01-fixture",
        total_length=16,
        prefix=MaskedPattern(data, bytes([255] * 16)),
        checksum=ChecksumSpan(16, 0, 0),
        tail_runs=(),
        references=(),
    )


class FunctionSignatureLibraryPackTestsPort(_ResultAssertions):
    def test_FunctionSignatureLibraryPackTests_testEqualPredicatesWithDifferentNamesRemainAmbiguous(self):
        """FunctionSignatureLibraryPackTests.swift: testEqualPredicatesWithDifferentNamesRemainAmbiguous"""
        a, b = _pack_record("first"), _pack_record("second")
        matcher = _make_matcher([a, b], schema_version=1)
        self.assertEqual(matcher.validated_signature_count, 2)
        self.assertAmbiguous(
            matcher.match(Candidate(a.prefix.bytes, {}, ARM64)),
            [("first", "DOT01-fixture"), ("second", "DOT01-fixture")],
        )

    def test_FunctionSignatureLibraryPackTests_testRepeatedIdenticalIdentityKeepsOneUsablePredicate(self):
        """FunctionSignatureLibraryPackTests.swift: testRepeatedIdenticalIdentityKeepsOneUsablePredicate"""
        a = _pack_record("first")
        matcher = _make_matcher([a, a], schema_version=1)
        self.assertEqual(matcher.validated_signature_count, 1)
        self.assertEqual(_reasons(matcher), ["duplicatePredicate"])
        self.assertUnique(matcher.match(Candidate(a.prefix.bytes, {}, ARM64)), "first", "DOT01-fixture")


if __name__ == "__main__":
    unittest.main()
