"""Bind a newly emitted assisted body to an existing RG3 snapshot request.

No image loading, hashing, compilation, execution or receipt creation occurs.
The exporter supplies the captured identity; the emitter never manufactures it.
"""
from __future__ import annotations
from copy import deepcopy
import re
import json
from uuid import UUID
from compilation_adapter import adapt, Parameter, UnsupportedExport


def emit_bound_body(request: dict, pseudocode: str, *, function_uuid: str, source_binding: dict, prototype: str,
                    parameters: tuple[Parameter, ...], symbol_map: dict[str, str],
                    disassembly: str, prototype_authority: dict) -> dict:
    """Consume schema-1 captured coordinates and return a filled-only candidate.

    This is a request/response binding, not an assertion that arbitrary JSON is
    trusted. The native consumer must compare every image/function field with
    its current already-admitted snapshot before installing the source.
    """
    def require(value, message):
        if not value:
            raise UnsupportedExport(message)

    require(type(request) is dict and request.get('schema') == 'macscope-rg3-c-body-request-v1',
            'unsupported captured body request schema')
    def canonical_image(value):
        required = {'imageSlot', 'architecture', 'selectedSliceSHA256', 'analysisFingerprintSHA256'}
        require(type(value) is dict and required <= set(value) <= required | {'selectedSliceIndex'},
                'missing exact captured image identity')
        # Native synthesized Codable omits a nil optional. Canonicalize only for
        # comparison; preserve the request's original representation in output.
        canonical = dict(value)
        canonical.setdefault('selectedSliceIndex', None)
        require(type(canonical['imageSlot']) is int and canonical['imageSlot'] >= 0,
                'invalid captured image slot')
        index = canonical['selectedSliceIndex']
        require(index is None or type(index) is int and index >= 0, 'invalid captured slice index')
        require(canonical['architecture'] == 'arm64', 'unsupported captured architecture')
        for key in ('selectedSliceSHA256', 'analysisFingerprintSHA256'):
            require(isinstance(canonical[key], str) and re.fullmatch('[0-9a-f]{64}', canonical[key]),
                    'missing captured image digest/fingerprint')
        return canonical

    image = request.get('image')
    captured_image = canonical_image(image)
    functions = request.get('functions')
    require(type(functions) is list and 0 < len(functions) <= 100_000,
            'missing bounded captured function list')
    try:
        selected_uuid = UUID(function_uuid)
        ids = [UUID(item['functionUUID']) for item in functions]
    except (ValueError, TypeError, AttributeError, KeyError):
        raise UnsupportedExport('invalid requested function UUID') from None
    require(len(set(ids)) == len(ids), 'duplicate request function identity')
    matches = [item for item, uuid in zip(functions, ids) if uuid == selected_uuid]
    require(len(matches) == 1, 'requested function identity is absent or ambiguous')
    function = matches[0]
    require(set(function) == {'functionUUID', 'address', 'endAddressExclusive',
                             'emittedSymbol', 'name', 'language'},
            'missing exact captured function coordinate')
    require(function['language'] in ('c', 'unknown'), 'non-C requested function')
    try:
        uuid = UUID(function['functionUUID'])
    except (ValueError, TypeError, AttributeError):
        raise UnsupportedExport('missing captured function UUID') from None
    expected = 'msrg_recovered_' + uuid.hex
    require(function['emittedSymbol'] == expected, 'output symbol does not match captured function UUID')
    for key in ('address', 'endAddressExclusive'):
        require(isinstance(function[key], str) and re.fullmatch(r'0x[0-9a-f]{1,16}', function[key]),
                'function coordinates must be lossless hexadecimal addresses')
    require(int(function['address'], 16) < int(function['endAddressExclusive'], 16),
            'invalid captured function range')
    require(type(prototype_authority) is dict and
            prototype_authority.get('kind') in ('benchmark-original-source-not-inferred', 'authored-signature') and
            isinstance(prototype_authority.get('reference'), str) and prototype_authority['reference'].strip(),
            'explicit prototype authority is required')
    # A request labels an export destination; it is NOT source provenance.
    # Reuse separately captured source identity, and refuse historical packets
    # that never recorded it. Matching addresses alone cannot establish this.
    require(type(source_binding) is dict, 'source receipt lacks matching captured image identity')
    require(canonical_image(source_binding.get('image')) == captured_image,
            'source receipt lacks matching captured image identity')
    require(source_binding.get('functionUUID') == function['functionUUID'] and
            source_binding.get('address') == function['address'] and
            source_binding.get('endAddressExclusive') == function['endAddressExclusive'],
            'source receipt lacks matching captured function identity')
    require(isinstance(source_binding.get('captureReceipt'), str) and
            0 < len(source_binding['captureReceipt'].encode()) <= 4096,
            'source receipt reference is required')
    authority = json.dumps(prototype_authority, sort_keys=True, separators=(',', ':'))
    require(len(authority.encode()) <= 4096, 'prototype authority exceeds native packet bound')
    # The requested range must correspond to these retained decoded rows.
    addresses = [int(value, 16) for value in re.findall(r'^([0-9a-fA-F]+):\s', disassembly, re.M)]
    require(bool(addresses) and addresses[0] == int(function['address'], 16)
            and addresses[-1] + 4 == int(function['endAddressExclusive'], 16)
            and len(set(addresses)) == len(addresses)
            and all(b == a + 4 for a, b in zip(addresses, addresses[1:])),
            'retained disassembly range does not match captured request')
    exported = adapt(pseudocode, prototype=prototype, parameters=parameters,
                     symbol_map=symbol_map, disassembly=disassembly, emitted_name=expected)
    return {
        'schema': 'macscope-rg3-c-bodies-v1',
        'bodies': [{
            'image': deepcopy(image),
            'functionUUID': function['functionUUID'],
            'address': function['address'],
            'endAddressExclusive': function['endAddressExclusive'],
            'source': exported.source,
            'emittedSymbol': exported.emitted_symbol,
            'prototypeAuthority': authority,
            'rules': list(exported.rules) + ['CAPTURE-BINDING-REUSED'],
            'producerReceipt': source_binding['captureReceipt'],
        }],
    }
