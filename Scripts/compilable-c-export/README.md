# Signature-assisted C bodies

`compilation_adapter.adapt` emits a bounded scalar leaf from retained pseudocode,
explicit source prototype and ABI bindings, and retained disassembly. It does not
infer a prototype from ABI register order. `rg3_packet.emit_bound_body` binds a new
output to a selected function in a native `C-BODY-REQUEST.json`.

The request is emitted by normal project export from the existing captured image
identity. The producer also requires a separately captured `source_binding` with
that same image, function UUID, exact address range, and capture receipt. Copying
request fields is not evidence that source belongs to the image. Missing historical
identity stays missing: never invent a digest/UUID or reload an input to fill it in
without the user's specific authority.

The pure producer entry point is:

```python
from compilation_adapter import Parameter
from rg3_packet import emit_bound_body

packet = emit_bound_body(
    request, retained_pseudocode,
    function_uuid=selected_function_uuid,
    source_binding=retained_source_binding,
    prototype=explicit_prototype,
    parameters=explicit_source_ordered_parameters,
    symbol_map=retained_symbol_map,
    disassembly=retained_disassembly,
    prototype_authority={"kind": authority_kind, "reference": authority_reference},
)
```

Serialize `packet` as JSON. Pass its absolute path as optional `cBodiesPath` to the
existing live-workspace `export-project` command along with `appPath` and a new
`outputDirectory`. The native consumer matches the full image identity, UUID and
range against its captured input. It refuses missing/mismatched bindings and leaves
those stubs intact. Malformed or duplicate candidates fail the transaction before
publication. C and unknown-language functions need explicit C prototype authority;
Objective-C and Swift bodies are not admitted by this path.

The producer emits a fresh collision-safe `msrg_recovered_<UUID>` symbol. Never
rename an already-compiled source and carry its old receipt to the renamed source.
The consumer preserves the emitted translation unit byte-for-byte under
`Decompiled/C`, archives the original placeholder under `Support/OriginalStubs`,
and replaces its `Sources/C` file with one include. Static helpers are not compiled
as a second translation unit. The synthetic project entrypoint is unchanged.

Manifest state is **filled**, not `compiles` or `accepted`. Producer receipt fields
are references, not compile authority. Compilation, runtime equivalence, original
ABI replacement and application behavior remain unestablished by this import.
Unknown caller JSON fields cannot promote state. This path never runs a compiler,
executes recovered code, enables benchmark queues, or hashes/reloads an image.

The current supported source envelope contains the standard integer/math headers,
the adapter's allowlisted static numeric helpers, and one int-returning function.
Unsupported helpers, global definitions and directives are refused rather than
patched. Source formatting is a versioned producer/consumer contract.

Preserve passing evidence. A normal export may perform resource conversion and
project generation; this interface is not permission to repeat an already-verified
export or fixture admission. Use only separately authorized new/changed work.
