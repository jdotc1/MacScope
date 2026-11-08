#!/usr/bin/env python3
"""Extract one bounded, include-free authored header into SDKTypeArchive v1.

libclang is loaded only by a subprocess. No compiler plugin, AST serialization,
function body execution, SDK crawl or shipped compiler dependency is involved.
Includes require an explicit bounded header manifest; implicit discovery is refused.
C API declarations: https://clang.llvm.org/docs/LibClang.html and clang-c/Index.h.
"""
from __future__ import annotations

import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata

sys.path.insert(0, str(Path(__file__).resolve().parent))
import clang_import_configuration as configuration

MAX_SOURCE = 256 * 1024
MAX_ARCHIVE = 16 * 1024 * 1024
MAX_HEADERS = 128
MAX_CLOSURE_BYTES = 8 * 1024 * 1024
MAX_CLOSURE_MANIFEST = 64 * 1024
MAX_NODES = 10_000
MAX_FIELDS = 4096
WORKER_SECONDS = 30


class ExtractionError(ValueError):
    pass


class CXString(C.Structure):
    _fields_ = [("data", C.c_void_p), ("private_flags", C.c_uint)]


class CXCursor(C.Structure):
    _fields_ = [("kind", C.c_uint), ("xdata", C.c_int), ("data", C.c_void_p * 3)]


class CXType(C.Structure):
    _fields_ = [("kind", C.c_uint), ("data", C.c_void_p * 2)]


class CXLocation(C.Structure):
    _fields_ = [("ptr_data", C.c_void_p * 2), ("int_data", C.c_uint)]


class CXUnsavedFile(C.Structure):
    _fields_ = [("filename", C.c_char_p), ("contents", C.c_char_p), ("length", C.c_ulong)]


CHILD_VISITOR = C.CFUNCTYPE(C.c_uint, CXCursor, CXCursor, C.c_void_p)
FIELD_VISITOR = C.CFUNCTYPE(C.c_uint, CXCursor, C.c_void_p)


class Clang:
    def __init__(self, library: Path):
        self.lib = C.CDLL(str(library))
        declarations = {
            "createIndex": (C.c_void_p, [C.c_int, C.c_int]),
            "disposeIndex": (None, [C.c_void_p]),
            "parseTranslationUnit2": (C.c_int, [C.c_void_p, C.c_char_p, C.POINTER(C.c_char_p), C.c_int,
                                               C.POINTER(CXUnsavedFile), C.c_uint, C.c_uint, C.POINTER(C.c_void_p)]),
            "disposeTranslationUnit": (None, [C.c_void_p]),
            "getTranslationUnitCursor": (CXCursor, [C.c_void_p]),
            "getClangVersion": (CXString, []), "getCString": (C.c_char_p, [CXString]),
            "disposeString": (None, [CXString]),
            "visitChildren": (C.c_uint, [CXCursor, CHILD_VISITOR, C.c_void_p]),
            "Type_visitFields": (C.c_uint, [CXType, FIELD_VISITOR, C.c_void_p]),
            "getCursorType": (CXType, [CXCursor]), "getTypeDeclaration": (CXCursor, [CXType]),
            "getCursorSpelling": (CXString, [CXCursor]), "getCursorUSR": (CXString, [CXCursor]),
            "getTypeSpelling": (CXString, [CXType]), "getCanonicalType": (CXType, [CXType]),
            "Type_getNamedType": (CXType, [CXType]), "getPointeeType": (CXType, [CXType]),
            "getArrayElementType": (CXType, [CXType]), "getArraySize": (C.c_longlong, [CXType]),
            "getTypedefDeclUnderlyingType": (CXType, [CXCursor]),
            "getEnumDeclIntegerType": (CXType, [CXCursor]),
            "getEnumConstantDeclValue": (C.c_longlong, [CXCursor]),
            "getEnumConstantDeclUnsignedValue": (C.c_ulonglong, [CXCursor]),
            "Type_getSizeOf": (C.c_longlong, [CXType]), "Type_getAlignOf": (C.c_longlong, [CXType]),
            "Cursor_getOffsetOfField": (C.c_longlong, [CXCursor]),
            "Cursor_isAnonymousRecordDecl": (C.c_uint, [CXCursor]),
            "Cursor_isBitField": (C.c_uint, [CXCursor]), "getFieldDeclBitWidth": (C.c_int, [CXCursor]),
            "isConstQualifiedType": (C.c_uint, [CXType]), "isVolatileQualifiedType": (C.c_uint, [CXType]),
            "isRestrictQualifiedType": (C.c_uint, [CXType]),
            "getCursorLocation": (CXLocation, [CXCursor]),
            "getSpellingLocation": (None, [CXLocation, C.POINTER(C.c_void_p), C.POINTER(C.c_uint), C.POINTER(C.c_uint), C.POINTER(C.c_uint)]),
            "getFileName": (CXString, [C.c_void_p]),
            "getNumDiagnostics": (C.c_uint, [C.c_void_p]), "getDiagnostic": (C.c_void_p, [C.c_void_p, C.c_uint]),
            "getDiagnosticSeverity": (C.c_uint, [C.c_void_p]), "getDiagnosticSpelling": (CXString, [C.c_void_p]),
            "disposeDiagnostic": (None, [C.c_void_p]),
        }
        for name, (result, arguments) in declarations.items():
            try:
                function = getattr(self.lib, "clang_" + name)
            except AttributeError as error:
                raise ExtractionError("required libclang capability missing: " + name) from error
            function.restype, function.argtypes = result, arguments
            setattr(self, name, function)

    def string(self, value: CXString) -> str:
        try:
            result = (self.getCString(value) or b"").decode("utf-8", "strict")
            if len(result.encode()) > 16384:
                raise ExtractionError("libclang string exceeds bound")
            return result
        finally:
            self.disposeString(value)

    def children(self, cursor: CXCursor) -> list[CXCursor]:
        result = []
        @CHILD_VISITOR
        def visit(child, parent, context):
            result.append(child)
            return 0 if len(result) > MAX_NODES else 1
        self.visitChildren(cursor, visit, None)
        if len(result) > MAX_NODES:
            raise ExtractionError("cursor count exceeds bound")
        return result

    def fields(self, kind: CXType) -> list[CXCursor]:
        result = []
        @FIELD_VISITOR
        def visit(field, context):
            result.append(field)
            return 0 if len(result) > MAX_FIELDS else 1
        self.Type_visitFields(kind, visit, None)
        if len(result) > MAX_FIELDS:
            raise ExtractionError("field count exceeds bound")
        return result

    def origin(self, cursor: CXCursor, source: Path, header_names: dict | None = None) -> dict | None:
        file = C.c_void_p()
        line, column, offset = C.c_uint(), C.c_uint(), C.c_uint()
        self.getSpellingLocation(self.getCursorLocation(cursor), C.byref(file), C.byref(line), C.byref(column), C.byref(offset))
        if not file.value:
            return None
        path = Path(self.string(self.getFileName(file))).resolve()
        names = header_names or {source: source.name}
        if path not in names:
            raise ExtractionError("declaration outside the explicit header closure")
        return {"header": names[path], "line": line.value, "column": column.value}


def checked_source(source: Path, *, allow_includes: bool = False) -> bytes:
    # Capture a stable, regular file; this is construction-time reading, not admission.
    import stat
    before = source.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_SOURCE:
        raise ExtractionError("input must be one bounded regular header")
    with source.open("rb") as stream:
        opened = os.fstat(stream.fileno())
        data = stream.read(MAX_SOURCE + 1)
        after = os.fstat(stream.fileno())
    signature = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if (len(data) > MAX_SOURCE or len(data) != before.st_size
            or any(signature(item) != signature(before) for item in (opened, after, source.lstat()))):
        raise ExtractionError("header changed during bounded read")
    logical = data.decode("utf-8").replace("\\\r\n", "").replace("\\\n", "").replace("??=", "#").replace("%:", "#")
    logical = re.sub(r"/\*.*?\*/|//[^\n]*", " ", logical, flags=re.S)
    if not allow_includes and re.search(r"(?m)^\s*#\s*(?:include|include_next|import|embed)\b", logical):
        raise ExtractionError("includes require an explicit header closure")
    return data


def load_header_manifest(path: Path) -> dict[str, Path]:
    if path.is_symlink() or path.stat().st_size > MAX_CLOSURE_MANIFEST:
        raise ExtractionError("header manifest must be bounded and ordinary")
    data = path.read_bytes()
    if len(data) > MAX_CLOSURE_MANIFEST:
        raise ExtractionError("header manifest exceeds bound")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result: raise ExtractionError("duplicate header manifest key")
            result[key] = value
        return result
    value = json.loads(data, object_pairs_hook=unique)
    if not isinstance(value, dict) or len(value) >= MAX_HEADERS:
        raise ExtractionError("header manifest must map fewer than128 include names to explicit paths")
    result = {}
    for name, physical in value.items():
        if (not isinstance(name, str) or not name or len(name.encode()) > 1024
                or Path(name).is_absolute() or ".." in Path(name).parts
                or name != Path(name).as_posix() or any(c in name for c in '\0\r\n"<>\\')
                or not isinstance(physical, str) or not Path(physical).is_absolute()):
            raise ExtractionError("invalid explicit header mapping")
        result[name] = Path(physical)
    return result


def prepare_header_closure(source: Path, headers: dict[str, Path] | None = None):
    # Include names are explicit, not a request to walk -I/-F roots or an SDK.
    mapping = {source.name: source}
    if headers is not None:
        for name, path in headers.items():
            if (not isinstance(name, str) or not name or len(name.encode()) > 1024
                    or Path(name).is_absolute() or ".." in Path(name).parts
                    or name != Path(name).as_posix() or any(c in name for c in '\0\r\n"<>\\')
                    or not isinstance(path, Path) or not path.is_absolute()):
                raise ExtractionError("invalid explicit header mapping")
    for name, path in (headers or {}).items():
        if name in mapping: raise ExtractionError("entry header name collides with closure")
        mapping[name] = path
    if len(mapping) > MAX_HEADERS: raise ExtractionError("header count exceeds bound")
    original, names, physical = {}, {}, {}
    total = 0
    for name, path in mapping.items():
        data = checked_source(path, allow_includes=headers is not None)
        canonical = path.resolve(strict=True)
        if canonical in names: raise ExtractionError("header paths alias each other")
        if any(c in str(canonical) for c in '\0\r\n"\\'):
            raise ExtractionError("header path cannot be represented literally")
        total += len(data)
        if total > MAX_CLOSURE_BYTES: raise ExtractionError("aggregate header bytes exceed bound")
        original[canonical], names[canonical], physical[name] = data, name, canonical
    rewritten = {}
    for path, data in original.items():
        text = data.decode("utf-8")
        # Clang also accepts FF/VT and normalizes CR. Reject rather than let
        # unsupported preprocessing whitespace bypass the literal-directive gate.
        if any((ord(c) < 32 and c not in "\t\n") or ord(c) == 127
               or (c.isspace() and c not in " \t\n") for c in text):
            raise ExtractionError("unsupported preprocessing whitespace/control")
        # Refuse disguised/continued directives instead of guessing preprocessor tokens.
        if headers is not None and (re.search(r"(?m)^\s*%:", text) or "??" in text or re.search(r"\\\r?\n", text) or 'R"' in text):
            raise ExtractionError("alternative/continued preprocessing requires a separate reviewed adapter")
        masked = re.sub(r'/\*.*?\*/|//[^\n]*',
                        lambda match: ''.join('\n' if c == '\n' else ' ' for c in match[0]), text, flags=re.S)
        if re.search(r"\b(?:__has_include|__has_include_next|__has_embed|_Pragma|__pragma)\b", masked):
            # Even a probe can consult unlisted filesystem metadata. Indirect
            # pragma strings can request module reads outside the literal gate.
            raise ExtractionError("include probes and indirect pragmas require separate admission")
        if re.search(r"@\s*import\b|(?m:^\s*(?:export\s+)?import\b)", masked):
            raise ExtractionError("module imports are outside explicit header closure")
        for pragma in re.finditer(r"(?m)^[ \t]*#[ \t]*pragma\b([^\n]*)", masked):
            body = pragma[1].strip()
            # These forms affect only this translation unit's record layout or
            # repeated-header state; file/module/dependency pragmas are excluded.
            if not re.fullmatch(r"once|pack[ \t]*\([ \t]*(?:(?:push|pop)(?:[ \t]*,[ \t]*(?:1|2|4|8|16))?|(?:1|2|4|8|16))?[ \t]*\)", body):
                raise ExtractionError("unsupported pragma outside explicit header closure")
        replacements = []
        for match in re.finditer(r"(?m)^[ \t]*#[ \t]*(include_next|include|import|embed)\b([^\n]*)", masked):
            directive, operand = match.group(1), match.group(2).strip()
            literal = re.fullmatch(r'"([^"<>]+)"|<([^"<>]+)>', operand)
            if directive not in ("include", "import") or literal is None:
                raise ExtractionError("only literal admitted include/import directives are supported")
            requested = literal[1] or literal[2]
            relative = (Path(names[path]).parent / requested).as_posix()
            candidates = [relative, requested] if operand.startswith('"') else [requested]
            selected = next((name for name in candidates if name in physical), None)
            if selected is None: raise ExtractionError("include missing from explicit header closure: " + requested)
            target = physical[selected]
            replacements.append((match.start(), match.end(), '#'+directive+' "'+str(target)+'"'))
        for begin, end, replacement in reversed(replacements): text = text[:begin]+replacement+text[end:]
        rewritten[path] = text.encode("utf-8")
    return original, rewritten, names


def declaration_seeds(clang, root):
    pending = list(clang.children(root))
    examined = 0
    while pending:
        cursor = pending.pop(0); examined += 1
        if examined > MAX_NODES: raise ExtractionError("declaration traversal exceeds bound")
        if cursor.kind in (2, 3, 4, 5, 20):
            yield cursor
            if cursor.kind in (2, 3, 4): pending.extend(clang.children(cursor))
        elif cursor.kind in (22, 23):  # namespaces and linkage specifications
            pending.extend(clang.children(cursor))


def record_layout(size, alignment, child_kinds):
    if any(kind in (21, 24, 25, 44) for kind in child_kinds):
        return {"status": "unknown", "reason": "C++ base/member-function ABI is not represented in archive v1"}
    if size >= 0 and alignment > 0:
        return {"status": "known", "sizeBytes": size, "alignmentBytes": alignment}
    return {"status": "unknown", "reason": f"libclang layout: size={size}, alignment={alignment}"}


def extract_in_worker(config: dict, source: Path, data: bytes, headers: dict | None = None) -> dict:
    if configuration.configuration_id(config) != config.get("configurationID"):
        raise ExtractionError("configuration identity mismatch")
    original, rewritten, header_names = prepare_header_closure(source, headers)
    if original[source] != data:
        raise ExtractionError("entry header changed before parse")
    library = Path(config["compiler"]).parent.parent / "lib/libclang.dylib"
    clang = Clang(library)
    index = clang.createIndex(0, 0)
    if not index:
        raise ExtractionError("libclang index creation failed")
    unit = C.c_void_p()
    arguments = [arg.encode() for arg in config["arguments"]]
    argv = (C.c_char_p * len(arguments))(*arguments)
    filename = os.fsencode(source)
    # Keep byte buffers alive for the complete libclang call. No unlisted include remains.
    buffers = [(os.fsencode(path), contents) for path, contents in rewritten.items()]
    unsaved = (CXUnsavedFile * len(buffers))(*(CXUnsavedFile(name, contents, len(contents)) for name, contents in buffers))
    try:
        error = clang.parseTranslationUnit2(index, filename, argv, len(arguments), unsaved, len(buffers), 0x40, C.byref(unit))
        if error or not unit.value:
            raise ExtractionError(f"libclang parse failed: CXErrorCode={error}")
        diagnostics, errors = [], []
        count = clang.getNumDiagnostics(unit)
        if count > 1024:
            raise ExtractionError("diagnostic count exceeds bound")
        for i in range(count):
            diagnostic = clang.getDiagnostic(unit, i)
            try:
                severity = clang.getDiagnosticSeverity(diagnostic)
                message = clang.string(clang.getDiagnosticSpelling(diagnostic))
                diagnostics.append(f"severity={severity}: {message}")
                if severity >= 3:
                    errors.append(message)
            finally:
                clang.disposeDiagnostic(diagnostic)
        if errors:
            raise ExtractionError("clang error diagnostics: " + "; ".join(errors)[:16384])
        pending, ids, nodes = [], {}, {}

        def normalize(kind):
            # Elaborated tag sugar carries no distinct layout. Typedefs remain nodes.
            return clang.Type_getNamedType(kind) if kind.kind == 119 else kind

        def ensure(kind):
            kind = normalize(kind)
            spelling = clang.string(clang.getTypeSpelling(kind)) or "<unknown>"
            declaration = clang.getTypeDeclaration(kind)
            origin = clang.origin(declaration, source, header_names)
            usr = clang.string(clang.getCursorUSR(declaration))
            # USRs are scoped hints. Anonymous declarations use input-relative location.
            hint = usr or spelling.replace(str(source), source.name)
            key = f"{kind.kind}:{hint}:{spelling.replace(str(source), source.name)}"
            if origin and not usr:
                key += f":{origin['header']}:{origin['line']}:{origin['column']}"
            if len(key.encode()) > 900:
                key = f"type:{kind.kind}:" + hashlib.sha256(key.encode()).hexdigest()
            if key not in ids:
                if len(ids) >= MAX_NODES:
                    raise ExtractionError("type count exceeds bound")
                ids[key] = key
                pending.append((key, kind, spelling.replace(str(source), source.name), declaration, origin))
            return key

        for cursor in declaration_seeds(clang, clang.getTranslationUnitCursor(unit)):
            clang.origin(cursor, source, header_names)
            ensure(clang.getCursorType(cursor))
        position = 0
        while position < len(pending):
            key, kind, spelling, declaration, origin = pending[position]
            position += 1
            size, alignment = clang.Type_getSizeOf(kind), clang.Type_getAlignOf(kind)
            layout = ({"status": "known", "sizeBytes": size, "alignmentBytes": alignment}
                      if size >= 0 and alignment > 0 else
                      {"status": "unknown", "reason": f"libclang layout: size={size}, alignment={alignment}"})
            node = {"id": key, "kind": "opaque", "spelling": spelling, "layout": layout,
                    "fields": [], "enumValues": [], "qualifiers": []}
            if origin:
                node["origin"] = origin
            for name, query in (("const", clang.isConstQualifiedType), ("volatile", clang.isVolatileQualifiedType), ("restrict", clang.isRestrictQualifiedType)):
                if query(kind): node["qualifiers"].append(name)
            if 3 <= kind.kind <= 23:
                node["kind"] = "scalar"
                if kind.kind <= 20:
                    node["signed"] = kind.kind >= 13
            elif kind.kind == 101:
                node.update(kind="pointer", pointeeTypeID=ensure(clang.getPointeeType(kind)))
            elif kind.kind == 105:
                node.update(kind="record", recordKind="union" if declaration.kind == 3 else "struct")
                node["layout"] = record_layout(size, alignment, [child.kind for child in clang.children(declaration)])
                for i, field in enumerate(clang.fields(kind)):
                    field_type = clang.getCursorType(field)
                    anonymous = bool(clang.Cursor_isAnonymousRecordDecl(clang.getTypeDeclaration(normalize(field_type))))
                    name = "" if anonymous else clang.string(clang.getCursorSpelling(field)).replace(str(source), source.name)
                    offset = clang.Cursor_getOffsetOfField(field)
                    item = {"id": f"{key}/field:{i}", "name": name, "typeID": ensure(field_type),
                            "flexibleArray": field_type.kind == 114, "anonymous": anonymous}
                    if offset >= 0:
                        item["bitOffset"] = offset
                    else:
                        node["layout"] = {"status": "unknown", "reason": f"libclang field offset error: {offset}"}
                    if clang.Cursor_isBitField(field):
                        width = clang.getFieldDeclBitWidth(field)
                        if width < 0:
                            raise ExtractionError("bitfield width unavailable")
                        item["bitWidth"] = width
                    node["fields"].append(item)
            elif kind.kind == 106:
                base = clang.getEnumDeclIntegerType(declaration)
                node.update(kind="enumeration", underlyingTypeID=ensure(base))
                signed = clang.getCanonicalType(base).kind >= 13
                for child in clang.children(declaration):
                    if child.kind == 7:
                        value = clang.getEnumConstantDeclValue(child) if signed else clang.getEnumConstantDeclUnsignedValue(child)
                        node["enumValues"].append({"name": clang.string(clang.getCursorSpelling(child)), "value": str(value)})
            elif kind.kind == 107:
                node.update(kind="typedef", underlyingTypeID=ensure(clang.getTypedefDeclUnderlyingType(declaration)))
            elif kind.kind in (112, 114):
                node.update(kind="array", elementTypeID=ensure(clang.getArrayElementType(kind)))
                count = clang.getArraySize(kind)
                if count >= 0: node["arrayCount"] = count
                else: node["layout"] = {"status": "unknown", "reason": "incomplete array extent"}
            else:
                node["layout"] = {"status": "unknown", "reason": f"type kind {kind.kind} is display-only; prototype/ABI support deferred"}
            canonical = ensure(clang.getCanonicalType(kind))
            if canonical != key: node["canonicalTypeID"] = canonical
            nodes[key] = node
        propagate_unknown_layouts(nodes)
        doc = {"schema": "macscope.sdk-type-archive", "schemaMajor": 1, "schemaMinor": 0,
               "configurationID": config["configurationID"],
               "provenance": {"compiler": config["compiler"], "compilerVersion": config["compilerVersion"],
                              "libclangVersion": clang.string(clang.getClangVersion()),
                              "sdkIdentity": f"{config['sdkPath']}|{config['sdkVersion']}|{config['sdkBuild']}",
                              "targetTriple": config["profile"]["target"], "language": config["profile"]["language"],
                              "sdkRelease": config["sdkVersion"], "sdkBuild": config["sdkBuild"],
                              "architecture": config["profile"]["architecture"],
                              "headerClosure": [{"header": header_names[path], "inputSHA256": hashlib.sha256(contents).hexdigest()}
                                                for path, contents in sorted(original.items(), key=lambda item: header_names[item[0]])],
                              "extractorVersion": configuration.EXTRACTOR_VERSION, "input": source.name,
                              "inputSHA256": hashlib.sha256(data).hexdigest(), "arguments": config["arguments"]},
               "diagnostics": diagnostics + ["Semantic annotations, ObjC interface layout, base/vtable ABI and complete function prototypes remain unknown/deferred."],
               "types": [nodes[key] for key in sorted(nodes)]}
        validate_archive(doc)
        return doc
    finally:
        if unit.value: clang.disposeTranslationUnit(unit)
        clang.disposeIndex(index)


def propagate_unknown_layouts(nodes):
    # Unknown base/vtable layout cannot become a known by-value typedef/array/record.
    users = {}
    for identity, node in nodes.items():
        refs = []
        if node["kind"] in ("typedef", "enumeration"): refs = [node["underlyingTypeID"]]
        elif node["kind"] == "array" and "arrayCount" in node: refs = [node["elementTypeID"]]
        elif node["kind"] == "record": refs = [field["typeID"] for field in node["fields"] if not field["flexibleArray"]]
        for ref in refs: users.setdefault(ref, []).append(identity)
    pending = [key for key, node in nodes.items() if node["layout"]["status"] == "unknown"]
    for key in pending:
        for user in users.get(key, []):
            if nodes[user]["layout"]["status"] != "unknown":
                nodes[user]["layout"] = {"status": "unknown", "reason": "incomplete by-value dependency"}
                pending.append(user)


def iorpc_constant_candidates(doc: dict, enum_type_ids: list[str]) -> dict:
    """Caller-selected enum facts only; numeric aliases remain ambiguous candidates."""
    if (not isinstance(enum_type_ids, list) or len(enum_type_ids) > 128
            or any(not isinstance(item, str) for item in enum_type_ids)
            or len(set(enum_type_ids)) != len(enum_type_ids)):
        raise ExtractionError("invalid IORPC enum selection")
    provenance = doc["provenance"]
    for key in ("sdkRelease", "sdkBuild", "architecture"):
        if not isinstance(provenance.get(key), str) or not provenance[key]:
            raise ExtractionError("exact SDK release/build/architecture required for constant facts")
    nodes = {node["id"]: node for node in doc["types"]}
    result = []
    for identity in enum_type_ids:
        node = nodes.get(identity)
        if node is None or node["kind"] != "enumeration" or not node.get("origin"):
            raise ExtractionError("IORPC selection must identify one source-backed extracted enum")
        for value in node["enumValues"]:
            try: number = int(value["value"], 10)
            except (TypeError, ValueError) as error: raise ExtractionError("invalid enum constant") from error
            if not 0 <= number <= (1 << 64) - 1:
                raise ExtractionError("message candidate outside uint64")
            result.append({"enumTypeID": identity, "name": value["name"], "id": number,
                           "origin": node["origin"]})
            if len(result) > MAX_NODES: raise ExtractionError("IORPC candidate count exceeds bound")
    counts = {}
    for item in result: counts[item["id"]] = counts.get(item["id"], 0) + 1
    for item in result: item["status"] = "ambiguous-numeric-alias" if counts[item["id"]] > 1 else "unadmitted-candidate"
    return {"sdkRelease": provenance["sdkRelease"], "sdkBuild": provenance["sdkBuild"],
            "architecture": provenance["architecture"], "constants": result,
            "admission": "requires Lane A exact-build/source admission; no message dispatch or class association inferred"}


def validate_archive(doc: dict) -> None:
    """Producer-side v1 checks; the Swift loader independently validates admission."""
    encoded = configuration.canonical_json(doc)
    if len(encoded) > MAX_ARCHIVE or doc.get("schema") != "macscope.sdk-type-archive" or (doc.get("schemaMajor"), doc.get("schemaMinor")) != (1, 0):
        raise ExtractionError("archive schema/byte bound")
    stack = [doc]
    work = 0
    while stack:
        value = stack.pop(); work += 1
        if work > 1_000_000: raise ExtractionError("archive work bound")
        if isinstance(value, str) and (len(value.encode()) > 16384 or "\0" in value):
            raise ExtractionError("archive string bound")
        if isinstance(value, dict): stack.extend(value.keys()); stack.extend(value.values())
        elif isinstance(value, list): stack.extend(value)
    types = doc["types"]
    if len(types) > MAX_NODES:
        raise ExtractionError("archive node bound")
    nodes = {node["id"]: node for node in types}
    if len(nodes) != len(types):
        raise ExtractionError("duplicate type identity")
    pending, users = {}, {}
    carrier_work = 0
    carrier_roots = {}
    def integer_base(key):
        nonlocal carrier_work
        visited, trail = set(), []
        root = None
        while True:
            if key in carrier_roots:
                root = carrier_roots[key]; break
            if key in visited or key not in nodes: break
            visited.add(key); trail.append(key); carrier_work += 1
            if carrier_work > 100_000: raise ExtractionError("carrier work bound")
            node = nodes[key]
            if node["kind"] == "scalar":
                if node.get("signed") is not None and type(node["signed"]) is not bool:
                    raise ExtractionError("invalid integer signedness")
                if type(node.get("signed")) is bool: root = node
                break
            if node["kind"] not in ("typedef", "enumeration"): break
            key = node.get("underlyingTypeID")
        for visited_key in trail: carrier_roots[visited_key] = root
        return root

    def enum_integer(value):
        # Bound conversion before Python's arbitrary-precision parser. All accepted
        # Int64/UInt64 spellings fit in 20 ASCII characters including a minus sign.
        if type(value) is not str or not 1 <= len(value) <= 20:
            raise ExtractionError("enum value")
        digits = value[1:] if value.startswith("-") else value
        if not digits or any(char < "0" or char > "9" for char in digits):
            raise ExtractionError("enum value")
        if (len(digits) > 1 and digits[0] == "0") or value == "-0":
            raise ExtractionError("enum value")
        return int(value)
    for node in types:
        layout, kind = node["layout"], node["kind"]
        known = layout["status"] == "known"
        if known:
            size, align = layout["sizeBytes"], layout["alignmentBytes"]
            if type(size) is not int or type(align) is not int or not 0 <= size <= (2**64 - 1)//8 or align <= 0 or align & (align-1) or size % align:
                raise ExtractionError("invalid known layout")
        elif layout.get("reason") is None or "sizeBytes" in layout or "alignmentBytes" in layout:
            raise ExtractionError("invalid unknown layout")
        refs = [node[name] for name in ("canonicalTypeID", "underlyingTypeID", "pointeeTypeID", "elementTypeID") if name in node]
        refs += [field["typeID"] for field in node["fields"]]
        if any(ref not in nodes for ref in refs):
            raise ExtractionError("dangling type reference")
        required = []
        if kind == "record":
            for index, field in enumerate(node["fields"]):
                carrier = nodes[field["typeID"]]
                if "bitWidth" in field and integer_base(field["typeID"]) is None:
                    raise ExtractionError("noninteger bitfield")
                if field["flexibleArray"]:
                    if node["recordKind"] != "struct" or index != len(node["fields"])-1 or carrier["kind"] != "array" or "arrayCount" in carrier:
                        raise ExtractionError("invalid flexible tail")
                else: required.append(field["typeID"])
                if known:
                    offset = field.get("bitOffset")
                    if "bitWidth" in field:
                        width = field["bitWidth"]
                        carrier_size = carrier["layout"].get("sizeBytes")
                        # Match the consumer's selected field type layout, not
                        # a guessed storage unit or the resolved integer root.
                        if (type(width) is not int or not 0 <= width <= (2**64 - 1)
                                or type(carrier_size) is not int or not 0 <= carrier_size <= (2**64 - 1)//8
                                or width > carrier_size*8 or (width == 0 and field["name"] != "")):
                            raise ExtractionError("invalid bit width")
                    extent = 0 if field["flexibleArray"] else field.get("bitWidth", carrier["layout"].get("sizeBytes", -1)*8)
                    if type(offset) is not int or offset < 0 or extent < 0 or offset + extent > size*8 or (node["recordKind"] == "union" and offset != 0):
                        raise ExtractionError("invalid field bit extent")
        elif kind in ("typedef", "enumeration"):
            required.append(node["underlyingTypeID"])
            if kind == "enumeration":
                values = node["enumValues"]
                if type(values) is not list or len(values) > 4096:
                    raise ExtractionError("enum value count")
                base = integer_base(required[0])
                signed = base.get("signed") if base is not None else None
                width = base["layout"].get("sizeBytes") if base is not None else None
                if known and (signed is None or type(width) is not int or not 1 <= width <= 8):
                    raise ExtractionError("enum base")
                names = set()
                for item in values:
                    if type(item) is not dict:
                        raise ExtractionError("enum item")
                    name = item.get("name")
                    if type(name) is not str or not name:
                        raise ExtractionError("enum name")
                    # Swift String/Set equality uses canonical equivalence. This
                    # comparison key never changes the retained spelling.
                    name_key = unicodedata.normalize("NFC", name)
                    if name_key in names: raise ExtractionError("enum name")
                    names.add(name_key)
                    value = enum_integer(item.get("value"))
                    minimum = -(1 << 63) if signed is not False else 0
                    maximum = (1 << (63 if signed is True else 64)) - 1
                    if type(width) is int and 0 < width < 8:
                        if signed is True:
                            minimum, maximum = -(1 << (width * 8 - 1)), (1 << (width * 8 - 1)) - 1
                        elif signed is False:
                            maximum = (1 << (width * 8)) - 1
                    if not minimum <= value <= maximum:
                        raise ExtractionError("enum range")
            if known and layout != nodes[required[0]]["layout"]:
                raise ExtractionError("underlying layout mismatch")
        elif kind == "array":
            if "arrayCount" in node:
                required.append(node["elementTypeID"])
                element = nodes[required[0]]["layout"]
                if known and (element.get("sizeBytes", -1)*node["arrayCount"] != size or element.get("alignmentBytes") != align):
                    raise ExtractionError("array layout mismatch")
            elif known: raise ExtractionError("unknown array extent")
        elif kind == "opaque" and known:
            raise ExtractionError("opaque layout cannot be authoritative")
        if known:
            for ref in required:
                if nodes[ref]["layout"]["status"] != "known":
                    raise ExtractionError("incomplete by-value dependency")
                users.setdefault(ref, []).append(node["id"])
            pending[node["id"]] = len(required)
    queue = [key for key, degree in pending.items() if degree == 0]
    for key in queue:
        for user in users.get(key, []):
            pending[user] -= 1
            if pending[user] == 0: queue.append(user)
    if len(queue) != len(pending):
        raise ExtractionError("by-value layout cycle")


def run_worker(config: dict, source: Path, directory: Path) -> dict:
    job = directory / "job.json"
    job.write_bytes(configuration.canonical_json({"configuration": config, "source": str(source)}))
    with (directory / "worker.stdout").open("wb") as stdout, (directory / "worker.stderr").open("wb") as stderr:
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--worker", str(job)],
                                stdout=stdout, stderr=stderr, env=configuration.CLEAN_ENV, timeout=WORKER_SECONDS, check=False)
    errors = (directory / "worker.stderr").read_bytes()[:16384].decode("utf-8", "replace")
    if result.returncode:
        raise ExtractionError(f"libclang worker failed ({result.returncode}): {errors}")
    output = directory / "worker.stdout"
    if output.stat().st_size > MAX_ARCHIVE:
        raise ExtractionError("worker output exceeds bound")
    return json.loads(output.read_bytes())


def extract(profile: dict, source: Path, output: Path, *, headers: dict | None = None, iorpc_enums: list[str] | None = None, resolve=configuration.resolve_configuration, worker=run_worker) -> dict:
    original, _, names = prepare_header_closure(source, headers)
    data = original[source.resolve(strict=True)]
    source = source.resolve(strict=True)
    config = resolve(profile, source.parent)
    if headers is not None:
        config["headerClosurePaths"] = {name: str(path.resolve(strict=True)) for name, path in headers.items()}
        config["configurationID"] = configuration.configuration_id(config)
    output = output.parent.resolve(strict=True) / output.name
    if output.is_symlink() or output in original:
        raise ExtractionError("output must not replace a symlink or input")
    with tempfile.TemporaryDirectory(prefix=".clang-types-", dir=output.parent) as temporary:
        directory = Path(temporary)
        doc = worker(config, source, directory)
        validate_archive(doc)
        if doc["configurationID"] != config["configurationID"] or doc["provenance"]["inputSHA256"] != hashlib.sha256(data).hexdigest():
            raise ExtractionError("worker input/configuration identity changed")
        if headers is not None:
            expected = [{"header": names[path], "inputSHA256": hashlib.sha256(contents).hexdigest()}
                        for path, contents in sorted(original.items(), key=lambda item: names[item[0]])]
            if doc["provenance"].get("headerClosure") != expected:
                raise ExtractionError("worker header closure changed")
        if iorpc_enums is not None:
            doc["provenance"]["iorpcConstantCandidates"] = iorpc_constant_candidates(doc, iorpc_enums)
            validate_archive(doc)
        payload = configuration.canonical_json(doc) + b"\n"
        staged = directory / "archive.json"
        with staged.open("wb") as stream:
            stream.write(payload); stream.flush(); os.fsync(stream.fileno())
        os.replace(staged, output)
    return doc


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--iorpc-enum-type-id", action="append", help="explicit extracted enum identity; emits unadmitted constant candidates")
    parser.add_argument("--header-closure", type=Path, help="explicit include-name to absolute-header-path JSON mapping")
    args = parser.parse_args()
    if args.worker:
        resource.setrlimit(resource.RLIMIT_CPU, (20, 25))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_ARCHIVE, MAX_ARCHIVE))
        # Darwin may reject RLIMIT_DATA despite reporting an unlimited ceiling.
        # ctypes releases the GIL during parsing, so this worker-local watchdog
        # can terminate a runaway parse. Sampling is not an exact allocation cap.
        def memory_watchdog():
            while True:
                peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                peak_bytes = peak if sys.platform == "darwin" else peak * 1024
                if peak_bytes > 512 * 1024 * 1024:
                    os._exit(125)
                time.sleep(0.05)
        threading.Thread(target=memory_watchdog, daemon=True).start()
        if args.worker.stat().st_size > 128 * 1024:
            raise ExtractionError("worker request exceeds bound")
        job = json.loads(args.worker.read_bytes())
        source = Path(job["source"])
        headers = job["configuration"].get("headerClosurePaths")
        mapped = {name: Path(path) for name, path in headers.items()} if headers is not None else None
        print(configuration.canonical_json(extract_in_worker(job["configuration"], source, checked_source(source, allow_includes=mapped is not None), mapped)).decode())
    else:
        if not all((args.profile, args.input, args.output)):
            parser.error("--profile, --input and --output are required")
        started = time.monotonic()
        headers = load_header_manifest(args.header_closure) if args.header_closure else None
        doc = extract(configuration.load_profile(args.profile), args.input, args.output, headers=headers, iorpc_enums=args.iorpc_enum_type_id)
        print(json.dumps({"output": str(args.output), "types": len(doc["types"]), "seconds": time.monotonic()-started}))


if __name__ == "__main__":
    try:
        main()
    except (ExtractionError, configuration.ConfigurationError, subprocess.TimeoutExpired) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
