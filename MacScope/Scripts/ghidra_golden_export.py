#!/usr/bin/env python3
# Ghidra -> GoldenOutput exporter (the MacScope-vs-Ghidra oracle).
#
# Runs HEADLESS via the `pyghidra` package (CPython 3 -> JVM through JPype): it opens a binary
# in a transient Ghidra project, runs auto-analysis, then walks Ghidra's program model and dumps
# the analysis into MacScope's GoldenOutput JSON schema, so GoldenDifferentialTests can diff
# MacScope's output against Ghidra's the same way it diffs against the reference disassembler.
#
# This is OUR code written from Ghidra's public Java/PyGhidra API. Ghidra is Apache-2.0, but the
# produced ghidra.json is a host/version-specific reference output and is NOT committed.
# No Ghidra code is copied.
#
# Address format MATCHES GoldenOutput.hexAddress EXACTLY: "0x" + 16-digit zero-padded lowercase
# hex (Models/AnalysisModels.swift:2459). Getting this wrong makes every address key mismatch and
# the diff useless.
#
# v2 SCOPE: binary(partial), sections, symbols(binary symtab only), imports, exports,
# instructions (bounded), procedures, basicBlocks, controlFlowEdges (bounded),
# crossReferences (bounded), demangledNames, and pseudocode(bounded -- Ghidra's decompiler).
# Full binary metadata (platform/SDK/UUID) remains omitted because Ghidra and MacScope expose
# different host/version-specific detail there; correctness-over-coverage says keep those absent
# until they can be normalized exactly.
#
# Usage:  python3 ghidra_golden_export.py <binary_path> <out_json> [--basename NAME]
#                                          [--project-dir DIR] [--max-instr N] [--max-pseudo N]
# Requires: GHIDRA_INSTALL_DIR set, and `pyghidra` + `jpype1` importable (run_ghidra_golden.sh
# bootstraps a pinned venv with the Ghidra-bundled wheels).

import argparse
import json
import os
import sys

MAX_INSTR_DEFAULT = 8000   # matches the reference exporter's bound; /bin/ls __text is ~3k.
MAX_PSEUDO_DEFAULT = 8     # decompile only the first N procedures by start address (expensive).
MAX_EDGES_DEFAULT = 20000  # large enough for /bin/ls, finite for pathological CFGs.
MAX_XREFS_DEFAULT = 20000  # same bound principle as instructions/CFG.


def addr(value):
    """GoldenOutput.hexAddress: '0x' + 16-digit zero-padded lowercase hex."""
    try:
        return "0x" + format(int(value) & 0xFFFFFFFFFFFFFFFF, "016x")
    except Exception:
        return "0x0000000000000000"


def build_golden(flat, basename_override, max_instr, max_pseudo, max_edges, max_xrefs, log):
    # Ghidra Java types are only importable AFTER the JVM is up (pyghidra.start()).
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.program.model.symbol import SourceType
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import TaskMonitor

    program = flat.getCurrentProgram()
    monitor = TaskMonitor.DUMMY
    listing = program.getListing()

    def cap(label, fn, default=None):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - best-effort capture, like the reference exporter
            log.append("%s: %s" % (label, exc))
            return default

    try:
        from ghidra.app.util.demangler import DemanglerUtil
    except Exception as exc:  # noqa: BLE001 - optional feature, do not fail the export
        DemanglerUtil = None
        log.append("demanglerImport: %s" % exc)

    def jitems(label, iterator):
        """Materialize a Java Iterator/Iterable without assuming JPype's Python adapter."""
        if iterator is None:
            return []
        try:
            return list(iterator)
        except Exception:
            if not hasattr(iterator, "hasNext"):
                return [iterator]
            items = []
            while bool(cap(label + ".hasNext", lambda: iterator.hasNext(), False)):
                item = cap(label + ".next", lambda: iterator.next())
                if item is None:
                    break
                items.append(item)
            return items

    def address_offset(a):
        if a is None:
            return None
        if not bool(cap("addrIsMem", lambda: a.isMemoryAddress(), False)):
            return None
        offset = cap("addrOffset", lambda: a.getOffset())
        return int(offset) if offset is not None else None

    def clean_string(value):
        if value is None:
            return None
        text = str(value).strip()
        return text if text else None

    def flow_kind(flow):
        """Map Ghidra FlowType to MacScope's existing CFG vocabulary."""
        if flow is None:
            return None
        if bool(cap("flowFallthrough", lambda: flow.isFallthrough(), False)):
            return "fallthrough"
        if bool(cap("flowCall", lambda: flow.isCall(), False)):
            return "call"
        if bool(cap("flowJump", lambda: flow.isJump(), False)):
            if bool(cap("flowComputed", lambda: flow.isComputed(), False)):
                return "switch"
            return "branch"
        if bool(cap("flowConditional", lambda: flow.isConditional(), False)):
            return "branch"
        return None

    out = {
        "schemaVersion": 1,
        "binary": {}, "sections": [], "symbols": [], "imports": [], "exports": [],
        "instructions": [], "procedures": [], "basicBlocks": [], "controlFlowEdges": [],
        "crossReferences": [], "demangledNames": [], "pseudocode": [],
    }

    # --- binary metadata (partial; platform/SDK/UUID intentionally omitted in v1) ---
    lang = program.getLanguage()
    processor = str(cap("processor", lambda: lang.getProcessor().toString()) or "")
    bits = cap("bits", lambda: lang.getLanguageDescription().getSize(), 0) or 0
    if processor == "AARCH64":
        architecture = "arm64"
    elif processor == "x86" and int(bits) == 64:
        architecture = "x86_64"
    else:
        architecture = "unknown"
    exe_path = str(cap("exePath", lambda: program.getExecutablePath()) or "")
    name = basename_override or os.path.basename(exe_path) or "?"
    # Match MacScope's kind vocabulary ("Mach-O executable") to drop one binary-field diff; the
    # architecture string is left "arm64" (MacScope encodes the fat-slice index in its own string,
    # which is not reproducible here), and platform/SDK/UUID are v1-omitted (documented gaps).
    exe_format = str(cap("exeFmt", lambda: program.getExecutableFormat()) or "")
    kind = "Mach-O executable" if "Mach-O" in exe_format else "executable"
    out["binary"] = {
        "name": name, "pathBasename": name, "kind": kind,
        "architecture": architecture, "hasEmbeddedUUID": False,
        "platformName": None, "minimumOSVersion": None, "sdkVersion": None, "buildTools": [],
    }

    # --- sections (Ghidra memory blocks ~= Mach-O sections) ---
    blocks = cap("blocks", lambda: list(program.getMemory().getBlocks()), []) or []
    block_ranges = []
    for block in blocks:
        block_name = str(cap("blkName", lambda: block.getName()) or "?")
        block_start = int(cap("blkStart", lambda: block.getStart().getOffset(), 0) or 0)
        block_size = max(0, int(cap("blkSize", lambda: block.getSize(), 0) or 0))
        block_exec = bool(cap("blkExec", lambda: block.isExecute(), False))
        block_init = bool(cap("blkInit", lambda: block.isInitialized(), True))
        block_ranges.append({
            "name": block_name,
            "lo": block_start,
            "hi": block_start + block_size,
            "isExecutable": block_exec,
        })
        out["sections"].append({
            "name": block_name,
            "address": addr(block_start),
            "size": block_size,
            "fileOffset": 0,  # Ghidra's file-offset API is awkward; left 0 (documented limitation).
            "isExecutable": block_exec,
            "isZeroFill": not block_init,
        })

    def block_for_offset(offset):
        if offset is None:
            return None
        for block in block_ranges:
            if offset >= block["lo"] and offset < block["hi"]:
                return block
        return None

    has_text_block = any(b["isExecutable"] and "__text" in b["name"].lower() for b in block_ranges)

    def is_text_instruction_address(a):
        block = block_for_offset(address_offset(a))
        if block is None or not block["isExecutable"]:
            return False
        return "__text" in block["name"].lower() if has_text_block else True

    def classify_data_xref_target(to_offset):
        block = block_for_offset(to_offset)
        if block is None:
            return None
        name = block["name"].lower()
        if "objc_selrefs" in name or "selrefs" in name:
            return "selref"
        if "cstring" in name or "cfstring" in name or "string" in name:
            return "string"
        if not block["isExecutable"]:
            return "data"
        return None

    # --- symbols: only those sourced from the binary's symbol table, to mirror MacScope's
    # symtab-derived symbols and EXCLUDE Ghidra's auto-generated FUN_/LAB_/DAT_ labels. ---
    symtab = cap("symtab", lambda: program.getSymbolTable())
    extmgr = cap("extMgr", lambda: program.getExternalManager())
    all_symbols = []
    demangle_inputs = []

    def add_demangle_input(name, address_obj=None):
        if name:
            demangle_inputs.append((name, address_obj))

    if symtab is not None:
        all_symbols = cap("allSyms", lambda: list(symtab.getAllSymbols(True)), []) or []
        for sym in all_symbols:
            src = cap("symSrc", lambda: sym.getSource())
            if src in (SourceType.DEFAULT, SourceType.ANALYSIS):
                continue  # Ghidra-synthetic; not in the Mach-O symbol table.
            a = cap("symAddr", lambda: sym.getAddress())
            in_mem = bool(cap("symInMem", lambda: a is not None and a.isMemoryAddress(), False))
            name = str(cap("symName", lambda: sym.getName()) or "?")
            out["symbols"].append({
                "name": name,
                "address": addr(a.getOffset()) if in_mem else None,
                "kind": str(cap("symKind", lambda: sym.getSymbolType().toString()) or "symbol"),
                "libraryName": None,
            })
            add_demangle_input(name, a if in_mem else None)

    def library_display_name(library_name):
        library_name = clean_string(library_name)
        if extmgr is None or library_name is None:
            return library_name
        path = clean_string(cap("extLibPath", lambda: extmgr.getExternalLibraryPath(library_name)))
        return path or library_name

    def add_import(imports_by_name, name, library_name=None, library_ordinal=None):
        name = clean_string(name)
        if name is None:
            return
        row = {
            "name": name,
            "libraryName": library_display_name(library_name),
            "libraryOrdinal": library_ordinal,
        }
        old = imports_by_name.get(name)
        if old is None or (old["libraryName"] is None and row["libraryName"] is not None):
            imports_by_name[name] = row
        add_demangle_input(name)

    # --- imports (Ghidra external symbols/locations, normalized to MacScope's name spelling) ---
    imports_by_name = {}
    if symtab is not None:
        for sym in jitems("extSyms", cap("extSyms", lambda: symtab.getExternalSymbols())):
            loc = cap("extLocForSym", lambda: extmgr.getExternalLocation(sym)) if extmgr is not None else None
            original = cap("extLocOrigName", lambda: loc.getOriginalImportedName()) if loc is not None else None
            label = cap("extLocLabel", lambda: loc.getLabel()) if loc is not None else None
            name = clean_string(original) or clean_string(label) or clean_string(cap("extSymName", lambda: sym.getName()))
            library = cap("extLocLib", lambda: loc.getLibraryName()) if loc is not None else None
            add_import(imports_by_name, name, library)
    if extmgr is not None:
        for library in cap("extLibNames", lambda: list(extmgr.getExternalLibraryNames()), []) or []:
            for loc in jitems("extLocs", cap("extLocs", lambda: extmgr.getExternalLocations(library))):
                original = cap("extLocOrigName2", lambda: loc.getOriginalImportedName())
                label = cap("extLocLabel2", lambda: loc.getLabel())
                add_import(imports_by_name, clean_string(original) or clean_string(label),
                           cap("extLocLib2", lambda: loc.getLibraryName()))
    out["imports"] = list(imports_by_name.values())

    # --- exports (memory-backed global/external-entry symbols from the loaded image) ---
    exports_by_key = {}
    for sym in all_symbols:
        src = cap("expSrc", lambda: sym.getSource())
        if src in (SourceType.DEFAULT, SourceType.ANALYSIS):
            continue
        if bool(cap("expIsExternal", lambda: sym.isExternal(), False)):
            continue
        a = cap("expAddr", lambda: sym.getAddress())
        off = address_offset(a)
        if off is None:
            continue
        if not (bool(cap("expEntry", lambda: sym.isExternalEntryPoint(), False))
                or bool(cap("expGlobal", lambda: sym.isGlobal(), False))):
            continue
        name = clean_string(cap("expName", lambda: sym.getName()))
        if name is None:
            continue
        row = {"name": name, "address": addr(off), "source": "LC_SYMTAB"}
        exports_by_key[(row["name"], row["address"])] = row
        add_demangle_input(name, a)
    out["exports"] = list(exports_by_key.values())

    # --- demangled names (API-confirmed only; never synthesize name==demangled pairs) ---
    demangled_by_mangled = {}
    if DemanglerUtil is not None:
        for name, address_obj in demangle_inputs:
            if name in demangled_by_mangled:
                continue
            demangled_objects = cap(
                "demangle",
                lambda n=name, a=address_obj: DemanglerUtil.demangle(program, n, a)
                if a is not None else DemanglerUtil.demangle(n),
                [],
            )
            for demangled_obj in jitems("demangledObjects", demangled_objects):
                text = clean_string(cap("demangledSig", lambda: demangled_obj.getSignature(False)))
                if text is None:
                    text = clean_string(cap("demangledOrig", lambda: demangled_obj.getOriginalDemangled()))
                if text is None:
                    text = clean_string(cap("demangledRaw", lambda: demangled_obj.getRawDemangled()))
                if text is not None and text != name:
                    demangled_by_mangled[name] = text
                    break
    out["demangledNames"] = [
        {"mangled": mangled, "demangled": demangled}
        for mangled, demangled in demangled_by_mangled.items()
    ]

    # --- instructions (bounded, ascending address) ---
    instr_emitted = 0
    for ins in cap("insIter", lambda: listing.getInstructions(True), iter([])) or iter([]):
        if instr_emitted >= max_instr:
            break
        a = cap("insAddr", lambda: ins.getAddress().getOffset(), 0)
        raw = cap("insBytes", lambda: ins.getBytes(), None)
        try:
            bytestr = " ".join("%02x" % (int(b) & 0xFF) for b in raw) if raw is not None else ""
        except Exception:
            bytestr = ""
        mnem = str(cap("insMnem", lambda: ins.getMnemonicString()) or "?")
        full = str(cap("insStr", lambda: ins.toString()) or mnem)
        operands = full[len(mnem):].strip() if full.startswith(mnem) else full
        out["instructions"].append({
            "address": addr(a), "bytes": bytestr, "mnemonic": mnem,
            "operands": operands, "comment": None,
        })
        instr_emitted += 1

    # --- procedures ---
    fm = cap("funcMgr", lambda: program.getFunctionManager())
    funcs = []
    if fm is not None:
        for func in cap("funcIter", lambda: list(fm.getFunctions(True)), []) or []:
            if bool(cap("isExt", lambda: func.isExternal(), False)):
                continue
            funcs.append(func)
            ep = cap("funcEP", lambda: func.getEntryPoint().getOffset(), 0)
            end = cap("funcEnd", lambda: func.getBody().getMaxAddress().getOffset(), ep)
            out["procedures"].append({
                "name": str(cap("funcName", lambda: func.getName()) or "sub"),
                "startAddress": addr(ep), "endAddress": addr(end), "confidence": 1.0,
            })

    # --- basic blocks (one pass over the whole program; map each block to its function) ---
    bbm = cap("bbm", lambda: BasicBlockModel(program))
    if bbm is not None and fm is not None:
        edge_seen = set()
        it = cap("bbIter", lambda: bbm.getCodeBlocks(monitor))
        while it is not None and bool(cap("bbHasNext", lambda: it.hasNext(), False)):
            blk = cap("bbNext", lambda: it.next())
            if blk is None:
                break
            start_addr = cap("bbStartAddr", lambda: blk.getFirstStartAddress())
            owner = cap("bbOwner", lambda: fm.getFunctionContaining(start_addr))
            proc_start = addr(owner.getEntryPoint().getOffset()) if owner is not None else None
            icount = 0
            for _ in cap("bbInsIter", lambda: listing.getInstructions(blk, True), iter([])) or iter([]):
                icount += 1
            out["basicBlocks"].append({
                "procedureStartAddress": proc_start,
                "startAddress": addr(cap("bbMin", lambda: blk.getMinAddress().getOffset(), 0)),
                "endAddress": addr(cap("bbMax", lambda: blk.getMaxAddress().getOffset(), 0)),
                "instructionCount": icount,
            })
            if len(out["controlFlowEdges"]) < max_edges:
                dests = cap("bbDests", lambda: blk.getDestinations(monitor))
                for dest in jitems("bbDestIter", dests):
                    flow = cap("edgeFlow", lambda: dest.getFlowType())
                    kind = flow_kind(flow)
                    if kind is None:
                        continue
                    from_addr = cap("edgeReferent", lambda: dest.getReferent()) \
                        or cap("edgeSource", lambda: dest.getSourceAddress())
                    to_addr = cap("edgeDest", lambda: dest.getDestinationAddress()) \
                        or cap("edgeRef", lambda: dest.getReference())
                    from_off = address_offset(from_addr)
                    to_off = address_offset(to_addr)
                    if from_off is None or to_off is None:
                        continue
                    key = (addr(from_off), addr(to_off), kind)
                    if key in edge_seen:
                        continue
                    edge_seen.add(key)
                    out["controlFlowEdges"].append({"from": key[0], "to": key[1], "kind": key[2]})
                    if len(out["controlFlowEdges"]) >= max_edges:
                        break

    # --- cross-references (from __text instructions; MacScope xref kind vocabulary only) ---
    refmgr = cap("refMgr", lambda: program.getReferenceManager())
    if refmgr is not None and max_xrefs > 0:
        xref_seen = set()
        for ins in cap("xrefInsIter", lambda: listing.getInstructions(True), iter([])) or iter([]):
            ins_addr = cap("xrefInsAddr", lambda: ins.getAddress())
            if not is_text_instruction_address(ins_addr):
                continue
            refs = cap("refsFrom", lambda: refmgr.getReferencesFrom(ins_addr), []) or []
            for ref in refs:
                ref_type = cap("refType", lambda: ref.getReferenceType())
                to_addr = cap("refTo", lambda: ref.getToAddress())
                from_off = address_offset(cap("refFrom", lambda: ref.getFromAddress()))
                to_off = address_offset(to_addr)
                if from_off is None or to_off is None:
                    continue
                kind = None
                if bool(cap("refIsCall", lambda: ref_type.isCall(), False)):
                    kind = "call"
                elif bool(cap("refIsData", lambda: ref_type.isData(), False)) \
                        or bool(cap("refIsRead", lambda: ref_type.isRead(), False)) \
                        or bool(cap("refIsWrite", lambda: ref_type.isWrite(), False)):
                    kind = classify_data_xref_target(to_off)
                if kind is None:
                    continue
                key = (addr(from_off), addr(to_off), kind)
                if key in xref_seen:
                    continue
                xref_seen.add(key)
                out["crossReferences"].append({"from": key[0], "to": key[1], "kind": key[2]})
                if len(out["crossReferences"]) >= max_xrefs:
                    break
            if len(out["crossReferences"]) >= max_xrefs:
                break

    # --- pseudocode (Ghidra's decompiler; first N procedures by start address) ---
    if max_pseudo > 0 and funcs:
        targets = sorted(funcs, key=lambda f: int(f.getEntryPoint().getOffset()))[:max_pseudo]
        ifc = cap("decompIfc", lambda: DecompInterface())
        if ifc is not None and bool(cap("decompOpen", lambda: ifc.openProgram(program), False)):
            for func in targets:
                res = cap("decompFn", lambda: ifc.decompileFunction(func, 60, monitor))
                if res is None or not bool(cap("decompOK", lambda: res.decompileCompleted(), False)):
                    continue
                df = cap("decompDF", lambda: res.getDecompiledFunction())
                c_text = str(cap("decompC", lambda: df.getC()) or "") if df is not None else ""
                out["pseudocode"].append({
                    "procedureStartAddress": addr(cap("psEP", lambda: func.getEntryPoint().getOffset(), 0)),
                    "procedureName": str(cap("psName", lambda: func.getName()) or "sub"),
                    "returnType": "",
                    "lines": c_text.split("\n"),
                })
            cap("decompDispose", lambda: ifc.dispose())

    # Light, stable ordering for a human-diffable file (the Swift diff is order-independent).
    out["sections"].sort(key=lambda s: (s["address"], s["name"]))
    out["symbols"].sort(key=lambda s: (s["address"] or "~", s["name"]))
    out["imports"].sort(key=lambda i: (i["name"], i["libraryName"] or ""))
    out["exports"].sort(key=lambda e: (e["address"] or "~", e["name"]))
    out["instructions"].sort(key=lambda i: i["address"])
    out["procedures"].sort(key=lambda p: p["startAddress"])
    out["basicBlocks"].sort(key=lambda b: (b["startAddress"], b["endAddress"]))
    out["controlFlowEdges"].sort(key=lambda e: (e["from"], e["to"], e["kind"]))
    out["crossReferences"].sort(key=lambda r: (r["from"], r["to"], r["kind"]))
    out["demangledNames"].sort(key=lambda d: d["mangled"])
    out["pseudocode"].sort(key=lambda p: p["procedureStartAddress"])
    return out


def main():
    parser = argparse.ArgumentParser(description="Export Ghidra analysis as MacScope GoldenOutput JSON.")
    parser.add_argument("binary", help="path to the (thin) binary to analyze")
    parser.add_argument("out", help="destination JSON path")
    parser.add_argument("--basename", default=None,
                        help="override the binary basename in the output (e.g. 'ls')")
    parser.add_argument("--project-dir", default=None, help="Ghidra project location (temp by default)")
    parser.add_argument("--max-instr", type=int, default=MAX_INSTR_DEFAULT)
    parser.add_argument("--max-pseudo", type=int, default=MAX_PSEUDO_DEFAULT)
    parser.add_argument("--max-edges", type=int, default=MAX_EDGES_DEFAULT)
    parser.add_argument("--max-xrefs", type=int, default=MAX_XREFS_DEFAULT)
    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        sys.exit("error: binary not found: %s" % args.binary)
    if "GHIDRA_INSTALL_DIR" not in os.environ:
        sys.exit("error: GHIDRA_INSTALL_DIR is not set (point it at .../ghidra/<ver>/libexec)")

    import pyghidra
    pyghidra.start()  # boots the JVM; must precede any `import ghidra.*`

    project_dir = args.project_dir or os.path.join(
        os.path.dirname(os.path.abspath(args.out)) or ".", "_ghidra_project")
    os.makedirs(project_dir, exist_ok=True)

    log = []
    with pyghidra.open_program(
        args.binary,
        project_location=project_dir,
        project_name="macscope_golden",
        analyze=True,
    ) as flat:
        out = build_golden(flat, args.basename, args.max_instr, args.max_pseudo,
                           args.max_edges, args.max_xrefs, log)

    with open(args.out, "w") as fh:
        json.dump(out, fh, indent=2, sort_keys=True)

    counts = {k: len(v) for k, v in out.items() if isinstance(v, list)}
    print("GHIDRA_EXPORT_DONE -> %s  counts=%s  arch=%s  log=%s"
          % (args.out, counts, out["binary"].get("architecture"), log[:8]))


if __name__ == "__main__":
    main()
