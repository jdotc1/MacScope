"""App-authored native-call transaction, installed into a private LLDB generation.

All expressions are assembled from a closed type vocabulary and typed numeric data.
Target output is never part of this protocol. The host retains process ownership.
"""
import base64
import ctypes
import json
import os
import re
import lldb

_state = {"phase": "empty", "sequence": 0}
_types = {
    "void": ("void", 0), "int8": ("signed char", 1), "uint8": ("unsigned char", 1),
    "int16": ("short", 2), "uint16": ("unsigned short", 2),
    "int32": ("int", 4), "uint32": ("unsigned int", 4),
    "int64": ("long long", 8), "uint64": ("unsigned long long", 8), "pointer": ("void *", 8),
}


class _BSDInfo(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in (
        "flags", "status", "xstatus", "pid", "ppid", "uid", "gid", "ruid", "rgid", "svuid", "svgid", "rfu")]
    _fields_ += [("comm", ctypes.c_char * 16), ("name", ctypes.c_char * 32)]
    _fields_ += [(name, ctypes.c_uint32) for name in ("nfiles", "pgid", "pjobc", "tdev", "tpgid")]
    _fields_ += [("nice", ctypes.c_int32), ("seconds", ctypes.c_uint64), ("microseconds", ctypes.c_uint64)]


def _require(condition, message):
    if not condition:
        raise RuntimeError(message)


def _unsigned(text):
    _require(type(text) is str and re.fullmatch(r"0|[1-9][0-9]{0,19}", text) is not None, "invalid unsigned value")
    value = int(text)
    _require(value <= 0xffffffffffffffff, "unsigned value overflow")
    return value


def _identity(request):
    info = _BSDInfo()
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    observed = library.proc_pidinfo(request["pid"], 3, 0, ctypes.byref(info), ctypes.sizeof(info))
    _require(observed == ctypes.sizeof(info), "owned process identity is unavailable")
    _require((info.pid, info.seconds, info.microseconds) ==
             (request["pid"], _unsigned(request["startSeconds"]), _unsigned(request["startMicroseconds"])),
             "owned process identity changed")
    path = ctypes.create_string_buffer(4096)
    _require(library.proc_pidpath(request["pid"], path, len(path)) > 0, "owned executable path unavailable")
    _require(os.fsdecode(path.value) == request["path"], "owned executable changed")


def _emit(phase, ok=True, error=None, **values):
    _state["sequence"] += 1
    record = {"schema": 1, "token": _state.get("token", ""), "sequence": _state["sequence"],
              "requestID": _state.get("requestID", ""), "phase": phase, "ok": ok,
              "error": error[:2048] if error else None}
    record.update(values)
    print("MACSCOPE_NATIVE_V1 " + json.dumps(record, sort_keys=True, separators=(",", ":")))


def begin(token, request_id, count, byte_count):
    _require(_state["phase"] == "empty", "native request already exists")
    _require(type(token) is str and re.fullmatch(r"[a-f0-9]{64}", token) is not None, "invalid session token")
    _require(type(request_id) is str and re.fullmatch(r"[a-fA-F0-9-]{36}", request_id) is not None, "invalid request identity")
    _require(type(count) is int and 1 <= count <= 512 and type(byte_count) is int and 0 < byte_count <= 131072,
             "request exceeds capacity")
    _state.update(token=token, requestID=request_id, count=count, byteCount=byte_count,
                  upload=[], phase="uploading")
    _emit("begin")


def append(token, index, chunk):
    _require(token == _state.get("token") and _state["phase"] == "uploading", "request upload is stale")
    _require(type(index) is int and index == len(_state["upload"]) and index < _state["count"], "request chunk order changed")
    _require(type(chunk) is str and len(chunk) <= 512 and re.fullmatch(r"[A-Za-z0-9+/=]+", chunk) is not None,
             "request chunk invalid")
    _state["upload"].append(chunk)
    _emit("append", index=index)


def _decode_request():
    _require(len(_state["upload"]) == _state["count"], "request upload is incomplete")
    encoded = "".join(_state.pop("upload"))
    raw = base64.b64decode(encoded, validate=True)
    _require(len(raw) == _state["byteCount"], "request byte count changed")
    def unique_pairs(pairs):
        value = {}
        for key, item in pairs:
            _require(key not in value, "duplicate request key")
            value[key] = item
        return value
    request = json.loads(raw, object_pairs_hook=unique_pairs)
    expected = {"requestID", "path", "uuid", "pid", "startSeconds", "startMicroseconds",
                "entry", "function", "regions", "returnType", "arguments", "globals", "timeoutMicroseconds"}
    _require(type(request) is dict and set(request) == expected, "invalid request schema")
    _require(request["requestID"] == _state["requestID"], "request identity mismatch")
    _require(type(request["path"]) is str and request["path"].startswith("/") and len(request["path"].encode()) <= 4096,
             "invalid executable path")
    _require(type(request["uuid"]) is str and re.fullmatch(r"[a-f0-9]{32}", request["uuid"]) is not None, "invalid image UUID")
    _require(type(request["pid"]) is int and 1 < request["pid"] <= 2147483647 and request["pid"] != os.getpid(), "invalid process")
    _require(request["returnType"] in _types, "unsupported return type")
    _require(type(request["timeoutMicroseconds"]) is int and 100000 <= request["timeoutMicroseconds"] <= 10000000,
             "invalid call timeout")
    _require(type(request["regions"]) is list and 1 <= len(request["regions"]) <= 128, "invalid image regions")
    for region in request["regions"]:
        _require(set(region) == {"name", "address", "size", "permissions"}, "invalid image region")
        address, size = _unsigned(region["address"]), _unsigned(region["size"])
        _require(size > 0 and address + size <= 0x10000000000000000,
                 "invalid image interval")
        _require(type(region["permissions"]) is int and 0 <= region["permissions"] <= 7, "invalid region permissions")
    def admits(address, count, permission):
        matches = [r for r in request["regions"] if r["permissions"] & permission
                   and _unsigned(r["address"]) <= address
                   and address + count <= _unsigned(r["address"]) + _unsigned(r["size"])]
        return len(matches) == 1
    _require(_unsigned(request["entry"]) % 4 == 0 and admits(_unsigned(request["entry"]), 4, 4), "invalid startup address")
    _require(_unsigned(request["function"]) % 4 == 0 and admits(_unsigned(request["function"]), 4, 4), "invalid function address")
    _require(type(request["arguments"]) is list and len(request["arguments"]) <= 16, "too many arguments")
    _require(type(request["globals"]) is list and len(request["globals"]) <= 16, "too many globals")
    count, byte_count = len(request["globals"]), 0
    for region in request["globals"]:
        _require(set(region) == {"label", "address", "size"}, "invalid global")
        _require(type(region["size"]) is int and 0 < region["size"] <= 65536
                 and admits(_unsigned(region["address"]), region["size"], 1), "invalid global interval")
        _require(type(region["label"]) is str and len(region["label"].encode()) <= 256, "invalid global label")
        byte_count += region["size"]
    for argument in request["arguments"]:
        _require(set(argument) == {"type", "kind", "data", "address"}, "invalid argument")
        typ, kind = argument["type"], argument["kind"]
        _require(typ in _types and typ != "void", "unsupported parameter")
        _require(kind in ("integer", "null", "buffer", "image"), "unsupported argument storage")
        if kind == "integer":
            _require(typ != "pointer" and argument["address"] is None, "invalid integer storage")
            data = base64.b64decode(argument["data"], validate=True)
            _require(len(data) == _types[typ][1], "integer width mismatch")
        elif kind == "buffer":
            _require(typ == "pointer" and argument["address"] is None, "invalid buffer storage")
            data = base64.b64decode(argument["data"], validate=True)
            _require(0 < len(data) <= 65536, "invalid argument buffer")
            count += 1
            byte_count += len(data)
        elif kind == "null":
            _require(typ == "pointer" and argument["data"] is None and argument["address"] is None, "invalid null pointer")
        else:
            address = _unsigned(argument["address"])
            _require(typ == "pointer" and argument["data"] is None
                     and any(_unsigned(r["address"]) <= address < _unsigned(r["address"]) + r["size"]
                             for r in request["globals"]), "pointer has no observed image range")
    _require(count <= 16 and byte_count <= 65536, "observation budget exceeded")
    return request


def _module(target, request):
    _require(target.GetNumModules() <= 4096, "runtime module inventory exceeds limit")
    matches = [m for m in target.modules if os.path.realpath(m.GetFileSpec().fullpath) == request["path"]
               and m.GetUUIDString().replace("-", "").lower() == request["uuid"]]
    _require(len(matches) == 1, "loaded image identity is ambiguous or changed")
    module = matches[0]
    _require(module.GetTriple().split("-")[0] == "arm64", "loaded architecture is unsupported")
    return module


def _prove(allow_crashed=False):
    request, process, target = _state["request"], _state["process"], _state["target"]
    _identity(request)
    _require(process.IsValid() and process.GetProcessID() == request["pid"]
             and process.GetUniqueID() == _state["unique"], "debugger process changed")
    _require(process.GetState() in ((lldb.eStateStopped, lldb.eStateCrashed) if allow_crashed else (lldb.eStateStopped,))
             and process.GetStopID() == _state["stop"], "debugger stop changed")
    _module(target, request)
    return request, process, target


def _translate(address, count=1, permission=1):
    request, process, target = _prove()
    matches = [r for r in request["regions"] if r["permissions"] & permission
               and _unsigned(r["address"]) <= address
               and address + count <= _unsigned(r["address"]) + _unsigned(r["size"])]
    _require(len(matches) == 1, "static address has no unique admitted region")
    region = matches[0]
    module = _module(target, request)
    _require(module.GetNumSections() <= 128, "runtime section count exceeds limit")
    sections = [module.GetSectionAtIndex(i) for i in range(module.GetNumSections())]
    matches = [s for s in sections if s.GetFileAddress() == _unsigned(region["address"])
               and s.GetByteSize() == _unsigned(region["size"])]
    _require(len(matches) == 1, "runtime section does not match admitted image layout")
    loaded = matches[0].GetLoadAddress(target)
    _require(loaded != lldb.LLDB_INVALID_ADDRESS and loaded + address - _unsigned(region["address"]) + count <= 0x10000000000000000,
             "runtime address is unavailable or overflows")
    return loaded + address - _unsigned(region["address"])


def _operation(token, phase, operation):
    _require(token == _state.get("token"), "native operation token changed")
    previous = lldb.debugger.GetAsync()
    try:
        lldb.debugger.SetAsync(False)
        values = operation()
        _emit(phase, **(values or {}))
    except Exception as error:
        _state["phase"] = "failed"
        _emit(phase, ok=False, error=str(error))
    finally:
        lldb.debugger.SetAsync(previous)


def attach(token):
    def execute():
        _require(_state["phase"] == "uploading", "attach phase changed")
        request = _decode_request()
        _identity(request)
        target = lldb.debugger.CreateTargetWithFileAndArch(request["path"], "arm64")
        _require(target.IsValid(), "could not create native target")
        error = lldb.SBError()
        process = target.AttachToProcessWithID(lldb.SBListener(), request["pid"], error)
        _require(error.Success() and process.IsValid() and process.GetState() == lldb.eStateStopped, str(error))
        _state.update(request=request, target=target, process=process, unique=process.GetUniqueID(),
                      stop=process.GetStopID(), phase="attached", allocations=[])
        _prove()
        _require(process.GetNumThreads() >= 1, "native target has no thread")
        _state["thread"] = process.GetThreadAtIndex(0).GetThreadID()
        return {"pid": process.GetProcessID(), "stop": process.GetStopID()}
    _operation(token, "attach", execute)


def reach_entry(token):
    def execute():
        _require(_state["phase"] == "attached", "startup phase changed")
        request, process, target = _prove()
        entry = _translate(_unsigned(request["entry"]), 4, 4)
        breakpoint = target.BreakpointCreateByAddress(entry)
        _require(breakpoint.IsValid() and breakpoint.GetNumLocations() == 1, "startup breakpoint is ambiguous")
        breakpoint.SetThreadID(_state["thread"])
        _state["entryBreakpoint"] = breakpoint.GetID()
        error = process.Continue()
        _require(error.Success() and process.GetState() == lldb.eStateStopped, "startup failed: " + str(error))
        _state["stop"] = process.GetStopID()
        _prove()
        thread = process.GetThreadByID(_state["thread"])
        _require(thread.IsValid() and thread.GetFrameAtIndex(0).GetPC() == entry,
                 "target stopped before reaching the exact main entry")
        _require(target.BreakpointDelete(breakpoint.GetID()), "startup breakpoint cleanup failed")
        _state["phase"] = "atEntry"
        _state["function"] = _translate(_unsigned(request["function"]), 4, 4)
        return {"pid": request["pid"], "stop": process.GetStopID(), "function": str(_state["function"])}
    _operation(token, "entry", execute)


def _read(process, address, count):
    error = lldb.SBError()
    data = process.ReadMemory(address, count, error)
    if error.Fail() or data is None or len(data) != count:
        return None, str(error)[:1024]
    return base64.b64encode(data).decode("ascii"), None


def prepare_memory(token):
    def execute():
        _require(_state["phase"] == "atEntry", "memory preparation phase changed")
        request, process, target = _prove()
        arguments, observations = [], []
        for index, argument in enumerate(request["arguments"]):
            typ, kind = argument["type"], argument["kind"]
            if kind == "integer":
                raw = int.from_bytes(base64.b64decode(argument["data"], validate=True), "little")
                arguments.append("(%s)%dULL" % (_types[typ][0], raw))
            elif kind == "null":
                arguments.append("(void *)0ULL")
            elif kind == "image":
                arguments.append("(void *)%dULL" % _translate(_unsigned(argument["address"])))
            else:
                data = base64.b64decode(argument["data"], validate=True)
                error = lldb.SBError()
                address = process.AllocateMemory(len(data), lldb.ePermissionsReadable | lldb.ePermissionsWritable, error)
                _require(error.Success() and address != lldb.LLDB_INVALID_ADDRESS, "argument allocation failed")
                _state["allocations"].append(address)
                _require(process.WriteMemory(address, data, error) == len(data) and error.Success(), "argument initialization failed")
                arguments.append("(void *)%dULL" % address)
                observations.append({"label": "Argument %d" % (index + 1), "address": str(address), "size": len(data)})
        for region in request["globals"]:
            observations.append({"label": region["label"], "address": str(_translate(_unsigned(region["address"]), region["size"])),
                                 "size": region["size"]})
        for region in observations:
            before, error = _read(process, _unsigned(region["address"]), region["size"])
            region.update(before=before, after=None, diagnostic=error)
        _state.update(arguments=arguments, observations=observations, phase="ready")
        return {"pid": request["pid"], "stop": process.GetStopID(), "regions": len(observations)}
    _operation(token, "memory", execute)


def call(token):
    def execute():
        _require(_state["phase"] == "ready", "call phase changed")
        request, process, target = _prove()
        _state["phase"] = "calling"  # Never admit a second invocation, including after an error.
        frame = process.GetThreadByID(_state["thread"]).GetFrameAtIndex(0)
        _require(frame.IsValid(), "call frame is unavailable")
        return_type = _types[request["returnType"]][0]
        parameter_types = ", ".join(_types[a["type"]][0] for a in request["arguments"]) or "void"
        expression = "((%s (*)(%s))%dULL)(%s)" % (return_type, parameter_types, _state["function"], ", ".join(_state["arguments"]))
        if request["returnType"] == "void":
            expression = "(%s, 0ULL)" % expression
        options = lldb.SBExpressionOptions()
        options.SetLanguage(lldb.eLanguageTypeC_plus_plus)
        options.SetTimeoutInMicroSeconds(request["timeoutMicroseconds"])
        options.SetTryAllThreads(False)
        options.SetStopOthers(True)
        options.SetIgnoreBreakpoints(True)
        options.SetTrapExceptions(True)
        options.SetUnwindOnError(False)
        options.SetFetchDynamicValue(lldb.eNoDynamicValues)
        options.SetSuppressPersistentResult(True)
        value = frame.EvaluateExpression(expression, options)
        output = {"schema": 1, "requestID": request["requestID"], "uuid": request["uuid"],
                  "function": str(_state["function"]), "outcome": "completed", "returnBytes": None,
                  "memory": _state["observations"], "diagnostics": [], "faultPC": None}
        if not value.IsValid() or value.GetError().Fail():
            message = str(value.GetError())[:2048]
            output["diagnostics"].append(message)
            if "timed out" in message.lower() or "timeout" in message.lower():
                output["outcome"] = "timedOut"
            elif "EXC_" in message or "signal" in message.lower():
                output["outcome"] = "crashed"
            else:
                output["outcome"] = "failed"
            thread = process.GetSelectedThread()
            if thread.IsValid() and thread.GetNumFrames() > 0:
                pc = thread.GetFrameAtIndex(0).GetPC()
                if pc not in (0, lldb.LLDB_INVALID_ADDRESS):
                    output["faultPC"] = str(pc)
        elif request["returnType"] != "void":
            error = lldb.SBError()
            count = _types[request["returnType"]][1]
            data = value.GetData().ReadRawData(error, 0, count)
            if error.Success() and data is not None and len(data) == count:
                output["returnBytes"] = base64.b64encode(data).decode("ascii")
            else:
                output["outcome"] = "failed"
                output["diagnostics"].append("Typed return bytes were unavailable.")
        if process.GetState() in (lldb.eStateStopped, lldb.eStateCrashed):
            _state["stop"] = process.GetStopID()
            try:
                _prove(allow_crashed=True)
            except Exception as error:
                output["outcome"] = "failed"
                output["returnBytes"] = None
                output["diagnostics"].append(str(error)[:1024])
            else:
                for region in output["memory"]:
                    after, error = _read(process, _unsigned(region["address"]), region["size"])
                    region["after"] = after
                    if error:
                        region["diagnostic"] = error
                for address in _state["allocations"]:
                    process.DeallocateMemory(address)
        else:
            output["diagnostics"].append("The target exited before post-call memory could be read.")
        raw = json.dumps(output, sort_keys=True, separators=(",", ":")).encode()
        _require(len(raw) <= 262144, "native result exceeds capacity")
        encoded = base64.b64encode(raw).decode("ascii")
        _state.update(resultPages=[encoded[i:i+32768] for i in range(0, len(encoded), 32768)],
                      nextPage=0, phase="finished")
        return {"pages": len(_state["resultPages"]), "pid": request["pid"]}
    _operation(token, "call", execute)


def result_page(token, index):
    _require(token == _state.get("token") and _state["phase"] == "finished", "result is stale")
    _require(type(index) is int and index == _state["nextPage"] and index < len(_state["resultPages"]), "result page order changed")
    _state["nextPage"] += 1
    _emit("page", index=index, count=len(_state["resultPages"]), data=_state["resultPages"][index])


def close(token):
    _require(token == _state.get("token"), "close token changed")
    process = _state.get("process")
    if process is not None and process.IsValid():
        error = process.Destroy()
        _require(error.Success(), "native target destruction failed: " + str(error))
    _state["phase"] = "closed"
    _emit("close")
