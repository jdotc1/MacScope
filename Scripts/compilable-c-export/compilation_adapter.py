"""Explicitly signature-assisted C export, separate from raw DEA scoring.

Consumes retained text evidence only. Does not launch, build, hash, rewrite
receipts, change the v1 normalizer, or enable any benchmark queue.
"""
from __future__ import annotations
from dataclasses import dataclass
import re


class UnsupportedExport(ValueError):
    pass


@dataclass(frozen=True)
class Parameter:
    declaration: str
    name: str
    register: str
    abi_type: str


@dataclass(frozen=True)
class Export:
    source: str
    rules: tuple[str, ...]
    emitted_symbol: str
    classification: str = 'SIGNATURE_ASSISTED_C_EXPORT'
    runtime_equivalence: str = 'NOT_ESTABLISHED'


_ID = r'[A-Za-z_][A-Za-z_0-9]*'
_SCALAR = r'(?:u?int(?:8|16|32|64)_t|float|double|int)'
_HELPERS = {
    '__a64_subtract_f32': 'static inline float __a64_subtract_f32(float a, float b) { return a - b; }',
    '__a64_absolute_f64': 'static inline double __a64_absolute_f64(double a) { return fabs(a); }',
}


def adapt(pseudocode: str, *, prototype: str, parameters: tuple[Parameter, ...],
          symbol_map: dict[str, str], disassembly: str,
          emitted_name: str | None = None) -> Export:
    """Export a bounded scalar leaf using an explicitly supplied C contract.

    A declaration is evidence, not inferred source order. ABI aliases stay local
    to the generated body. Return and frame recovery require matching decoded
    rows. Failure is atomic: no partially repaired source is returned.
    """
    def require(condition, reason):
        if not condition:
            raise UnsupportedExport(reason)

    signature = re.fullmatch(r'\s*int\s+(' + _ID + r')\s*\(([^()]*)\)\s*;?\s*', prototype)
    require(signature is not None, 'requires an explicit int-returning scalar prototype')
    target, supplied = signature.groups()
    output_name = target if emitted_name is None else emitted_name
    require(isinstance(output_name, str) and re.fullmatch(_ID, output_name) is not None,
            'invalid output symbol')
    require(output_name not in {'auto', 'break', 'case', 'char', 'const', 'continue',
            'default', 'do', 'double', 'else', 'enum', 'extern', 'float', 'for',
            'goto', 'if', 'inline', 'int', 'long', 'register', 'restrict', 'return',
            'short', 'signed', 'sizeof', 'static', 'struct', 'switch', 'typedef',
            'union', 'unsigned', 'void', 'volatile', 'while', '_Bool', '_Complex',
            '_Atomic', '_Alignas', '_Alignof', '_Generic', '_Noreturn', '_Static_assert',
            '_Thread_local', 'int64_t', 'uint64_t', 'int32_t', 'uint32_t', 'uintptr_t',
            'fabs', *list(_HELPERS)}, 'output symbol conflicts with C/support namespace')
    require(supplied.strip() == ', '.join(p.declaration for p in parameters),
            'source parameter order/declarations disagree with supplied prototype')
    require(len({p.name for p in parameters}) == len(parameters), 'duplicate source parameter')
    header = re.match(r'int64_t\s+(' + _ID + r')\(/\* ABI inputs: ([^\n]*) \*/\) \{\n', pseudocode)
    require(header is not None, 'expected exact ABI-only fallback header')
    emitted, abi_text = header.groups()
    require(symbol_map.get(emitted) == target and emitted == '_' + target,
            'target name requires the retained single-underscore symbol mapping')
    entries = abi_text.split(', ')
    aliases: dict[str, str] = {}
    registers: dict[str, str] = {}
    for item in entries:
        match = re.fullmatch(r'([xwsd][0-7]):(' + _SCALAR + r') (' + _ID + r')', item)
        require(match is not None, 'unsupported ABI input record')
        register, type_name, alias = match.groups()
        require(register not in registers and alias not in aliases, 'duplicate ABI input')
        require(type_name == {'x': 'int64_t', 'w': 'int32_t', 's': 'float', 'd': 'double'}[register[0]],
                'ABI register and scalar type disagree')
        registers[register] = alias
        aliases[alias] = type_name
    require(len(parameters) == len(entries), 'source/ABI parameter counts disagree')
    require(len({p.register for p in parameters}) == len(parameters), 'duplicate parameter binding')
    bindings = []
    for parameter in parameters:
        require(re.fullmatch(_ID, parameter.name) is not None, 'invalid source parameter name')
        require(parameter.register in registers, 'source parameter lacks an explicit ABI binding')
        alias = registers[parameter.register]
        require(aliases[alias] == parameter.abi_type, 'source binding disagrees with ABI type')
        base = parameter.declaration.removesuffix(parameter.name).strip()
        require(base + ' ' + parameter.name == parameter.declaration,
                'unsupported source declaration spelling')
        if base.endswith('*'):
            require(base in ('float *', 'double *', 'int *') and parameter.register.startswith('x'),
                    'unsupported pointer binding')
            expression = '(int64_t)(uintptr_t)' + parameter.name
        elif base == 'int':
            require(parameter.register.startswith('w'), 'int parameter needs a W-register binding')
            expression = '(int32_t)' + parameter.name
        else:
            require(base in ('float', 'double') and base == parameter.abi_type,
                    'unsupported scalar binding')
            expression = parameter.name
        bindings.append(f'    {parameter.abi_type} {alias} = {expression};')

    body = pseudocode[header.end():]
    require(body.endswith('}\n') or body.endswith('}'), 'incomplete function body')
    # These rows are evidence from the retained disassembly, not new decoding.
    machine = []
    for line in disassembly.splitlines():
        row = re.match(r'^([0-9a-fA-F]+):\s+(?:(?:[0-9a-fA-F]{2})\s+){4}([a-z0-9.]+)\s*(.*)$', line)
        if row:
            machine.append((row[2], row[3].strip()))
    require(len(machine) >= 4 and machine[-1] == ('ret', ''), 'missing ordinary leaf return evidence')
    require(not any(op in ('bl', 'blr', 'br') for op, _ in machine), 'calls/indirect flow unsupported')
    sp_writes = [(op, args) for op, args in machine if re.match(r'sp\s*,', args)]
    require(len(sp_writes) == 2 and sp_writes[0][0] == 'sub' and sp_writes[1][0] == 'add',
            'unsupported stack-pointer writes')
    frame = re.fullmatch(r'sp, sp, #(0x[0-9a-f]+|[0-9]+)', sp_writes[0][1])
    require(frame is not None and sp_writes[1][1] == sp_writes[0][1], 'unbalanced decoded frame')
    amount = int(frame[1], 0)
    require(0 < amount <= 4096 and machine[0] == sp_writes[0]
            and machine[-2] == sp_writes[1], 'nonlocal frame lifetime unsupported')
    bookkeeping = list(re.finditer(r'^    (' + _ID + r') = __(stack_alloc|stack_free)\((0x[0-9a-f]+|[0-9]+)\);[^\n]*\n', body, re.M))
    require([m[2] for m in bookkeeping] == ['stack_alloc', 'stack_free']
            and all(int(m[3], 0) == amount for m in bookkeeping), 'unproven stack helper sequence')
    for match in bookkeeping:
        require(len(re.findall(r'\b' + re.escape(match[1]) + r'\b', body)) == 1,
                'stack helper result escapes bookkeeping')
    body = re.sub(r'^    ' + _ID + r' = __stack_(?:alloc|free)\([^\n]*\n', '', body, flags=re.M)
    require(re.search(r'\bsp(?:_[0-9]+)?\b', body) is None, 'remaining stack pointer use')
    ret_load = re.fullmatch(r'w0, \[sp, #(0x[0-9a-f]+|[0-9]+)\]', machine[-3][1])
    require(machine[-3][0] == 'ldr' and ret_load is not None, 'return register is not a proven W0 load')
    offset = int(ret_load[1], 0)
    require(offset + 4 <= amount, 'return slot outside admitted frame')
    terminal = re.search(r'    (w0_[0-9]+) = \*\(uint32_t \*\)&\(local_([0-9a-f]+)\);[^\n]*\n    return unresolved_return_contract;[^\n]*\n?\}\n?\Z', body)
    require(terminal is not None and int(terminal[2], 16) == offset,
            'unresolved return lacks exact final decoded register/slot evidence')
    require(body.count('unresolved_return_contract') == 1, 'multiple unresolved return contracts')
    body = body.replace('return unresolved_return_contract;', f'return (int){terminal[1]};')
    require('__unknown' not in body and '__unavailable' not in body, 'unsupported/refused body')

    types = dict(aliases)
    for type_name, name in re.findall(r'^    (' + _SCALAR + r') (' + _ID + r');$', body, re.M):
        require(name not in types, 'local/input name collision')
        types[name] = type_name
    local_names = set(types)
    require(not (set(p.name for p in parameters) & local_names), 'source parameter shadows emitted storage')
    assignments = re.findall(r'^    (' + _ID + r') = ([^;\n]+);', body, re.M)
    pending = list(assignments)
    declared = {}

    def expression_type(name, expression):
        register = re.fullmatch(r'([swdx])[0-9]+_[0-9]+', name)
        fixed = {'s': 'float', 'd': 'double', 'w': 'uint32_t', 'x': 'uint64_t'}
        if register:
            return fixed[register[1]]
        load = re.match(r'\*\((' + _SCALAR + r') \*\)', expression)
        if load:
            return load[1]
        if expression in types:
            return types[expression]
        if re.fullmatch(r'(?:0x[0-9a-f]+|[0-9]+)', expression):
            require(int(expression, 0) <= 0x7fffffff, 'large untyped integer literal')
            return 'int32_t'
        if '// compare to bool' in next((line for line in body.splitlines() if line.startswith('    ' + name + ' = ')), ''):
            require(re.fullmatch(r'\(double\)\(' + _ID + r'\) < \(double\)\(' + _ID + r'\)', expression),
                    'unsupported comparison predicate')
            require(all(value in types for value in re.findall(r'\(double\)\((' + _ID + r')\)', expression)),
                    'comparison reads an undeclared value')
            return 'int'
        binary = re.fullmatch(r'(' + _ID + r') [+-] (' + _ID + r'|0x[0-9a-f]+)', expression)
        if binary:
            left = types.get(binary[1]); right = types.get(binary[2])
            if binary[2].startswith('0x') and int(binary[2], 16) <= 0x7fffffff:
                right = 'int32_t'
            if left and right:
                require(left in ('uint32_t', 'int32_t', 'int64_t') and right in ('uint32_t', 'int32_t', 'int64_t'),
                        'unsupported arithmetic types')
                return 'int64_t' if 'int64_t' in (left, right) else 'uint32_t' if 'uint32_t' in (left, right) else 'int32_t'
        return None

    while pending:
        deferred = []
        for name, expression in pending:
            type_name = expression_type(name, expression)
            if type_name is None:
                deferred.append((name, expression)); continue
            require(name not in types or types[name] == type_name, 'conflicting storage types')
            if name not in local_names:
                require(name not in {p.name for p in parameters}, 'temporary shadows source parameter')
                declared[name] = type_name
            types[name] = type_name
        require(len(deferred) < len(pending), 'cannot prove every temporary type')
        pending = deferred
    used_helpers = set(re.findall(r'\b(__[A-Za-z_0-9]+)\s*\(', body))
    require(used_helpers <= _HELPERS.keys(), 'unsupported helper; no stubs permitted')
    # A new declaration must never hide a still unresolved identifier. Comments
    # and hex literals are not identifiers; labels occupy a distinct C namespace.
    code = re.sub(r'/\*[\s\S]*?\*/|//[^\n]*', '', body)
    code = re.sub(r'\b0x[0-9a-fA-F]+\b', '0', code)
    labels = set(re.findall(r'^\s*(' + _ID + r'):', code, re.M))
    words = set(re.findall(r'\b' + _ID + r'\b', code))
    allowed = set(types) | labels | used_helpers | {
        'int', 'int8_t', 'int16_t', 'int32_t', 'int64_t', 'uint8_t',
        'uint16_t', 'uint32_t', 'uint64_t', 'float', 'double', 'if', 'goto', 'return',
    }
    require(words <= allowed, 'body contains an unresolved identifier')
    require(output_name not in set(types) | labels | {p.name for p in parameters},
            'output symbol collides with function storage or labels')
    helper_text = '\n'.join(_HELPERS[name] for name in sorted(used_helpers))
    declarations = [f'    {type_name} {name};' for name, type_name in sorted(declared.items())]
    source = '#include <stdint.h>\n#include <math.h>\n' + helper_text + '\n'
    source += f'int {output_name}({supplied}) {{\n' + '\n'.join(bindings + declarations) + '\n' + body
    rules = ('EXPLICIT-SOURCE-PROTOTYPE', 'EXPLICIT-ABI-BINDINGS',
                          'TYPED-STORAGE-DECLARATIONS', 'DEAD-BALANCED-FRAME-BOOKKEEPING',
                          'DECODED-W0-RETURN-SLOT', 'SCALAR-NUMERIC-HELPERS')
    if output_name != target:
        rules += ('CALLER-CHOSEN-OUTPUT-SYMBOL',)
    return Export(source, rules, output_name)
