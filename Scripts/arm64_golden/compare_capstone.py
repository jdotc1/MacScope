#!/usr/bin/env python3
"""Add Capstone observations to a bounded differential_sweep.py TSV report.

The base must match the sweep's recorded base; word order determines addresses.
Text differences are observations, not proof of different semantics.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from pathlib import Path

MAX_WORDS = 128
COLUMNS = ('word', 'source', 'category', 'detail', 'group', 'fields', 'known', 'llvm', 'macscope')
LINE = re.compile(r'^\s*([0-9a-fA-F]+)\s+((?:[0-9a-fA-F]{2}\s+){4})(.*\S)\s*$')


def read_sweep(path: Path) -> list[dict[str, str]]:
    with path.open(encoding='utf-8', newline='') as file:
        header = file.readline().rstrip('\n').lstrip('# ').split('\t')
        if tuple(header) != COLUMNS:
            raise ValueError('unexpected sweep.tsv header')
        rows = list(csv.DictReader(file, fieldnames=COLUMNS, delimiter='\t'))
    if not 1 <= len(rows) <= MAX_WORDS:
        raise ValueError(f'expected 1 to {MAX_WORDS} instruction rows')
    for row in rows:
        if None in row or any(value is None for value in row.values()) or not re.fullmatch(r'[0-9a-fA-F]{8}', row['word']):
            raise ValueError('malformed sweep row')
    return rows


def capstone_decode(cstool: str, word: int, address: int) -> str | None:
    encoded = word.to_bytes(4, 'little').hex()
    result = subprocess.run([cstool, 'arm64', encoded, hex(address)], capture_output=True, text=True)
    if result.returncode == 252 and result.stdout.strip() == 'ERROR: invalid assembly code':
        return None
    if result.returncode:
        raise RuntimeError(f'cstool failed ({result.returncode}): {result.stderr or result.stdout}')
    match = LINE.fullmatch(result.stdout.strip())
    if not match or int(match.group(1), 16) != address or bytes.fromhex(match.group(2)) != bytes.fromhex(encoded):
        raise RuntimeError(f'unexpected cstool output: {result.stdout!r}')
    return ' '.join(match.group(3).split())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sweep', type=Path, required=True, help='sweep.tsv from the existing LLVM/MacScope workflow')
    parser.add_argument('--base', type=lambda x: int(x, 0), required=True, help='base address recorded by that sweep')
    parser.add_argument('--out', type=Path, required=True, help='new JSON output file')
    parser.add_argument('--cstool', default='cstool', help='Capstone cstool executable')
    args = parser.parse_args()
    try:
        rows = read_sweep(args.sweep)
        summary = json.loads(args.sweep.with_name('summary.json').read_text(encoding='utf-8'))
        bases = [int(match.group(1), 16) for line in summary['header']
                 if (match := re.search(r'\bbase=(0x[0-9a-fA-F]+)\b', line))]
        if bases != [args.base]:
            raise ValueError('base does not match the sweep summary')
        if args.base < 0 or args.base + 4 * len(rows) > 1 << 64:
            raise ValueError('address range is outside uint64')
        version = subprocess.run([args.cstool, '-v'], capture_output=True, text=True, check=True).stdout.strip()
        for index, row in enumerate(rows):
            address = args.base + index * 4
            capstone = capstone_decode(args.cstool, int(row['word'], 16), address)
            row.update(address=hex(address), capstone=capstone,
                       capstone_status='decoded' if capstone is not None else 'not-decoded')
        payload = {'base': hex(args.base), 'source_sweep': str(args.sweep), 'capstone_version': version,
                   'note': 'Text differences and decode availability are observations, not semantic verdicts.',
                   'rows': rows}
        with args.out.open('x', encoding='utf-8') as out:
            json.dump(payload, out, indent=2)
            out.write('\n')
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f'comparison failed: {exc}', file=sys.stderr)
        return 1
    print(f'Wrote {len(rows)} comparisons to {args.out}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
