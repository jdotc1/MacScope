#!/usr/bin/env python3
"""Display retained evidence or run one opt-in synthetic BinDiff comparison.

The records and matcher fingerprints are hand-authored. This is not a real
binary export, full MacScope analysis, or a general accuracy measurement.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'Scripts/version-matching/bindiff-comparison'
MODELS = ROOT / 'MacScope/Services/VersionMatching'
SCHEMA = ROOT / 'ThirdParty/BinExport'


def check_matcher(result: dict) -> None:
    actual = [(x['oldID'], x['newID'], x['basis'], x['differences']) for x in result['matches']]
    expected = [('old.alpha', 'new.alpha', 'symbolName', []),
                ('old.beta', 'new.beta', 'symbolName', ['body'])]
    if (actual != expected or result['addedIDs'] != ['new.added'] or
            result['removedIDs'] != ['old.removed'] or result['unresolved'] != []):
        raise ValueError('MacScope matcher output differs from the controlled fixture contract')


def run_command(command: list[str], input_data: bytes | None = None) -> bytes:
    result = subprocess.run(command, input=input_data, capture_output=True, timeout=120, check=False)
    if result.returncode:
        error = (result.stderr or result.stdout).decode('utf-8', errors='replace')
        raise RuntimeError(f'{command[0]} failed with exit {result.returncode}: {error}')
    return result.stdout


def read_bindiff(database: Path) -> list[dict]:
    with closing(sqlite3.connect(database.resolve().as_uri() + '?mode=ro', uri=True)) as db:
        rows = db.execute('SELECT f.address1, f.name1, f.address2, f.name2, '
                          'f.similarity, f.confidence, a.name FROM function f '
                          'LEFT JOIN functionalgorithm a ON a.id=f.algorithm ORDER BY f.address1').fetchall()
    return [dict(old_address=r[0], old_name=r[1], new_address=r[2], new_name=r[3],
                 similarity=r[4], confidence=r[5], algorithm=r[6]) for r in rows]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--reuse-receipt', type=Path, help='show historical evidence without running tools')
    action.add_argument('--run', action='store_true', help='run a new comparison when verification policy permits')
    parser.add_argument('--out', type=Path, help='new external output directory, required for --run')
    parser.add_argument('--bindiff-config', type=Path, default=Path('/opt/homebrew/libexec/bindiff/8/bindiff.json'))
    parser.add_argument('--protoc', default='protoc')
    parser.add_argument('--swiftc', default='swiftc')
    parser.add_argument('--bindiff', default='bindiff')
    args = parser.parse_args()
    try:
        if args.reuse_receipt:
            if args.out:
                raise ValueError('--out is not used with --reuse-receipt')
            print('Retained receipt (historical evidence; not re-verified):')
            print(args.reuse_receipt.read_text(encoding='utf-8'), end='')
            return 0
        if args.out is None:
            raise ValueError('--out is required for --run')
        out = args.out.resolve()
        repo = ROOT.resolve()
        if out == repo or repo in out.parents:
            raise ValueError('output must be outside the checkout')
        out.mkdir(parents=True, exist_ok=False)
        for name in ('old', 'new'):
            encoded = run_command([args.protoc, '--proto_path=' + str(SCHEMA), '--encode=BinExport2',
                                   'binexport2.proto'], (FIXTURES / f'{name}.textproto').read_bytes())
            (out / f'{name}.BinExport').write_bytes(encoded)
        probe = out / 'macscope-matcher'
        run_command([args.swiftc, '-swift-version', '6', '-O',
                     str(MODELS / 'FunctionVersionFingerprint.swift'),
                     str(MODELS / 'FunctionVersionMatchModels.swift'),
                     str(MODELS / 'FunctionVersionMatcher.swift'), str(FIXTURES / 'main.swift'),
                     '-o', str(probe)])
        matcher = json.loads(run_command([str(probe)]))
        check_matcher(matcher)
        diff_output = run_command([args.bindiff, '--config=' + str(args.bindiff_config),
                                   '--output_dir=' + str(out), str(out / 'old.BinExport'),
                                   str(out / 'new.BinExport')]).decode('utf-8')
        databases = list(out.glob('*.BinDiff'))
        if len(databases) != 1:
            raise ValueError('expected exactly one BinDiff result database')
        pairs = read_bindiff(databases[0])
        report = {'kind': 'synthetic-bindiff-comparison', 'macscope': matcher, 'bindiff_pairs': pairs,
                  'bindiff_output': diff_output,
                  'scope': 'Hand-authored synthetic BinExport records and hand-supplied MacScope fingerprints; '
                           'not full app analysis, real binary export, or an accuracy measurement.'}
        (out / 'comparison.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(diff_output, end='')
        print('MacScope fixture contract passed; inspect BinDiff pairs in', out / 'comparison.json')
        return 0
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, RuntimeError,
            subprocess.TimeoutExpired) as error:
        print(f'BinDiff comparison failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
