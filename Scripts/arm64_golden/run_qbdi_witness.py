#!/usr/bin/env python3
"""Display retained QBDI evidence or run one opt-in ARM64 trace.

A new run is subject to MacScope's verification-reuse policy. Historical
receipts are displayed as supplied; they are not re-verified or promoted.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WITNESSES = ROOT / 'Scripts/arm64_golden/witnesses'


def check_trace(output: str) -> None:
    lines = output.splitlines()
    if not lines or lines[-1] != 'PASS' or lines.count('PASS') != 1 or 'FAIL' in lines:
        raise ValueError('QBDI trace did not report an unambiguous PASS')


def run_command(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode:
        raise RuntimeError(f'{command[0]} failed with exit {result.returncode}: {result.stderr or result.stdout}')
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--reuse-receipt', type=Path, help='show historical evidence without running tools')
    action.add_argument('--run', action='store_true', help='run the trace when authorized by verification policy')
    parser.add_argument('--out', type=Path, help='new external work directory, required for --run')
    parser.add_argument('--qbdi-prefix', type=Path, default=Path('/opt/homebrew/opt/qbdi'))
    parser.add_argument('--cc', default='clang')
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
        binary = out / 'qbdi-trace'
        lib = args.qbdi_prefix / 'lib'
        run_command([args.cc, '-arch', 'arm64', '-O1', '-Wall', '-Wextra',
                     '-I', str(args.qbdi_prefix / 'include'), '-L', str(lib),
                     f'-Wl,-rpath,{lib}', str(WITNESSES / 'qbdi-trace.c'),
                     str(WITNESSES / 'qbdi-target.s'), '-lQBDI', '-o', str(binary)])
        trace = run_command([str(binary)])
        check_trace(trace)
        receipt = {'kind': 'new-qbdi-witness', 'trace_output': trace,
                   'scope': 'One QBDI trace of an independently built ARM64 fixture; '
                            'not MacScope app runtime or a fresh MacIR test.'}
        (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
        print(trace, end='')
        print('Receipt:', out / 'receipt.json')
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f'QBDI witness workflow failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
