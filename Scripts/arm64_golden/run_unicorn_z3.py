#!/usr/bin/env python3
"""Display retained evidence or run the opt-in Unicorn/Z3 ARM64 witness.

A new run is subject to MacScope's verification-reuse policy. The prior receipt
is historical evidence; this tool does not re-verify or promote its source identity.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WITNESSES = ROOT / 'Scripts/arm64_golden/witnesses'
PASS_MARKER = 'PASS: result and checked unchanged registers/flags match the existing fixture'


def check_solver(output: str) -> None:
    if output.strip() != 'unsat':
        raise ValueError(f'Z3 did not prove the modeled equivalence: {output!r}')


def run_command(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
    if result.returncode != 0:
        raise RuntimeError(f'{command[0]} failed with exit {result.returncode}: {result.stderr or result.stdout}')
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--reuse-receipt', type=Path, help='show a retained prior receipt without running tools')
    action.add_argument('--run', action='store_true', help='run the two checks when authorized by verification policy')
    parser.add_argument('--out', type=Path, help='new external work directory, required for --run')
    parser.add_argument('--unicorn-prefix', type=Path, default=Path('/opt/homebrew/opt/unicorn'))
    parser.add_argument('--cc', default='clang')
    parser.add_argument('--z3', default='z3')
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
        binary = out / 'unicorn-add'
        run_command([args.cc, '-O2', '-Wall', '-Wextra', '-I', str(args.unicorn_prefix / 'include'),
                     '-L', str(args.unicorn_prefix / 'lib'), str(WITNESSES / 'unicorn-add.c'),
                     '-lunicorn', '-o', str(binary)])
        witness = run_command([str(binary)])
        if PASS_MARKER not in witness.splitlines():
            raise ValueError('Unicorn witness did not report its expected successful result')
        solver = run_command([args.z3, '-smt2', str(WITNESSES / 'ubfiz-equivalence.smt2')])
        check_solver(solver)
        receipt = {'kind': 'new-tool-witness', 'unicorn_output': witness, 'z3_output': solver,
                   'scope': 'One Unicorn architectural case and one modeled 64-bit bit-vector expression; '
                            'not a fresh MacIR test or proof of the running implementation.'}
        (out / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
        print(witness, end='')
        print('Z3:', solver.strip())
        print('Receipt:', out / 'receipt.json')
        return 0
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f'ARM64 witness workflow failed: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
