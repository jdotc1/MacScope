#!/usr/bin/env python3
"""Run bounded LLVM/MacScope/Capstone checks on curated and Csmith instructions.

Use already-built, source-matched Csmith objects and a source-matched decoder
probe. This entry point never builds or re-verifies either input.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GOLDEN = ROOT / 'Scripts/arm64_golden'
SEEDS = (101, 202, 303)
SAMPLE_PER_FIXTURE = 8
OBJ_LINE = re.compile(r'^\s*([0-9a-fA-F]+):\s+([0-9a-fA-F]{8})\s+')


def fixture_words(dump: str, limit: int) -> list[tuple[int, int]]:
    if not re.search(r'file format mach-o arm64\b', dump):
        raise ValueError('expected a Mach-O arm64 object')
    in_text = False
    result = []
    for line in dump.splitlines():
        if line.startswith('Disassembly of section '):
            in_text = line.strip() == 'Disassembly of section __TEXT,__text:'
            continue
        match = OBJ_LINE.match(line) if in_text else None
        if match:
            result.append((int(match.group(1), 16), int(match.group(2), 16)))
            if len(result) == limit:
                break
    if len(result) != limit:
        raise ValueError(f'object has fewer than {limit} decodable text words')
    return result


def check_curated(rows: list[dict]) -> None:
    expected = ('d503201f', '91000400', '8b020020', 'f9400020', '14000002', 'd65f03c0', 'ffffffff')
    if len(rows) < len(expected) or tuple(row['word'].lower() for row in rows[:7]) != expected:
        raise ValueError('curated instruction set does not match the focused contract')
    for row in rows[:6]:
        if not (row['capstone_status'] == 'decoded' and
                (row['category'] == 'match' or
                 (row['category'] == 'mismatch' and row['detail'] == 'spelling'))):
            raise ValueError(f"curated decode regression at {row['word']}; inspect comparison.json")
    if rows[6]['category'] != 'both-reject' or rows[6]['capstone_status'] != 'not-decoded':
        raise ValueError('curated undecoded-word status changed; inspect comparison.json')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True, help='existing source-matched decoder probe')
    parser.add_argument('--fixture-objects', type=Path, required=True, help='directory of seed-101.o, seed-202.o, seed-303.o')
    parser.add_argument('--out', type=Path, required=True, help='new external output directory')
    parser.add_argument('--cstool', default='cstool')
    args = parser.parse_args()
    try:
        if not args.probe.is_file():
            raise ValueError('existing probe is required')
        repo = ROOT.resolve()
        out = args.out.resolve()
        if out == repo or repo in out.parents:
            raise ValueError('output must be outside the checkout')
        out.mkdir(parents=True, exist_ok=False)
        curated = [int(word, 16) for word in (GOLDEN / 'fixtures/focused-arm64.words').read_text().split()]
        selection = []
        words = list(curated)
        for seed in SEEDS:
            obj = args.fixture_objects / f'seed-{seed}.o'
            if not obj.is_file() or obj.stat().st_size > 2_000_000:
                raise ValueError(f'missing or oversized fixture object: {obj}')
            dump = subprocess.run(['xcrun', 'llvm-objdump', '-d', str(obj)], capture_output=True,
                                  text=True, check=True).stdout
            for address, word in fixture_words(dump, SAMPLE_PER_FIXTURE):
                selection.append({'fixture': obj.name, 'original_address': hex(address), 'word': f'{word:08x}'})
                words.append(word)
        # The existing word-file workflow de-duplicates, preserving first occurrence.
        unique = list(dict.fromkeys(words))
        (out / 'selected.json').write_text(json.dumps({'curated_words': len(curated),
            'fixture_selections': selection, 'unique_words': len(unique),
            'note': 'Objects and probe must be matched to their source by the operator; '
                    'sample words are relocated to synthetic contiguous addresses.'}, indent=2) + '\n')
        word_file = out / 'words.hex'
        word_file.write_text(''.join(f'{word:08x}\n' for word in unique))
        sweep_out = out / 'sweep'
        subprocess.run([sys.executable, str(GOLDEN / 'differential_sweep.py'), '--words-file', str(word_file),
                        '--probe', str(args.probe.resolve()), '--jobs', '1', '--out', str(sweep_out)], check=True)
        comparison = out / 'comparison.json'
        subprocess.run([sys.executable, str(GOLDEN / 'compare_capstone.py'), '--sweep', str(sweep_out / 'sweep.tsv'),
                        '--base', '0x100000000', '--cstool', args.cstool, '--out', str(comparison)], check=True)
        report = json.loads(comparison.read_text())
        if len(report['rows']) != len(unique):
            raise ValueError('comparison did not retain all selected words')
        check_curated(report['rows'])
        print(f'Compared {len(unique)} unique words; {len(selection)} fixture selections. '
              f'Inspect {comparison} for differences.')
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f'ARM64 oracle workflow failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
