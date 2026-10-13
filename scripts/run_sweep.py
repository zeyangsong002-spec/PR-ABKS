#!/usr/bin/env python3
"""Explicit one-parameter sweeps; no historical figure settings are inferred."""
# SPDX-License-Identifier: MIT
import argparse
import hashlib
import json
from pathlib import Path
import platform
import subprocess
from datetime import datetime, timezone


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', default='build/prabks')
    parser.add_argument('--params', default='params/a.param')
    parser.add_argument('--output-dir', required=True, help='Must not exist')
    keys = ('users', 'attrs', 'policy', 'eta', 'tags', 'punctures', 'keywords', 'runs', 'warmup')
    defaults = (10, 10, 4, 3, 1, 1, 10, 10, 1)
    for key, value in zip(keys, defaults):
        parser.add_argument('--' + key, type=int, default=value)
    parser.add_argument('--axis', choices=keys[:7], required=True)
    parser.add_argument('--values', nargs='+', type=int, required=True)
    parser.add_argument('--dry-run', action='store_true', help='Print commands; create no files')
    args = parser.parse_args()
    binary, params = Path(args.binary).resolve(), Path(args.params).resolve()
    if not binary.is_file() or not params.is_file():
        parser.error('Binary and parameter file must exist')
    if len(set(args.values)) != len(args.values):
        parser.error('Repeated sweep values are not allowed')
    output = Path(args.output_dir).resolve()
    if output.exists():
        parser.error('Output directory already exists')
    commands = []
    for value in args.values:
        config = {key: getattr(args, key) for key in keys}
        config[args.axis] = value
        if not (config['users'] >= 2 and config['attrs'] >= config['policy'] >= 1
                and 0 <= config['tags'] < config['eta'] and config['punctures'] >= 0
                and config['keywords'] >= 1 and config['runs'] >= 1 and config['warmup'] >= 0):
            parser.error('Invalid configuration: ' + str(config))
        command = [str(binary), '--benchmark', '--params', str(params), '--output',
                   str(output / f'{args.axis}_{value}.csv')]
        for key in keys:
            command.extend(['--' + key, str(config[key])])
        commands.append({'configuration': config, 'command': command, 'status': 'pending'})
    if args.dry_run:
        print(json.dumps(commands, indent=2))
        return
    output.mkdir(parents=True, exist_ok=False)
    manifest = {'purpose': 'New measurements; not historical manuscript figure reproduction',
                'started_utc': datetime.now(timezone.utc).isoformat(),
                'platform': platform.system() + ' ' + platform.release(),
                'machine': platform.machine(),
                'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'params_sha256': hashlib.sha256(params.read_bytes()).hexdigest(),
                'experiments': commands}
    def save():
        (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    save()
    for index, item in enumerate(commands):
        with (output / f'run_{index}.log').open('w', encoding='utf-8') as log:
            result = subprocess.run(item['command'], stdout=log, stderr=subprocess.STDOUT)
        item['status'] = 'passed' if result.returncode == 0 else 'failed'
        item['returncode'] = result.returncode
        save()
        if result.returncode:
            raise SystemExit(f'Run {index} failed; see its log. No later points executed.')
    print(f'Completed {len(commands)} configurations; manifest: {output / "manifest.json"}')


if __name__ == '__main__':
    main()
