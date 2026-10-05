"""Run the reviewer's schema-and-pin edit in a disposable clone of a revision."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revision', default='HEAD')
    parser.add_argument('--expect', choices=('pass', 'refuse'), default='refuse')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='regista-b2-bypass-') as directory:
        clone = Path(directory) / 'checkout'
        subprocess.run(['git', 'clone', '-q', str(REPO), str(clone)], check=True)
        subprocess.run(['git', '-C', str(clone), 'checkout', '-q', args.revision], check=True)
        schema = clone / 'src/regista/schema.sql'
        schema.write_bytes(schema.read_bytes() + b'\nALTER TABLE events DROP COLUMN occurred_at;\n')
        path = clone / 'scripts/schema-baseline.json'
        ledger = json.loads(path.read_text())
        digest = hashlib.sha256(schema.read_bytes()).hexdigest()
        ledger['baseline']['schema.sql'] = digest
        if 'schema_versions' in ledger:
            ledger['schema_versions']['1'] = digest
        path.write_text(json.dumps(ledger))
        for command in (['verify-baseline'], ['check-release', '--version', '0.8.0']):
            result = subprocess.run(
                [sys.executable, str(clone / 'scripts/check_published_migrations.py'), *command],
                cwd=clone, capture_output=True, text=True, timeout=120,
            )
            print(f'{args.revision} {command[0]}: exit {result.returncode}', flush=True)
            print((result.stdout + result.stderr).strip(), flush=True)
            expected = 0 if args.expect == 'pass' else 1
            if result.returncode != expected:
                raise SystemExit(f'expected exit {expected}, got {result.returncode}')


if __name__ == '__main__':
    main()
