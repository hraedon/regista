"""Assert Stage B2 regression tests kill defects in disposable checkout copies."""
from __future__ import annotations

import ast
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GUARD = 'scripts/check_published_migrations.py'
KERNEL = 'src/regista/kernel.py'


def replace_function(source: str, name: str, body: str) -> str:
    tree = ast.parse(source)
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
    lines = source.splitlines(keepends=True)
    start = node.body[0].lineno - 1
    indentation = ' ' * node.body[0].col_offset
    lines[start:node.end_lineno] = [indentation + body + '\n']
    return ''.join(lines)


MUTANTS = [
    ('repin_same_version', GUARD, 'function:check_pin_history', 'return []',
     'tests/test_schema_binding.py::test_reviewer_bypass_repinning_same_version_fails'),
    ('ignore_code_version', GUARD, 'if version != ledger["baseline_version"]:', 'if False:',
     'tests/test_schema_binding.py::test_bumped_pin_requires_matching_code_version'),
    ('ignore_published_pairs', GUARD, 'function:verify_ledger', 'return []',
     'tests/test_schema_binding.py::test_published_pair_is_immutable_and_unknown_version_refused'),
    ('omit_prepublication_message', GUARD,
     '            if not fresh:\n                print(PREPUBLICATION_MESSAGE)',
     '            if not fresh:\n                pass',
     'tests/test_schema_binding.py::test_prepublication_message_is_explicit'),
    ('ignore_namespace_occupancy', KERNEL, 'function:_refuse_legacy_schema', 'return set()',
     'tests/test_f1_baseline.py::test_non_table_schema_is_not_empty'),
    ('ignore_hidden_legacy', KERNEL, 'function:_refuse_legacy_schema', 'return set()',
     'tests/test_f1_baseline.py::test_legacy_schema_hidden_from_unprivileged_role'),
    ('ignore_late_legacy', KERNEL, 'if row and not row["destination_supported"]:', 'if False:',
     'tests/test_f1_baseline.py::test_legacy_objects_added_to_initialized_schema_refuse_before_write'),
    ('accept_removed_key', 'src/regista/workflow.schema.json', '"properties": {',
     '"properties": {"regista_version": {},',
     'tests/test_workflow_schema_pins.py::test_removed_keys_do_not_overlap_accepted_schema_keys'),
    ('ignore_workflow_lock', KERNEL, 'function:_transaction_lock', 'return',
     'tests/test_f1_core.py::test_concurrent_workflow_registration'),
    ('ignore_zip_collisions', GUARD, 'if key in seen:', 'if False:',
     'tests/test_distribution_vectors.py::test_a_duplicate_zip_member_fails'),
    ('ignore_record_hashes', GUARD, 'digest != f"sha256={expected}"', 'False',
     'tests/test_distribution_vectors.py::test_a_record_naming_other_bytes_fails'),
]


def run(root: Path, selection: str, report: Path) -> tuple[int, list[str], list[str]]:
    result = subprocess.run(
        [sys.executable, '-m', 'pytest', '-q', selection, f'--junitxml={report}'],
        cwd=root, env={**os.environ, 'REGISTA_KERNEL_TEST_ROOT': str(root / 'src')},
        capture_output=True, text=True, timeout=120,
    )
    cases = list(ET.parse(report).iter('testcase'))
    failed = [c.attrib['name'] for c in cases if c.find('failure') is not None]
    other = [c.attrib['name'] for c in cases if c.find('failure') is None]
    if result.returncode != 0 and not failed:
        print(result.stdout + result.stderr)
    return result.returncode, failed, other


def main() -> None:
    if not os.environ.get('REGISTA_TEST_DSN'):
        raise SystemExit('REGISTA_TEST_DSN must name disposable PostgreSQL')
    with tempfile.TemporaryDirectory(prefix='regista-b2-proof-') as directory:
        root = Path(directory) / 'checkout'
        subprocess.run(['git', 'clone', '-q', str(REPO), str(root)], check=True)
        # Use exactly the current source; clone supplies the immutable pin history.
        for path in ('src', 'scripts', 'tests'):
            shutil.copytree(REPO / path, root / path, dirs_exist_ok=True)
        for name, filename, before, after, selection in MUTANTS:
            path = root / filename
            original = path.read_text()
            code, _, _ = run(root, selection, Path(directory) / 'control.xml')
            if code:
                raise SystemExit(f'{name}: unmodified control failed')
            if before.startswith('function:'):
                changed = replace_function(original, before.removeprefix('function:'), after)
            else:
                if before not in original:
                    raise SystemExit(f'{name}: mutation anchor disappeared')
                changed = original.replace(before, after, 1)
            try:
                path.write_text(changed)
                code, failed, other = run(root, selection, Path(directory) / 'mutant.xml')
                if code != 1 or not failed or other:
                    raise SystemExit(f'{name}: need test-body assertion failures; '
                                     f'code={code}, failed={failed}, other={other}')
                print(f'KILLED {name}: {len(failed)} assertion failures', flush=True)
            finally:
                path.write_text(original)
    print(f'{len(MUTANTS)} mutants killed; no survivors')


if __name__ == '__main__':
    main()
