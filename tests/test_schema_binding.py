"""Schema version/content pairs survive pin edits and are bound to PyPI bytes."""
from __future__ import annotations

import copy
import json
import subprocess
from pathlib import Path
from typing import Any

import pytest
from test_distribution_guard import GUARD, ROOT, fixture_tree


def commit_pin(tree: Path, ledger: dict[str, Any]) -> None:
    (tree / 'scripts').mkdir(exist_ok=True)
    (tree / 'scripts/schema-baseline.json').write_text(json.dumps(ledger))
    subprocess.run(['git', 'init', '-q', str(tree)], check=True)
    subprocess.run(['git', '-C', str(tree), 'add', '.'], check=True)
    subprocess.run(['git', '-C', str(tree), '-c', 'user.name=fixture', '-c',
                    'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
                    'commit', '-qm', 'baseline fixture'], check=True)


def test_reviewer_bypass_repinning_same_version_fails(tmp_path: Path) -> None:
    ledger, tree = fixture_tree(tmp_path)
    commit_pin(tree, ledger)
    schema = tree / 'src/regista/schema.sql'
    schema.write_bytes(schema.read_bytes() + b'\nALTER TABLE events DROP COLUMN occurred_at;\n')
    ledger['baseline']['schema.sql'] = GUARD._sha(schema.read_bytes())
    ledger.setdefault('schema_versions', {})['1'] = ledger['baseline']['schema.sql']
    assert GUARD.verify_baseline(ledger, tree)
    assert GUARD.check_release(ledger, '0.8.0', tree, fresh={})
    # A committed rewrite must still fail, not just a dirty working-tree edit.
    commit_pin(tree, ledger)
    assert GUARD.verify_baseline(ledger, tree)


def test_new_schema_requires_version_bump_and_entry(tmp_path: Path) -> None:
    ledger, tree = fixture_tree(tmp_path)
    commit_pin(tree, ledger)
    schema = tree / 'src/regista/schema.sql'
    schema.write_bytes(schema.read_bytes() + b'\n-- next schema\n')
    digest = GUARD._sha(schema.read_bytes())
    ledger['baseline']['schema.sql'] = digest
    ledger['schema_versions']['2'] = digest
    assert GUARD.verify_baseline(ledger, tree)  # code still speaks 1
    code = tree / 'src/regista/kernel.py'
    code.write_text(code.read_text().replace('KERNEL_SCHEMA_VERSION = 1',
                                            'KERNEL_SCHEMA_VERSION = 2'))
    ledger['baseline_version'] = 2
    assert GUARD.verify_baseline(ledger, tree) == []
    assert GUARD.check_release(ledger, '0.8.1', tree, fresh={}) == []
    del ledger['schema_versions']['2']
    assert GUARD.verify_baseline(ledger, tree)


def test_new_hash_cannot_reuse_an_old_version_or_drop_it(tmp_path: Path) -> None:
    ledger, tree = fixture_tree(tmp_path)
    commit_pin(tree, ledger)
    ledger['schema_versions']['1'] = '0' * 64
    assert GUARD.check_pin_history(ledger, tree)
    del ledger['schema_versions']['1']
    assert GUARD.check_pin_history(ledger, tree)


def test_prepublication_message_is_explicit(monkeypatch: pytest.MonkeyPatch,
                                           capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr(GUARD, 'build_releases', lambda: {})
    assert GUARD.main(['verify-ledger']) == 0
    assert 'no published 0.8.x release yet; PyPI binding not applicable' in capsys.readouterr().out


def test_published_pair_is_immutable_and_unknown_version_refused() -> None:
    ledger = GUARD.load_ledger()
    fresh = {'0.8.0': {'kernel_schema_version': 1,
                       'schema_sha256': ledger['schema_versions']['1']}}
    assert GUARD.verify_ledger(ledger, fresh) == []
    rewritten = copy.deepcopy(ledger)
    rewritten['schema_versions']['1'] = '0' * 64
    assert GUARD.verify_ledger(rewritten, fresh)
    fresh['0.8.0']['kernel_schema_version'] = 2
    assert GUARD.verify_ledger(ledger, fresh)


def test_check_release_refuses_a_republish_and_a_downgrade() -> None:
    ledger = GUARD.load_ledger()
    fresh = {'0.8.1': {'kernel_schema_version': 1,
                       'schema_sha256': ledger['schema_versions']['1']}}
    assert GUARD.check_release(ledger, '0.8.1', ROOT, fresh=fresh)
    assert GUARD.check_release(ledger, '0.8.0', ROOT, fresh=fresh)


@pytest.mark.parametrize('shape', ['valid', 'download-mismatch', 'wheel-disagreement',
                                   'missing-wheel', 'missing-version', 'yanked'])
def test_pypi_binding_inspects_downloaded_wheel_bytes(
    monkeypatch: pytest.MonkeyPatch, shape: str,
) -> None:
    import test_distribution_vectors as vectors

    vectors._wheel_members_are_0644.__wrapped__(monkeypatch)
    blob = vectors._wheel_with('regista/kernel.py', b'KERNEL_SCHEMA_VERSION = 1\n')
    second = vectors._wheel_with('regista/kernel.py', b'KERNEL_SCHEMA_VERSION = 2\n')
    if shape == 'missing-version':
        blob = vectors._good_wheel()
    file = {'filename': 'r-0.0.0-py3-none-any.whl', 'url': 'https://fixture.invalid/wheel',
            'packagetype': 'bdist_wheel', 'digests': {'sha256': GUARD._sha(blob)},
            'yanked': shape == 'yanked'}
    files = [file]
    if shape == 'download-mismatch':
        file['digests'] = {'sha256': '0' * 64}
    if shape == 'wheel-disagreement':
        files.append({**file, 'url': 'https://fixture.invalid/second',
                      'digests': {'sha256': GUARD._sha(second)}})
    if shape == 'missing-wheel':
        files = [{**file, 'packagetype': 'sdist'}]
    index = {'releases': {'0.7.2': [file], '0.8.0': files, '0.9.0': []}}
    responses = {GUARD.PYPI_JSON: json.dumps(index).encode(), file['url']: blob,
                 'https://fixture.invalid/second': second}
    monkeypatch.setattr(GUARD, '_fetch', lambda url: responses[url])
    if shape in ('valid', 'yanked'):
        assert GUARD.build_releases() == {'0.8.0': {
            'kernel_schema_version': 1, 'schema_sha256': GUARD._sha(vectors.A)}}
    else:
        with pytest.raises((GUARD.GuardError, KeyError)):
            GUARD.build_releases()


def test_bumped_pin_requires_matching_code_version(tmp_path: Path) -> None:
    ledger, tree = fixture_tree(tmp_path)
    commit_pin(tree, ledger)
    ledger['schema_versions']['2'] = ledger['schema_versions']['1']
    ledger['baseline_version'] = 2
    assert GUARD.verify_baseline(ledger, tree)
    assert GUARD.check_release(ledger, '0.8.1', tree, fresh={})


def test_shallow_history_is_not_immutability_evidence(tmp_path: Path) -> None:
    ledger, tree = fixture_tree(tmp_path / 'full')
    commit_pin(tree, ledger)
    clone = tmp_path / 'shallow'
    subprocess.run(['git', 'clone', '-q', '--depth', '1', tree.as_uri(), str(clone)], check=True)
    with pytest.raises(GUARD.GuardError, match='full-depth'):
        GUARD.verify_baseline(ledger, clone)
