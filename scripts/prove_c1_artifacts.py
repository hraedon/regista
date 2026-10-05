"""Mutation-prove the C1 archive and workflow guards in disposable copies."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path

from prove_f1 import body, replace_once

ROOT = Path(__file__).parents[1]
MUTANTS = [
    ("c4_gzip_encoding", "scripts/check_published_migrations.py",
     replace_once("if encoded.getvalue() != blob:", "if False:"),
     "test_c4_sdist_canonical_bytes and gzip"),
    ("c4_tar_metadata", "scripts/check_published_migrations.py",
     replace_once("if (member.mtime != _SDIST_MTIME or member.mode not in (0o644, 0o755)\n"
                  "                    or member.type != tarfile.REGTYPE or member.linkname\n"
                  "                    or member.devmajor or member.devminor):", "if False:"),
     "test_c4_sdist_canonical_bytes and tar"),
    ("c4_guard_upload_order", ".github/workflows/publish.yml",
     replace_once("      - uses: actions/upload-artifact@",
                  "      - run: uvx --from twine==7.0.0 twine check dist/*\n"
                  "      - uses: actions/upload-artifact@"),
     "test_c4_guard_is_immediately_uploaded"),
    ("c4_twine_dependency", ".github/workflows/publish.yml",
     replace_once("needs: [build, twine]", "needs: [build]"),
     "test_c4_guard_is_immediately_uploaded"),
    ("c4_tool_hashes", ".github/workflows/publish.yml",
     replace_once("--require-hashes -r .github/twine-requirements.txt",
                  "-r .github/twine-requirements.txt"),
     "test_c4_release_tool_installations"),
    ("c4_frozen_verification", ".github/workflows/publish.yml",
     replace_once("uv sync --frozen --extra dev", "uv sync --extra dev"),
     "test_c4_verification_uses_frozen_project_lock"),
    ("c4_summary_hashes", ".github/workflows/publish.yml",
     replace_once("sha256sum dist/*.whl dist/*.tar.gz", "echo unchecked"),
     "test_c4_approval_summary_contains_exact_hashes"),
    ("gzip_tar_envelope", "scripts/check_published_migrations.py",
     body("_sdist_tar", "import gzip\nreturn gzip.decompress(blob)"),
     "test_c1_sdist_envelope_refuses_trailers"),
    ("sdist_metadata_binding", "scripts/check_published_migrations.py",
     replace_once("if pkg_info != archive.read(metadata_name):", "if False:"),
     "test_c1_sdist_metadata_is_bound"),
    ("sdist_root_binding", "scripts/check_published_migrations.py",
     replace_once('if root != expected_root or (where.endswith(".tar.gz") and\n'
                  '                                    Path(where).name != '
                  'expected_root + ".tar.gz"):',
                  'if False:'), "test_c1_sdist_root_is_bound"),
    ("ci_permissions", ".github/workflows/ci.yml",
     replace_once("permissions:\n  contents: read", "permissions: {}"),
     "test_actions_and_uv_are_pinned and ci"),
    ("publish_uv_latest", ".github/workflows/publish.yml",
     replace_once('version: "0.12.23"', 'version: "latest"'),
     "test_actions_and_uv_are_pinned and publish"),
    ("publish_uv_checksum", ".github/workflows/publish.yml",
     replace_once('checksum: "9167d72b3319674b6303c4cbe071854bba13ebdf3d76b1a7cbdc175471fb66d6"',
                  'checksum: "incorrect"'), "test_actions_and_uv_are_pinned and publish"),
    ("ci_mutable_action", ".github/workflows/ci.yml",
     replace_once("actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
                  "actions/checkout@v4"),
     "test_actions_and_uv_are_pinned and ci"),
    ("publish_identifier_gate", ".github/workflows/publish.yml",
     replace_once("python scripts/check_committed_identifiers.py", "true"),
     "test_publish_requires_identifier_and_merged_commit"),
    ("publish_main_ancestry", ".github/workflows/publish.yml",
     replace_once("git merge-base --is-ancestor HEAD origin/main", "true"),
     "test_publish_requires_identifier_and_merged_commit"),
]


def run(scratch: Path, selection: str) -> tuple[int, list[str], int, str]:
    report = scratch / "result.xml"
    env = {**os.environ, "REGISTA_GUARD_TEST_ROOT": str(scratch),
           "REGISTA_WORKFLOW_TEST_ROOT": str(scratch)}
    result = subprocess.run(
        [sys.executable, "-m", "pytest", str(ROOT / "tests/test_distribution_vectors.py"),
         str(ROOT / "tests/test_c1_workflows.py"), "-q", "-k", selection,
         f"--junitxml={report}"], env=env, capture_output=True, text=True, timeout=120,
    )
    cases = list(ET.parse(report).getroot().iter("testcase"))
    failed = [c.attrib["classname"] + "::" + c.attrib["name"] for c in cases
              if c.find("failure") is not None]
    errors = sum(c.find("error") is not None for c in cases)
    return result.returncode, failed, errors, result.stdout + result.stderr


def main() -> None:
    evidence: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="regista-c1-artifacts-") as directory:
        scratch = Path(directory)
        files = {file for _,file,_,_ in MUTANTS}
        files.update(("scripts/schema-baseline.json", ".github/twine-requirements.txt",
                      ".github/build-requirements.txt", "pyproject.toml"))
        for file in files:
            target = scratch / file
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / file, target)
        code, failed, errors, output = run(
            scratch, "c1 or c4 or actions_and_uv or publish_requires"
        )
        if code or failed or errors:
            raise SystemExit("unmodified control failed:\n" + output)
        print("CONTROL passed: " + output.strip().splitlines()[-1], flush=True)
        for name, file, mutate, selection in MUTANTS:
            target = scratch / file
            original = (ROOT / file).read_text()
            target.write_text(mutate(original))
            try:
                code, failed, errors, output = run(scratch, selection)
            finally:
                target.write_text(original)
            if code != 1 or not failed or errors:
                raise SystemExit(f"{name}: not proved by test-body failures:\n{output}")
            evidence.append({"mutant": name, "failures": failed, "exit_code": code})
            print(f"KILLED {name}: {len(failed)} test-body failures", flush=True)
    (ROOT / "plans/032-c4-artifact-mutations.json").write_text(
        json.dumps(evidence, indent=2) + "\n")
    print(f"{len(MUTANTS)} artifact/workflow mutants killed")


if __name__ == "__main__":
    main()
