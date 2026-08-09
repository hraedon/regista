#!/usr/bin/env python3
"""Cross-reference checker for the regista 0.6.0 specification set.

Gate 0 requires that "every internal cross-reference resolves". This script is
the check. It is deliberately mechanical: it makes no judgement about whether a
citation is *apt*, only about whether the thing it names exists.

Four classes of reference are checked:

1. ``FILE.md:N`` / ``FILE.md:N-M``  — sibling spec, line citation.
   The file must exist and the line range must be inside it. Line citations
   into documents this overlay edited are re-derived by ``rederive-citations.py``
   against the pre-overlay snapshot; anything still out of range is an error.
2. ``FILE.md`` (bare) and ``FILE.md §X`` — the file must exist, and where a
   section is named, a heading numbered ``X`` must exist in it.
3. ``src/regista/....py:N`` — code citation. Checked against the pinned
   post-S1 tree (``--code-ref``, default ``334b995``) when a git checkout is
   supplied with ``--repo``; the file must exist there and hold the line.
4. Filesystem paths (``s1-design/``, ``v6-design/``, absolute ``/home/...``)
   — these must not appear: this spec set is flat and self-contained.

Exit status is 0 only when nothing is reported.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

SPEC_SUFFIX = ".md"

# FILE.md:12  |  FILE.md:12-34
RE_LINE_CITE = re.compile(r"\b([A-Za-z0-9._-]+\.md):(\d+)(?:-(\d+))?")
# `src/regista/_x.py:12` or `migrations/001_initial.sql:9-10`
RE_CODE_CITE = re.compile(r"\b((?:src|tests|migrations|docs)/[A-Za-z0-9._/-]+):(\d+)(?:-(\d+))?")
# bare sibling mention
RE_FILE = re.compile(r"\b([A-Z0-9][A-Za-z0-9._-]*\.md)\b")
# "FILE.md §3.2" or "FILE.md `§3.2`"
RE_FILE_SECTION = re.compile(r"\b([A-Za-z0-9._-]+\.md)`?\s+`?§\s?(\d+(?:\.\d+)*)")
# forbidden path shapes
RE_FORBIDDEN = re.compile(r"(?:^|[\s(`])((?:/home/[A-Za-z0-9._/-]+)|(?:s1-design/[A-Za-z0-9._/-]*)|(?:v6-design/[A-Za-z0-9._/-]*))")
RE_HEADING = re.compile(r"^#{1,6}\s+(?:§\s*)?(\d+(?:\.\d+)*)[.)]?\s")

# Documents that are evidence, not specifications: they are allowed to carry
# citations into scratch paths because they record where evidence was produced.
EVIDENCE_DOCS = {"AUDIT-REPORT.md", "SOL-DESIGN-REVIEW.md"}

# Markdown files that live in the regista repository, not in this spec set.
# They are checked against the pinned code ref like any other code citation.
REPO_DOCS = {"spec.md", "README.md", "CHANGELOG.md", "AGENTS.md"}


def load_specs(root: Path) -> dict[str, list[str]]:
    return {
        p.name: p.read_text(encoding="utf-8").splitlines()
        for p in sorted(root.glob("*" + SPEC_SUFFIX))
    }


def headings(lines: list[str]) -> set[str]:
    found: set[str] = set()
    for line in lines:
        m = RE_HEADING.match(line)
        if m:
            found.add(m.group(1))
    return found


def in_code_block(lines: list[str], idx: int) -> bool:
    fence = 0
    for line in lines[:idx]:
        if line.lstrip().startswith("```"):
            fence += 1
    return fence % 2 == 1


def git_file_lines(repo: Path, ref: str, path: str) -> int | None:
    try:
        out = subprocess.run(
            ["git", "-C", str(repo), "show", f"{ref}:{path}"],
            capture_output=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return out.stdout.count(b"\n") + 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(Path(__file__).parent))
    ap.add_argument(
        "--repo",
        default=str(Path(__file__).resolve().parents[2]),
        help="regista checkout for code citations (default: this repository)",
    )
    ap.add_argument(
        "--code-ref",
        default="334b995",
        help="the pinned post-S1 tree every code citation is against",
    )
    args = ap.parse_args()

    root = Path(args.root)
    specs = load_specs(root)
    heads = {name: headings(lines) for name, lines in specs.items()}
    problems: list[str] = []
    code_cache: dict[str, int | None] = {}

    for name, lines in specs.items():
        for n, line in enumerate(lines, start=1):
            if in_code_block(lines, n - 1):
                continue

            for m in RE_LINE_CITE.finditer(line):
                target, start, end = m.group(1), int(m.group(2)), m.group(3)
                last = int(end) if end else start
                if target in REPO_DOCS:
                    if args.repo:
                        if target not in code_cache:
                            code_cache[target] = git_file_lines(
                                Path(args.repo), args.code_ref, target
                            )
                        total = code_cache[target]
                        if total is None:
                            problems.append(
                                f"{name}:{n}: repo document {target} absent at {args.code_ref}"
                            )
                        elif last > total:
                            problems.append(
                                f"{name}:{n}: {target}:{m.group(2)} past end of file "
                                f"({total} lines at {args.code_ref})"
                            )
                elif target not in specs:
                    problems.append(f"{name}:{n}: cites unknown file {target}")
                elif last > len(specs[target]):
                    problems.append(
                        f"{name}:{n}: {target}:{m.group(2)}"
                        f"{'-' + end if end else ''} is past end of file "
                        f"({len(specs[target])} lines)"
                    )

            for m in RE_FILE_SECTION.finditer(line):
                target, section = m.group(1), m.group(2)
                if target in REPO_DOCS:
                    continue
                if target not in specs:
                    problems.append(f"{name}:{n}: cites unknown file {target}")
                elif section not in heads[target]:
                    problems.append(f"{name}:{n}: {target} has no section §{section}")

            for m in RE_FILE.finditer(line):
                target = m.group(1)
                if target not in specs and target not in REPO_DOCS:
                    problems.append(f"{name}:{n}: names missing document {target}")

            if name not in EVIDENCE_DOCS:
                for m in RE_FORBIDDEN.finditer(line):
                    problems.append(f"{name}:{n}: non-flat path reference {m.group(1)!r}")

            if args.repo:
                for m in RE_CODE_CITE.finditer(line):
                    path, start, end = m.group(1), int(m.group(2)), m.group(3)
                    last = int(end) if end else start
                    if path not in code_cache:
                        code_cache[path] = git_file_lines(Path(args.repo), args.code_ref, path)
                    total = code_cache[path]
                    if total is None:
                        problems.append(
                            f"{name}:{n}: code citation {path} absent at {args.code_ref}"
                        )
                    elif last > total:
                        problems.append(
                            f"{name}:{n}: {path}:{m.group(2)}"
                            f"{'-' + end if end else ''} past end of file "
                            f"({total} lines at {args.code_ref})"
                        )

    for p in problems:
        print(p)
    print(f"\n{len(problems)} unresolved reference(s) across {len(specs)} documents.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
