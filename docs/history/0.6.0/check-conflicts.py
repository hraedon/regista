#!/usr/bin/env python3
"""Contested-value checker for the regista 0.6.0 specification set.

Gate 0's second acceptance criterion is that **no two documents give conflicting rules for the
same field**. `check-crossrefs.py` proves the links resolve; this proves the *values* agree.

It works on an inventory of tokens the overlay retired, renamed or reassigned. A retired token
may still appear — a document that silently deletes its old rule teaches nobody why — but only
inside a local marker: a blockquote (`>` line, which is how every SUPERSEDED / AMENDED / CUT /
WITHDRAWN / OBSOLETE note is written), a strikethrough (`~~…~~`), or a comment inside a JSON
example that points at the marker. A declaration may also be covered by the immediately preceding
multi-line marker or by an explicit cut/supersession marker at the start of its section. A banner
hundreds of lines away is not coverage. Anywhere else, the retired token is a live rule in a frozen
document, which is exactly the collision class this set spent a reconciliation pass removing.

`RECONCILIATION.md` is exempt because it is the overlay itself. Evidence documents are exempt for
the same reason. `ARCHITECTURE-0.6.0.md` is deliberately checked: its rank-5 banner is not a
substitute for local markers before a historical declaration.

Exit status is 0 only when nothing is reported.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

EXEMPT = {
    "RECONCILIATION.md",       # the overlay: it must quote what it retires
    "AUDIT-REPORT.md",         # evidence
    "SOL-DESIGN-REVIEW.md",    # evidence
    "IMPLEMENTATION-PLAN.md",  # work assignment, not a field contract
    "OVERLAY-APPLICATION.md",  # the coverage matrix: it names every retired token by design
}

# token -> why it is retired / what replaced it
CONTESTED: dict[str, str] = {
    "declared-selection": "scope kind cut from 0.6.0 (Resolution 4)",
    "accept_hmac_prefix": "renamed accept_legacy_shared_secret_events (Resolution 4)",
    "single_signer_lab": "retired governance spelling (Resolution 4)",
    "`co-signed`": "wire value is co_signed (Resolution 4)",
    '"co-signed"': "wire value is co_signed (Resolution 4)",
    "`solo-effective`": "wire value is solo_effective (Resolution 4)",
    '"solo-effective"': "wire value is solo_effective (Resolution 4)",
    "regista.review-verdict.v1": "withdrawn hash domain (collision 15)",
    "regista.key.fingerprint.v1": "withdrawn fingerprint domain (collision 8)",
    "regista.delegation.v1": "replaced by regista.action-delegation.v1 (Resolution 2)",
    "regista.delegation/v1": "replaced by regista.action-delegation/v1 (Resolution 2)",
    "regista.workflow.definition.v1": "renamed regista.workflow-definition.v1 (Resolution 2)",
    "result.accepted": "does not exist; use acceptable_under() (collision 23)",
    "project_system": "prose only, never a wire value (Resolution 4)",
    "s1-design/": "flat spec set (collision 23)",
    "v6-design/": "flat spec set (collision 23)",
}

# Phrases that assert a superseded *rule* rather than a superseded token.
CONTESTED_RE: dict[str, str] = {
    r"\b15 keys\b": "the v6 top level has 16 keys (collision 4)",
    r"len\(keys\(top\)\) == 15": "the v6 top level has 16 keys (collision 4)",
    r"`?transition`? MUST also be `?null`?": "transition is always required (Resolution 3)",
    r"threshold` and `signer_count` \*\*must not change": (
        "WI-280: threshold may rise, signers may be replaced"
    ),
}

MARKER_WORDS = re.compile(
    r"\b(?:SUPERSEDED|AMENDED|WITHDRAWN|OBSOLETE|RESOLVED|CONFIRMED|retired)\b"
    r"|CUT FROM|CUT —"
    r"|does not exist|\*\*Cut:\*\*|is cut|cut from 0\.6\.0|no longer|never a wire value"
    r"|is a retired spelling|not implemented|future design|rejected alternative|historical snapshot"
    r"|illustrative|does not ship|not a 0\.6\.0",
    re.IGNORECASE,
)

PRECEDING_MARKER_LINES = 8

STRUCTURAL_GUARDS: tuple[tuple[str, str, str], ...] = (
    (
        "ARCHITECTURE-0.6.0.md",
        r'"kind":\s*"complete-store\s*\|\s*contiguous-range\s*\|\s*declared-selection"',
        "the bundle scope union is owned by BUNDLE-V3 and excludes declared-selection",
    ),
    (
        "ARCHITECTURE-0.6.0.md",
        r"\bsubject_profile\b",
        "the review subject is owned by REVIEW-VERDICTS and has no subject_profile",
    ),
    (
        "RESULT-MODEL.md",
        r"version ∈ policy's full set \(v5 today\)",
        "v6 is the post-cutover full-authentication version",
    ),
    (
        "REVIEW-VERDICTS.md",
        r"\bsubject_profile\b",
        "subject_profile is cut and every occurrence needs a local cut marker",
    ),
    (
        "TRUST-DOMAIN.md",
        r"\|\s*Witness registration\s*\|\s*\*\*Yes",
        "witness registration is cut from 0.6.0",
    ),
    (
        "CUTOVER-CLASSIFICATION.md",
        r"^Under the S1 policy",
        "the S1 state is historical; post-cutover classification is chain-position based",
    ),
    (
        "CUTOVER-CLASSIFICATION.md",
        r"\|\s*Events, estate-wide\s*\|\s*\*\*352,509",
        "architecture-era counts require a historical snapshot marker",
    ),
    (
        "V6-ENVELOPE.md",
        r"Exactly the 15-key top-level object",
        "the v6 canonicalization input has 16 top-level members",
    ),
    (
        "V6-ENVELOPE.md",
        r"^\| 13 \| `transition` \| string \\?\| null",
        "v6 transition is a required non-empty string on every event",
    ),
    (
        "V6-ENVELOPE.md",
        r"^\| `metadata` \| object \\?\| null \| yes \| Lineage and harness claims",
        "v6 producer identity belongs only in the producer block",
    ),
    (
        "TRUST-DOMAIN.md",
        (
            r"(?:governance.*(?:determinant|deriv\w*)[^\n]*trust_domain_id"
            r"|trust_domain_id[^\n]*derived from governance)"
        ),
        "WI-280 keeps governance out of trust_domain_id derivation",
    ),
    (
        "TRUST-DOMAIN.md",
        r"recovery.{0,48}requires (?:the )?registrar",
        "Resolution 5 requires the current root threshold for recovery",
    ),
    (
        "OPERATOR-FORGERY.md",
        r"recovery.{0,48}(?:at|requires) registrar",
        "Resolution 5 requires the current root threshold for recovery",
    ),
    (
        "CUTOVER-CLASSIFICATION.md",
        r"^\| `trust_log_checkpoint_hash` \|",
        "the checkpoint carries the three-field trust_log_checkpoint object",
    ),
    (
        "IMPLEMENTATION-PLAN.md",
        r"P3\.2[^\n]*(?:deferred|not in this window)",
        "P0.2 passed and P3.2 is no longer described as blocked by that gate",
    ),
    (
        "FIELD-MATRIX.md",
        r"(?:current|shipped) classifier is permissive",
        "S1 shipped the strict classifier",
    ),
    (
        "RESULT-MODEL.md",
        r"(?:current|shipped) classifier is permissive",
        "S1 shipped the strict classifier",
    ),
)

SECTION_COVERAGE: tuple[tuple[str, str, str, str], ...] = (
    (
        "V6-ENVELOPE.md",
        "### 5.1 ",
        r"Exactly the 16-key top-level object",
        "§5.1 must name the 16-member canonicalization input",
    ),
    (
        "V6-ENVELOPE.md",
        "### 5.2 ",
        r"payload,\s+producer,\s+project_instance_id",
        "§5.2 canonical key order must include producer",
    ),
)

DECISION_COVERAGE: dict[str, tuple[tuple[str, str], ...]] = {
    "ARCHITECTURE-0.6.0.md": (
        ("v6 envelope", r"16-key v6|producer block"),
        ("monotone governance", r"monotone signed log"),
        ("fresh-clone limit", r"fresh clone.*(?:cannot|not)"),
        ("recovery authority", r"current root threshold"),
        ("Resolution 6 limits", r"producer.*block.*assertion"),
    ),
    "ARCHITECTURE-FINAL.md": (
        ("monotone governance", r"monotone signed log"),
        ("prior-observation publication limit", r"prior observation"),
        ("producer assertion", r"producer.*assertion"),
    ),
    "BUNDLE-V3.md": (
        ("cut scope", r"declared-selection.*cut|cut.*declared-selection"),
        ("root signatures", r"root_signatures"),
        ("external trust policy", r"externally supplied trust material|auditor.s pin"),
    ),
    "CUTOVER-CLASSIFICATION.md": (
        ("chain-position boundary", r"chain position"),
        ("named snapshot", r"named snapshot"),
        ("post-cutover epoch violation", r"EPOCH_VIOLATION"),
    ),
    "CUTOVER-POLICY.md": (
        ("chain-position boundary", r"chain position"),
        ("unsigned watermark limitation", r"administrative.*index hint"),
    ),
    "FIELD-MATRIX.md": (
        ("v6 scheme binding", r"signed in v6"),
        ("legacy field counts", r"v1(?:\u2013|-)v5"),
    ),
    "IMPLEMENTATION-PLAN.md": (
        ("review gate", r"P3\.2.*satisfied"),
        ("key hard gate", r"HARD PREREQUISITE"),
        ("witness cut", r"cut from 0\.6\.0"),
    ),
    "OPERATOR-FORGERY.md": (
        ("recovery authority", r"current root threshold"),
        ("prior-observation publication limit", r"prior observation"),
        ("producer limitation", r"producer block.*assertion"),
    ),
    "RESULT-MODEL.md": (
        ("v6 result owner", r"VerificationResultV6"),
        ("chain-position bound", r"signed chain position"),
        ("legacy status", r"LEGACY_PARTIAL"),
    ),
    "REVIEW-VERDICTS.md": (
        ("reducer-v1 subject", r"reduce_v1"),
        ("subject profile cut", r"subject_profile.*(?:absent|cut)"),
        (
            "registration versus action authority",
            r"principal_registration[\s\S]{0,300}action_delegation",
        ),
    ),
    "TRUST-DOMAIN.md": (
        ("stable domain identity", r"stable genesis identity"),
        ("monotone governance", r"monotone signed log"),
        ("fresh-clone limit", r"fresh clone.*(?:cannot|not)"),
        ("recovery authority", r"current root threshold"),
        ("witness cut", r"CUT FROM 0\.6\.0"),
    ),
    "V6-ENVELOPE.md": (
        ("16-key envelope", r"16-key"),
        ("producer block", r"producer"),
        ("bootstrap exceptions", r"Bootstrap [AB]|bootstrap"),
    ),
}


def is_section_heading(line: str) -> bool:
    return line.startswith("## ")


def has_preceding_marker(lines: list[str], idx: int) -> bool:
    cursor = idx - 1
    skipped_blank = 0
    seen_marker = False
    for _ in range(PRECEDING_MARKER_LINES):
        if cursor < 0:
            break
        line = lines[cursor]
        if not line.strip():
            skipped_blank += 1
            if seen_marker:
                cursor -= 1
                continue
            if skipped_blank > 2:
                break
            cursor -= 1
            continue
        if line.lstrip().startswith(">") or "~~" in line:
            seen_marker = seen_marker or bool(MARKER_WORDS.search(line))
            cursor -= 1
            continue
        break
    return seen_marker


def blockquote_has_marker(lines: list[str], idx: int) -> bool:
    if not lines[idx].lstrip().startswith(">"):
        return False
    start = idx
    while start > 0 and (
        lines[start - 1].lstrip().startswith(">") or not lines[start - 1].strip()
    ):
        start -= 1
    end = idx + 1
    while end < len(lines) and (
        lines[end].lstrip().startswith(">") or not lines[end].strip()
    ):
        end += 1
    return any(MARKER_WORDS.search(line) for line in lines[start:end])


def has_section_marker(lines: list[str], idx: int) -> bool:
    heading = idx
    while heading >= 0 and not is_section_heading(lines[heading]):
        heading -= 1
    if heading < 0:
        return False
    for line in lines[heading + 1 : min(idx, heading + 13)]:
        if is_section_heading(line):
            return False
        if line.lstrip().startswith(">") and MARKER_WORDS.search(line):
            return True
    return False


def is_marked(lines: list[str], idx: int) -> bool:
    """True when the line sits inside a marker: a blockquote, a strikethrough, a marker table
    row, or a JSON-example line that points at one."""
    line = lines[idx]
    stripped = line.lstrip()
    if stripped.startswith(">"):
        return blockquote_has_marker(lines, idx)
    if "~~" in line:
        return True
    if MARKER_WORDS.search(line):
        return True
    if has_preceding_marker(lines, idx) or has_section_marker(lines, idx):
        return True
    # a table row inside an OVERLAY APPLIED banner
    if stripped.startswith("|") and MARKER_WORDS.search("\n".join(lines[max(0, idx - 40): idx])):
        marker_seen = False
        for back in range(idx - 1, -1, -1):
            if is_section_heading(lines[back]):
                return lines[back].strip().startswith("## OVERLAY APPLIED") and marker_seen
            marker_seen = marker_seen or bool(MARKER_WORDS.search(lines[back]))
    # JSON example line carrying a pointer comment
    if "//" in line and re.search(r"//.*(CUT|see §|Resolution|collision|—)", line):
        return True
    return False


def section_text(path: Path, heading_prefix: str) -> str | None:
    lines = path.read_text(encoding="utf-8").splitlines()
    for start, line in enumerate(lines):
        if not line.startswith(heading_prefix):
            continue
        level = len(line) - len(line.lstrip("#"))
        end = len(lines)
        for cursor in range(start + 1, len(lines)):
            candidate = lines[cursor]
            if not candidate.startswith("#"):
                continue
            candidate_level = len(candidate) - len(candidate.lstrip("#"))
            if candidate_level <= level:
                end = cursor
                break
        return "\n".join(lines[start:end])
    return None


def check(root: Path) -> list[str]:
    problems: list[str] = []

    for path in sorted(root.glob("*.md")):
        if path.name in EXEMPT:
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        for n, line in enumerate(lines):
            for token, why in CONTESTED.items():
                if token in line and not is_marked(lines, n):
                    problems.append(f"{path.name}:{n + 1}: live use of {token!r} — {why}")
            for pattern, why in CONTESTED_RE.items():
                if re.search(pattern, line) and not is_marked(lines, n):
                    problems.append(f"{path.name}:{n + 1}: live rule {pattern!r} — {why}")

    for filename, pattern, why in STRUCTURAL_GUARDS:
        path = root / filename
        if not path.exists():
            problems.append(f"missing owning document {filename} for structural guard")
            continue
        lines = path.read_text(encoding="utf-8").splitlines()
        compiled = re.compile(pattern, re.IGNORECASE)
        for n, line in enumerate(lines):
            if compiled.search(line) and not is_marked(lines, n):
                problems.append(
                    f"{filename}:{n + 1}: unmarked stale declaration — {why}"
                )

    for filename, decisions in DECISION_COVERAGE.items():
        path = root / filename
        if not path.exists():
            problems.append(f"missing owning document {filename} for decision coverage")
            continue
        text = path.read_text(encoding="utf-8")
        for label, pattern in decisions:
            if not re.search(pattern, text, re.IGNORECASE):
                problems.append(f"{filename}: missing decision coverage for {label}")

    for filename, heading, pattern, why in SECTION_COVERAGE:
        path = root / filename
        if not path.exists():
            problems.append(f"missing owning document {filename} for section coverage")
            continue
        text = section_text(path, heading)
        if text is None:
            problems.append(f"{filename}: missing owning section {heading.strip()}")
        elif not re.search(pattern, text, re.IGNORECASE):
            problems.append(f"{filename} {heading.strip()}: {why}")

    return problems


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).parent)
    args = parser.parse_args()
    problems = check(args.root)

    for p in problems:
        print(p)
    print(f"\n{len(problems)} contested value(s) or structural decision-coverage violation(s).")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
