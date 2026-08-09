#!/usr/bin/env python3
"""Contested-value checker for the regista 0.6.0 specification set.

Gate 0's second acceptance criterion is that **no two documents give conflicting rules for the
same field**. `check-crossrefs.py` proves the links resolve; this proves the *values* agree.

It works on an inventory of tokens the overlay retired, renamed or reassigned. A retired token
may still appear — a document that silently deletes its old rule teaches nobody why — but only
inside a marker: a blockquote (`>` line, which is how every SUPERSEDED / AMENDED / CUT /
WITHDRAWN / OBSOLETE note is written), a strikethrough (`~~…~~`), or a comment inside a JSON
example that points at the marker. Anywhere else, the retired token is a live rule in a frozen
document, which is exactly the collision class this set spent a reconciliation pass removing.

Two documents are exempt because their whole job is to record the superseded state:
`RECONCILIATION.md` (the overlay itself) and `ARCHITECTURE-0.6.0.md` (rank 5, superseded in 14
places by a banner at its head). Evidence documents are exempt for the same reason.

Exit status is 0 only when nothing is reported.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

EXEMPT = {
    "RECONCILIATION.md",       # the overlay: it must quote what it retires
    "ARCHITECTURE-0.6.0.md",   # rank 5, superseded wholesale by its banner
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
    r"threshold` and `signer_count` \*\*must not change": "WI-280: threshold may rise, signers may be replaced",
}

MARKER_WORDS = re.compile(
    r"SUPERSEDED|AMENDED|CUT FROM|CUT —|WITHDRAWN|OBSOLETE|RESOLVED|CONFIRMED|retired|Retired"
    r"|does not exist|\*\*Cut:\*\*|is cut|cut from 0\.6\.0|no longer|never a wire value|is a retired spelling"
)


def is_marked(lines: list[str], idx: int) -> bool:
    """True when the line sits inside a marker: a blockquote, a strikethrough, a marker table
    row, or a JSON-example line that points at one."""
    line = lines[idx]
    stripped = line.lstrip()
    if stripped.startswith(">"):
        return True
    if "~~" in line:
        return True
    if MARKER_WORDS.search(line):
        return True
    # a table row inside an OVERLAY APPLIED banner
    if stripped.startswith("|") and MARKER_WORDS.search("\n".join(lines[max(0, idx - 40): idx])):
        # only if the banner heading is close above
        for back in range(idx - 1, max(-1, idx - 40), -1):
            if lines[back].startswith("## OVERLAY APPLIED"):
                return True
            if lines[back].startswith("## ") and "OVERLAY" not in lines[back]:
                break
    # JSON example line carrying a pointer comment
    if "//" in line and re.search(r"//.*(CUT|see §|Resolution|collision|—)", line):
        return True
    return False


def main() -> int:
    root = Path(__file__).parent
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

    for p in problems:
        print(p)
    print(f"\n{len(problems)} contested value(s) still stated as live rules.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
