# Publication-Review Checklist — regista

Before flipping the repository from private to public, verify each item.

**Status legend:**
- `[x]` — verified clean
- `[ ]` — not yet verified / action needed
- `[~]` — partially verified, caveat noted

---

## 1. Identifier scrub

- [x] `REGISTA_FORBIDDEN_IDENTIFIERS="$(cat .identifiers-denylist.local)" python3 scripts/check_committed_identifiers.py` exits 0 (denylist is never committed — gpo-lens pattern)
- [x] Always-on `samples/` guard active — no tracked file under `samples/`
- [ ] Git history rewritten via `git filter-repo` to scrub author/committer identity — **NOT done**. Author/committer still uses `Paul Merritt <plm@hraedon.com>`. See `docs/history-identifier-audit.md` (1632 leaks found).
- [ ] No work-domain email addresses in git log — **20 violations in working tree** + 402 in git history
- [ ] No internal hostnames in git history — `mvmpostgres01` (7 in history, 4 in working tree), `mvmcitest01` (4 in history, 3 in working tree)
- [ ] No personal principal handles in git history — `plm@hraedon.com` (402), `Merritt` (402), `hraedon` (415)
- [x] Denylist covers ALL identifier forms per adcs-lens WI-010 lesson — hostnames, AD domain, email, personal name, GitHub username. 6 identifiers total.

## 2. Secrets

- [ ] No API keys, tokens, or passwords in tracked files
- [ ] `.claude/` is gitignored
- [ ] Test fixtures use only placeholder credentials
- [ ] No real DSNs or connection strings in code or docs

## 3. Naming coherence

- [x] Package name `regista` is consistent across `pyproject.toml`, CLI, and docs
- [ ] `README.md` references `regista` as the working name
- [ ] `SUITE.lock` references the correct GitHub org and repo
- [ ] `AGENTS.md` is up to date

## 4. License and authorship

- [x] MIT license file present
- [ ] `pyproject.toml` author is generic
- [ ] No employer-proprietary code or references

## 5. Dependencies

- [ ] `pyproject.toml` lists all runtime dependencies
- [ ] No dependency on private/internal packages

## 6. CI

- [x] `.github/workflows/ci.yml` runs ruff + mypy + pytest
- [x] Identifier gate runs in CI (with always-on `samples/` guard)
- [ ] All tests pass on a clean checkout

## 7. Documentation

- [ ] README is coherent as a public-facing document
- [ ] No references to internal systems, employer, or internal projects
- [ ] Cross-project references use public URLs
- [ ] Reflections directory is clean of personal identifiers

---

## Remaining blockers before public flip

1. **Git history scrub** — 1632 identifier leaks in history (see `docs/history-identifier-audit.md`). Author/committer identity must be scrubbed. Run `git filter-repo --replace-text scripts/filter-repo-replacements.txt` followed by GitHub repo delete+recreate.
2. **Working tree scrub** — 20 identifier violations in tracked files (reflections, plans, CHANGELOG, README). Fix before commit.
3. **GitHub org name** — `hraedon` correlates with internal domain.
4. **Employer IP/moonlighting check** — not yet confirmed.