# Plan 018 — Rename regista → regista

**Status:** Ready to execute. Foundation phase of the cross-project rename (see `/projects/RENAME-regista-to-regista.md` for orchestration).
**Type:** Mechanical refactor with one schema-level decision.
**Pre-rename tag:** `v0.4.0-pre-rename` — the rollback target if anything goes sideways.
**Target tag at completion:** `v0.4.0`.

---

## 1. Decisions locked before starting

1. **Hard cutover, no compat shim.** Regista isn't on PyPI; all consumers are under one operator's control; consumers migrate in lockstep (Phase 2 of the meta plan). A `regista` shim that re-exports `regista` would be a permanent appendage in practice. Skip it.
2. **Rename the `regista_version` column to `regista_version`.** It's a load-bearing column (workflow registration tracks which library version registered each workflow). Migration cost is one `ALTER TABLE … RENAME COLUMN` plus code-site updates. Leaving the old name is a paper cut every time someone reads the column.
3. **Rename env vars.** `REGISTA_DSN` → `REGISTA_DSN`, and the other 9. No backwards-compat aliasing in code — consumers' Phase-2 plans include the env var rename.
4. **Tag pre-rename first.** `git tag v0.4.0-pre-rename` before any rename commits land. Consumers pin to this tag during their migration window so they're never broken by an in-flight rename.

---

## 2. Pre-flight checklist

Do these once, before any sed:

- [ ] GitHub repo renamed `hraedon/regista` → `hraedon/regista` via Settings (Phase 0 of the meta plan). GitHub's redirect handles the old URL automatically.
- [ ] `git remote set-url origin https://github.com/hraedon/regista.git` in the local checkout.
- [ ] `git tag v0.4.0-pre-rename && git push --tags origin`.
- [ ] Tests pass on the current tree: `pytest -q`. Tag is meaningless if the snapshot isn't green.
- [ ] Any locally-running regista sidecar or consumer process is stopped (`ps aux | grep -E 'regista|sidecar'`).
- [ ] You're on a fresh branch off main: `git checkout -b rename/regista-to-regista`.

If `pytest -q` is not green, **stop**. Don't rename a broken tree.

---

## 3. Execution order

The order matters. Code-site renames before directory move; directory move before venv rebuild; venv rebuild before test runs.

### 3a. In-tree string replacements

One sweep with sed across the whole tree. Excludes: `.venv/`, `.git/`, `dist/`, `__pycache__/`, `node_modules/` (none expected), `breadcrumbs/active/`, `breadcrumbs/resolved/`, `reflections/`, `debate/` (historical record).

```bash
# Live edit targets
sed -i \
  -e 's/\bregista\b/regista/g' \
  -e 's/\bREGISTA\b/REGISTA/g' \
  -e 's/\bRegista\b/Regista/g' \
  $(find . -type f \
      \( -name '*.py' -o -name '*.md' -o -name '*.toml' -o -name '*.yaml' -o -name '*.yml' -o -name '*.sql' -o -name '*.cfg' -o -name '*.ini' -o -name 'Makefile' \) \
      ! -path './.venv/*' \
      ! -path './.git/*' \
      ! -path './dist/*' \
      ! -path './**/__pycache__/*' \
      ! -path './breadcrumbs/*' \
      ! -path './reflections/*' \
      ! -path './debate/*')
```

Word-boundary anchoring (`\b`) is important: `regista` will hit, but so will words containing it (e.g., none that I see in the tree, but the anchor is cheap insurance). `REGISTA_DSN` etc. are caught by the uppercase sed.

After the sed, sanity-check:

```bash
# Should return 0 hits across edited files
grep -rn 'regista\|REGISTA\|Regista' \
  --include='*.py' --include='*.md' --include='*.toml' \
  --include='*.yaml' --include='*.sql' \
  . \
  | grep -v 'breadcrumbs/\|reflections/\|debate/\|\.venv/\|\.git/'
```

Any remaining hits are either (a) historical text that should stay, (b) intentional ("regista, formerly regista"), or (c) a sed miss to fix by hand.

### 3b. Directory rename of the Python package

`src/regista/` → `src/regista/`. Use `git mv` so history follows:

```bash
git mv src/regista src/regista
```

Check `pyproject.toml` already shows `packages = ["src/regista"]` from the 3a sed.

### 3c. CHANGELOG entry

Hand-write a v0.4.0 entry. Don't let sed touch the historical entries — they're point-in-time records. Add:

```markdown
## [0.4.0] — 2026-05-NN

### Changed

- **Project renamed: `regista` → `regista`.** The PyPI/GitHub name, Python module, console script, and all env vars now use `regista`. Repo is at https://github.com/hraedon/regista; the old URL redirects. See `RENAME-regista-to-regista.md` in the parent directory and Plan 018 for context.
- **Schema:** `workflows.regista_version` column renamed to `regista_version` (migration 029). Code paths in `_workflow_api.py`, `_in_memory.py`, `_work_items.py` updated accordingly.
- **Env vars:** `REGISTA_DSN`, `REGISTA_HMAC_KEY_*`, `REGISTA_BIND`, `REGISTA_DISABLE_DOCS`, `REGISTA_DISABLE_RATE_LIMIT`, `REGISTA_POOL_MAX`, `REGISTA_POOL_MIN`, `REGISTA_PROJECT`, `REGISTA_TOKENS_PATH`, `REGISTA_VERSION` → all renamed `REGISTA_*`. No backwards-compat aliasing.
- **Console script:** `regista` → `regista` in `[project.scripts]`.

### Migration notes for consumers

Consumers pin to `v0.4.0-pre-rename` during their migration window. See per-repo plans under each consumer in the meta orchestration doc. Migration steps per consumer:

1. Update `pyproject.toml` / requirements: `regista` → `regista`.
2. Update imports: `from regista import …` → `from regista import …`.
3. Update env var references in code, scripts, and deployment configs.
4. Re-run tests.
```

### 3d. Schema migration for `regista_version` → `regista_version`

Create `migrations/029_rename_regista_version_column.sql`:

```sql
-- Plan 018 (regista → regista rename): rename workflows.regista_version → regista_version.
ALTER TABLE workflows RENAME COLUMN regista_version TO regista_version;
```

Verify by hand that `_workflow_api.py`, `_in_memory.py`, `_work_items.py` references were caught by the sed; the column appears in SQL string literals which the sed touched. Spot-check:

```bash
grep -rn 'regista_version\|regista_version' src/
# Should be 0.
grep -rn 'regista_version' src/
# Should match the 6 sites previously holding regista_version.
```

### 3e. README / spec.md / spec.yaml / product-concepts/

These are the substantive content files. Sed gets the literal word; what it *doesn't* do is rewrite framing where "regista" was a deliberate metaphor (the geology-style "foundation" framing in the README's prose). Read README.md and spec.md after the sed and decide whether any prose needs hand-rewriting:

- `README.md` first paragraph: "Coordination and durable state for agent pipelines over Postgres" — still accurate, no rewrite needed.
- `README.md` "What's here" section: scan for places where "regista" was used as a *concept* not a *name*. Likely fine; the term mostly appears as the proper noun.
- `spec.md` header: `# Specification: regista` — accurate post-sed.
- `product-concepts/*.md` — these are positioning docs. Scan for stale framing.

If you find prose where "regista" was a metaphor that no longer reads well as "regista" (e.g., "this is the regista everything else builds on"), rewrite it. Don't leave geology metaphors that now lie.

### 3f. Venv rebuild

```bash
rm -rf .venv
uv venv
uv pip install -e ".[dev,test]"
.venv/bin/regista --help    # console script resolves under new name
```

### 3g. Test run

```bash
.venv/bin/pytest -q
```

Expected: 992+ tests green (or whatever the current count is at v0.4.0-pre-rename + new migration test). If any test references "regista" as a string (e.g., in error messages, log output), the sed caught the source but not the test's expected-value string. Fix the test's expected value to match `regista`.

### 3h. Tag and push

```bash
git add -A
git commit -m "rename: regista → regista (Plan 018)"
git push -u origin rename/regista-to-regista

# Open PR, self-review, merge to main.
# After merge:
git checkout main
git pull
git tag v0.4.0
git push --tags
```

Use a single atomic commit on the branch. The diff will be enormous (295+ files), but it's mechanical and reviewable as a diff-stat plus spot-checks. A multi-commit split here would create non-compiling intermediate states.

---

## 4. Exit criteria

All must be true before declaring Phase 1 done and unblocking the consumer plans:

- [ ] `https://github.com/hraedon/regista` accessible; old URL redirects.
- [ ] `main` branch at the rename commit; tag `v0.4.0` pushed.
- [ ] `pip install -e .` in a clean checkout succeeds; `regista --help` works.
- [ ] `pytest -q` green (modulo any pre-existing skipped tests).
- [ ] Migration 029 applies cleanly against a fresh test DB and against a DB at the v0.4.0-pre-rename schema.
- [ ] `grep -rn 'regista\|REGISTA' --include='*.py' --include='*.toml' src/ pyproject.toml` returns no hits. (`Regista` in CHANGELOG entries and historical text is fine; src/ should be clean.)
- [ ] CHANGELOG v0.4.0 entry written.
- [ ] No live regista process still running against the old name.

---

## 5. Intentionally not touched (historical record)

Same posture as the agent-notes rename. The sed exclusion list covers these, but called out for clarity:

- `breadcrumbs/active/*.md` and `breadcrumbs/resolved/*.md` — BC bodies that say "regista" are point-in-time records.
- `reflections/*.md` — dated session reflections.
- `debate/*.md` — design-debate artifacts; the historical name was correct when written.
- Closed plan documents (plans/001 through 017 if they reference the rename topic only in passing).
- Older `product-concepts/` docs if they're clearly historical (positioning docs from before the rename).

If you're unsure whether a file is live or historical, the test is: *would a reader six months from now need this file to reflect the new name to understand current state?* If yes, edit. If no, leave it.

---

## 6. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Sed catches a word inside another word and corrupts it | `\b` word-boundary anchors. Manual grep after sed catches misses. |
| Tests reference "regista" as a string in expected values | Run pytest; fix test strings as a follow-up commit (same PR). |
| Consumer pins to old commit during migration; regista continues to evolve before consumers catch up | Acceptable. `v0.4.0-pre-rename` is the durable pin; consumers migrate at their own pace. |
| Migration 029 fails against a DB with no `workflows.regista_version` column (e.g., a partial-init DB) | Migrations are sequential; if the schema is at an earlier version, run prior migrations first. Standard expectation. |
| `regista_version` reads worse than `regista_version` to future readers | One-time aesthetic cost. The alternative (column name lies about what it represents) is worse. |
| Re-running the rename is non-trivial if something blocks halfway | `git reset --hard v0.4.0-pre-rename` restores the clean state. Restart. |

---

## 7. Open questions (answer before merging the PR)

1. **Does the deployed sidecar systemd unit name change too?** Probably yes (`regista-sidecar.service` → `regista-sidecar.service`), but check `deploy/` for the canonical name and decide whether to break the systemd contract or alias.
2. **Do `migrations/*.sql` filenames need a comment block updating to reference the new name?** Probably no — SQL file names are historical; their content was sed-touched.
3. **Should `dist/` artifacts be cleaned up before the rename commit?** Yes — `rm -rf dist/` to avoid stale wheels in the diff.
4. **Are there any vendored references (`src/regista/_vendor/`) to "regista" that need preserving?** Sed catches all by default; verify `_vendor/` is intact by hand if vendored code has license headers mentioning regista.

Answer these inline in the PR description, not in this plan.
