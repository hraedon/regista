# /end — Session Wrap-Up

Close out a session cleanly: verify tests, update breadcrumbs, update the worklog, write a reflection, and commit.

## Steps (run in this order)

---

### 1. Determine what was done

```bash
git diff --stat HEAD 2>/dev/null | tail -5
git log --oneline origin/main..HEAD 2>/dev/null | head -20
```

Read the last worklog entry in `.regista/worklog.md` to understand the session context. Build a mental list of: what was completed, what was fixed, what was added.

---

### 2. Run the test suite

```bash
docker compose -f docker-compose.test.yml up -d 2>&1 | tail -3
.venv/bin/python -m pytest tests/ -v 2>&1 | tail -20
.venv/bin/ruff check src/
```

**If tests fail or lint has errors:** stop. Report the failure(s) and do not proceed to commit. Fix or flag before continuing.

---

### 3. Resolve work-items

Work-items live in **regista** (the SoT); transition them via the agent-notes CLI
— do not touch `breadcrumbs/` files (retired). For each item resolved this session:

```bash
# Move through the lifecycle; `done` requires the cross-lineage review gate,
# or use close_from_open for a won't-fix / duplicate dismissal.
agent-notes breadcrumb update --path . <WI-id> --status <state>
```

Confirm with `agent-notes breadcrumb find --path . --status open` that the backlog
reflects reality before committing.

---

### 4. Update worklog

Prepend a new entry to `.regista/worklog.md` before the existing `##` heading.

Entry format:
```
## <YYYY-MM-DD> — Session with <model-slug> (opencode)

**Focus:** <one phrase — what the session was about>

**Context:** <1–2 sentences on what state the project was in at session start>

**Delivered:**
- <change 1> — `<file(s)>`: <what changed and why>
- <change 2> — ...

**Breadcrumbs resolved:** BC-NN (title), ... or "None"

**Remaining open:** <highest-severity item still open, or "None">

**Test Results:** <N> passed in <time>s

**Lint:** <clean or N errors>

---
```

Be specific. Name files. Name breadcrumb numbers. Write for a future model reading this cold.

---

### 5. Write a reflection

Follow the `/reflection` skill steps exactly — gather metadata, write all four sections, save to `.regista/reflections/YYYY-MM-DD-<model-slug>-opencode.md` (append `-2` if a file already exists for today).

---

### 6. Update AGENTS.md if needed

Check if any of the following were changed this session:
- New public API methods → add to AGENTS.md Public API section
- New error codes → note in AGENTS.md
- New conventions discovered → add to AGENTS.md Conventions section
- New work-tracking conventions → update the AGENTS.md "Work tracking" section

Only update if there's a concrete addition. Do not rewrite for style.

---

### 7. Commit

Stage everything:
```bash
git add -A
git status
```

Review staged files. If anything looks wrong (secrets, generated files that shouldn't be committed, stale artifacts), unstage and investigate.

Write a commit message:
- Subject ≤ 50 chars, imperative mood
- Body: bullet the main changes, reference BC numbers resolved
- No comments in code

```bash
git commit -m "..."
```

---

### 8. Present the session summary

Output a single block:

```
## Session End — <date>

**Tests:** <N> passed / <N> failed
**Lint:**  <clean or N errors>
**Breadcrumbs resolved:** <list or "none">
**Worklog:** updated
**Reflection:** .regista/reflections/<filename>
**Commit:** <short hash> <subject>

**Still open (highest priority):** <BC-N: title or "nothing critical">
```

Do not ask questions. Do not propose further work unless a test is failing.
