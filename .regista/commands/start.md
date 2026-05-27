# /start — Session Bootstrap

Orient yourself at the start of a session in the regista project.

## Steps (run in this order)

### 1. Worklog — last entry

Read `.regista/worklog.md` and extract the most recent entry (identified by `##` heading with date). Summarise it in 2-3 sentences: what was completed, what was left open.

### 2. Open breadcrumbs

Run:
```bash
ls breadcrumbs/*.md 2>/dev/null | grep -v README | sort
```

For each file, extract `number`, `title`, `severity`, and `status` from the frontmatter. Group output by severity (critical → high → medium → low). Skip the `resolved/` subdirectory.

### 3. Test suite

Ensure Postgres is running, then:
```bash
docker compose -f docker-compose.test.yml up -d 2>&1 | tail -3
.venv/bin/python -m pytest tests/ -x -q --tb=no 2>&1 | tail -5
```

Report pass/fail count and any failing test names. Do not print full output.

### 4. Lint

```bash
.venv/bin/ruff check src/ 2>&1 | tail -5
```

### 5. Present summary

Output a single "here's where you left off" block in this format:

```
## Session Start — <today's date>

**Last work:**
- <worklog entry summary>

**Open breadcrumbs (<N> total):**
- [high]     <number>: <title>
- [medium]   <number>: <title>
- [low]      ...

**Tests:** <N> passed / <N> failed  (<failed test names if any>)
**Lint:**  <clean or N errors>

**Suggested next:** <one sentence — the highest-severity open breadcrumb or a failing test>
```

Do not ask any questions. Do not propose a plan. Present the summary and wait.
