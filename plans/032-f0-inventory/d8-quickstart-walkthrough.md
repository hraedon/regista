# D8 — the unfamiliar-reviewer quickstart walkthrough

**Date:** 2026-09-17. **Subject:** `prototypes/kernel/README.md` at `a9f6913`.
**Status of the F0a exit criterion: PARTIALLY satisfied.** See "What this does
and does not establish" before quoting it.

Plan 032 F0a requires that "a reviewer unfamiliar with the implementation must
be able to follow the quickstart unaided; record where they needed
clarification." It is the one exit criterion that cannot be self-reported —
whoever wrote the API is the worst judge of whether its quickstart is
followable.

## Method

Four runs, each given a copy of `prototypes/kernel/` at the committed state (so
in-flight defect fixes could not contaminate the reading), its own empty
PostgreSQL database, `psycopg` v3 already present, and this rule: **work from
`README.md` only; being stuck is the finding, not a problem to solve.** Reading
source to unblock was permitted only after recording the blocker, and anything
learned that way had to be labelled as such. The reviewer complied with that
labelling, which is what makes the blocker below trustworthy.

Deliberately withheld: the wider repository. A reviewer was given only the
directory, which is the condition a package user is actually in.

## What this does and does not establish

**It does not establish cross-lineage independence.** All four runs were
intended to be different models. They were not: `opencode2` v2.0.1 routes every
agent to a single model regardless of the `model:` pinned in the agent
definition — asked directly, it identifies itself as "Union Alpha", and the
banner prints that name under every agent. So this is **one reader's experience,
sampled four times**, and the findings below should be read as one sample.

Three of the four runs died mid-walkthrough with "The provider response ended
unexpectedly" — transient provider failure, not a verdict on the exercise. Two
runs produced substantial evidence: one reached step 5 of 6, and one kept a
414-line incremental log through the Python-API step before its own cutout. No
run reached the summary section, so the verdict below is assembled from their
logs rather than self-reported.

**Both substantive runs independently hit the same failures** — the compose
path, `python`, the `<id>` shell error, the empty `needs_review` filter, and the
unbridged `DSN`. Same model, so this is repeatability, not corroboration by a
second opinion; but it does rule out a one-off.

One reviewer's discipline is worth recording, because it is why the findings can
be trusted: it retracted, unprompted, four of its own earlier claims — including
a `psql` check it had not actually run and a README line it had mis-stated —
and relabelled every command it had adapted rather than executed verbatim.

**It does not satisfy the criterion in full.** Plan 032's preferred reader is a
person representative of the intended Python/PostgreSQL user. A fresh agent
session is a practical first pass that finds the cheap defects; it is not a
substitute. The findings here should be fixed *before* a person is asked, so
their time is spent on what an agent cannot see.

## Findings

Ordered by severity. Everything below was observed, not inferred.

### B1 (blocker). The Python API cannot complete the README's own implied loop

The README documents `roles={"accept": ("reviewer",)}` on a workflow, and its
CLI section shows a `--role` flag. It never shows **how a Python caller presents
a role.** The reviewer got as far as create → claim → two transitions, then hit
`accept` and was refused. Two compounding problems:

- The README alone is insufficient to proceed. This is a genuine dead end, not a
  slow patch.
- **The error does not name the parameter.** It says the caller "presented
  `None`" — which tells you a role was expected and not what to pass or where.

This is an API discoverability defect, not only a documentation one, and it is
the same class as the three defects F0a already caught by writing scenarios
(`health`/`list_workflows` missing from the public API, `release()` taking a
`Claim` a CLI cannot hold). A fourth instance of the same pattern is worth
noting: **the surface is still being found by use, not by reading it.**

### B2 (blocker). The first command in the quickstart cannot run

`docker compose -f ../../docker-compose.test.yml up -d` points outside the
directory. A reader with only the package cannot run step one, and learns the
file is load-bearing only by its failure. The README never offers "or point at
any PostgreSQL you already have" at the point where that would rescue them.

### F3. `transition <id>` is not merely a placeholder — it is a shell error

Pasted verbatim, bash reads `<id>` as input redirection and emits
`/bin/bash: id: No such file or directory`. A reader who copies the documented
command gets a cryptic error that does not look like a placeholder problem.

### F4. There is no documented way to obtain an id

The README's only CLI mutation example needs an `<id>` and never says how to get
one. Worse, the one query it shows — `list --state needs_review` — returns
`(none)` after the shipped examples run, because they leave nothing in that
state. The reviewer recovered by guessing that bare `list` works. It does; the
README does not mention it. **The single CLI command a new reader would try is
not executable against the state the README's own examples produce.**

### F5. The shell and Python halves of the quickstart do not connect

The shell section does `export DSN=...`; the Python snippet then uses a bare
`DSN` that is undefined in Python. The README never bridges them.

### F6. The DSN is presented as the answer, not an example

`postgresql://regista_test:regista_test@localhost:5432/regista_test` is given as
*the* connection string. A reader with their own database must work out that it
is a substitution.

### F7. `python` vs `python3`

Every documented command says `python`. On an ordinary modern Linux box only
`python3` exists. Small, universal, and hit on literally every command.

### F8. Unstated prerequisites

- **No Python version is stated anywhere**, on a package whose support range is
  a live decision (`>=3.11`, tested 3.11–3.14).
- **That all files must sit in one directory** and commands run from it. Implied
  by `python example_handoff.py`, never said. `k.initialize("schema.sql")` names
  the schema by bare filename and never says where that file is.
- **No install step is mentioned at all.** Reasonable if the intent is
  copy-the-directory, but the README does not say even that.
- **How to create a database.** The README does say "Point it at a fresh
  database" (line 109) — but that line sits below the quickstart, and nothing
  covers creating one or what privileges it needs. The Docker path is the only
  route shown, and it is the one that fails (B2).

Two candidate findings were **withdrawn** by the second reviewer on its own
initiative, and are recorded here so they are not re-raised:

- *"`psycopg` is ambiguous with psycopg2."* Withdrawn — `psycopg` is
  unambiguously the v3 distribution name. No import failure was observed.
- *"The README never says to use an empty database."* Withdrawn — line 109 says
  exactly that. The residual point above is narrower and survives.

### F10. The CLI is called two different things

The README documents `python cli.py …`. The documents scenario prints its
commands as `regista-kernel …`. A reader cannot tell whether an installed
executable exists, and the README never mentions one.

### F11. The README's only Python example produces no output

Run as given (once the `DSN` problem in F5 is worked around), the model snippet
completes silently — no print, no id, no state. The first successful direct use
of the API tells the reader nothing about whether it worked.

### F9. `example_documents.py` invokes a CLI that was never installed

It prints and shells out to `regista-kernel …`. Nothing in the README says the
scenario depends on a command-line entry point, or how a reader would have one.

## Claims checked

| README claim | Result |
| --- | --- |
| "Try it in two minutes" | **Dented.** The shipped examples do run first try, but step one fails outright and step five dead-ends. |
| Both scenarios run | **True.** Each passed first try against a substituted DSN. |
| "13 checks, each with a control" | **Count verified in both runs (13 passed, 0 failed); the control claim was NOT verified.** One reviewer noted honestly that running the suite confirms the runner's reported count and nothing about whether each check pairs its refusal with a legitimate call — that needs the test source, which was out of bounds. Recorded because it is exactly the kind of claim a reader takes on trust. |
| Replay "no drift; chain intact" (printed by the documents scenario) | **Printed, and now known to be narrower than it reads.** At the time of this walkthrough replay compared only state; the drift work is in flight. A reader shown "chain intact" will not infer the boundary. |

## The single change that would most improve this quickstart

Make the CLI section executable end to end from the state the examples actually
leave behind: show how to obtain an id, use a real one, and do not lead with a
filter that returns nothing. That one section is where a reader goes from
"watched a demo run" to "did something myself", and today it breaks at every
step — placeholder, missing query, and shell metacharacter.

Close behind it: show a Python caller presenting a role (B1), because that is
the only finding here that a reader cannot work around.

## Disposition

F3–F9 are documentation fixes. **B1 is not** — it is an API discoverability
defect plus an unhelpful error message, and it belongs with the kernel work.

D8 should be re-run against the corrected README, by a person, before F0a is
declared closed.
