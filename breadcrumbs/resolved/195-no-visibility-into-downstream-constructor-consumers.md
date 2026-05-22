---
number: "195"
title: No visibility mechanism for downstream consumers of Substrate constructor signature
severity: medium
status: implemented
kind: design
author: claude
date: "2026-05-19"
tags: [dep-sf2, public-api, consumer-coupling]
related: []
---

## Failure mode

Substrate's `__init__` constructor is a load-bearing public-API surface for
downstream consumers, but substrate has no concept of "downstream consumer of
constructor signature." Changes to `Substrate.__init__` — even unintentional
ones such as the recent indentation bug in the constructor body — can silently
break downstream tooling without producing any signal at substrate's CI. The
downstream project discovers the breakage at runtime, not at substrate
integration time.

This is the standard public-API blind-spot pattern: substrate's tests exercise
substrate's own callers, not the consumer call sites that live in sibling
repos.

## Evidence

- Downstream consumer:
  `/projects/software-factory-2/scripts/build_failure_corpus.py:148`
  `sub = Substrate(config.dsn, config.project_name, config.hmac_key_path)`
  (import at line 12: `from substrate import Substrate`). This script's
  correct operation depends on the constructor accepting that exact positional
  shape and completing without raising.
- sf2 reflection
  `/projects/software-factory-2/reflections/2026-05-15-glm-5-1.md` flags
  substrate as the source of recent silent-breakage process debt; the
  immediately following session's reflection
  `/projects/software-factory-2/reflections/2026-05-16-glm-5-1.md:41` makes
  the coupling concrete: "Substrate changes are uncommitted — `__init__.py`
  and `_in_memory.py` have uncommitted changes… The `register_workflow_file`
  fix is load-bearing — without it, any code path that calls
  `register_workflow_file` on a composed YAML will fail." The pattern (sf2
  discovering substrate-internal changes silently affect its production paths)
  applies identically to the constructor.
- Substrate's CI has no test that imports the way sf2 imports, and no contract
  surface that pins the constructor's positional signature.

## Proposed remedies (cheapest first; recommend the first)

1. **Recommended — contract test pinned to sf2's actual call shape.** Add a
   single test in substrate's suite that constructs `Substrate` using exactly
   the positional shape `Substrate(dsn, project_name, hmac_key_path)` that
   `build_failure_corpus.py:148` uses, with realistic argument types. Failure
   means substrate's CI breaks the moment the constructor's external contract
   regresses. Cost: one test file (~20 lines), zero new infrastructure, no
   cross-repo coupling at runtime. This is the cheapest credible signal.

2. **Public stability annotation on the constructor.** Mark `Substrate.__init__`
   with an explicit `# Public API — positional signature is stable; see BC-195`
   comment and add a docstring section listing known downstream consumers
   (sf2 at minimum). This is cheap but only catches changes a human reviewer
   notices; it doesn't fire at CI time. Useful as a complement to (1), not a
   substitute.

3. **"Downstream-consumer findings" channel.** Stand up a lightweight inbox
   (e.g., a `downstream/` directory or a labelled issue stream) where sf2
   files breakage reports back to substrate. This raises the visibility of
   the *category* of problem but does not prevent the next instance, and the
   cost — process, routing, follow-through — exceeds the cost of option (1)
   by an order of magnitude.

Pick (1). Add (2) opportunistically. (3) is for the multi-consumer future,
not now.

## Acceptance criteria

- [ ] A test in substrate's suite constructs `Substrate` with the exact
      positional signature used at
      `/projects/software-factory-2/scripts/build_failure_corpus.py:148`.
- [ ] The test runs in substrate's default `make check` / CI path (not
      `slow` or `manual`).
- [ ] The test fails — visibly, at substrate CI — if a future change to
      `Substrate.__init__` breaks that positional shape or introduces a
      regression in constructor execution (such as the indentation bug that
      motivated this breadcrumb).
- [ ] The test file or its header references BC-195 and names sf2 as the
      pinned consumer, so the next agent touching `__init__` knows why the
      test exists.
- [ ] (Optional) `Substrate.__init__` carries a one-line comment marking it
      as public-API surface with a pointer to BC-195.
