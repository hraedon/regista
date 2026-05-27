---
number: "271"
title: "CLI main() dispatch is a fragile 40-branch if/elif chain"
severity: low
status: implemented
kind: design
author: reflection
date: "2026-05-26"
tags: [cli, maintainability]
related: ["262"]
---

## Problem

`_cli.py:main()` has ~40 if/elif branches for command dispatch. Adding a new command requires changes in three places: (1) argparse definition, (2) command function, (3) dispatch branch. The dispatch is positional (`args.command == "X" and args.subcommand == "Y"`) and easy to get wrong.

Missing subcommand handling is inconsistent: some domains (hooks, timestamp, witness) print help and exit 2, others fall through to a generic handler.

## Resolution

Refactored to use `set_defaults(func=...)` pattern on every leaf subparser. The 40-branch if/elif chain replaced with a single `hasattr(args, "func")` check. Adding a new command now requires only two changes: (1) argparse definition + `set_defaults(func=...)`, (2) command function. Consistent help-on-missing-subcommand behavior via fallback to `target.print_help()`.
