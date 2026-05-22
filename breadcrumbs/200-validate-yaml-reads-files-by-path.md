---
number: "200"
title: "validate_yaml reads files when string happens to match existing path"
severity: medium
status: proposed
kind: bug
author: adversarial-review
date: "2026-05-22"
tags: [workflow, security, confused-deputy]
related: []
---

# BC-200 — validate_yaml reads files when string happens to match existing path

## Problem

In `_workflow.py:511-522`, `validate_yaml` checks if the input string is a valid file path that exists on disk, and reads the file if so. This means passing a string like `/etc/passwd` or a path to another YAML file would read that file instead of treating the input as YAML content.

The sidecar's `register_workflow` endpoint accepts `yaml_content` as a string, so an attacker could potentially read arbitrary YAML/JSON files. The damage is limited by YAML parsing (non-YAML files fail), but it's a confused-deputy issue.

```python
try:
    p = Path(source)
    if p.exists():
        raw = p.read_text()  # reads file even when string was intended as YAML
    else:
        raw = source
except Exception:
    raw = source
```

## Proposed fix

Remove the file-path auto-detection from `validate_yaml`. Callers that want to validate a file should use `validate_yaml(Path(path))` explicitly. The current behavior is a convenience that creates a security surface.
