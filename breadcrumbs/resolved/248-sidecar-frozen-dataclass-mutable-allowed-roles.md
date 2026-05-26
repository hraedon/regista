---
number: "248"
title: Sidecar frozen dataclass AuthenticatedActor has mutable allowed_roles list
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [sidecar, auth, security]
related: []
---

## Problem

`AuthenticatedActor` is `@dataclass(frozen=True)` but `allowed_roles: list[str]` is mutable. The `TokenRegistry` stores instances permanently and reuses them across all requests. Any code that accidentally mutates the list (`.sort()`, `.append()`, `+=`) permanently escalates privileges for all future requests using that token.

## Fix

Changed `allowed_roles` to `tuple[str, ...]` with a `__post_init__` that converts any list to tuple.
