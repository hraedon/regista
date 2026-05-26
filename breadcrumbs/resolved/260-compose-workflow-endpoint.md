---
number: "260"
title: compose_workflow endpoint and CLI command
severity: low
status: resolved
kind: improvement
author: adversarial-review
date: "2026-05-26"
tags: [sidecar, cli, workflow]
related: []
---

## Problem

The `compose_workflow` utility was library-only.

## Fix

Sidecar: `POST /v1/compose_workflow` accepts `file_path`, returns composed dict and source map. CLI: `substrate workflow compose <file> [--json]`.
