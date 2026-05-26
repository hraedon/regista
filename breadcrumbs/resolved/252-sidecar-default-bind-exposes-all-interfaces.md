---
number: "252"
title: Sidecar default bind 0.0.0.0 exposes service on all network interfaces
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [sidecar, security, network]
related: []
---

## Problem

The sidecar default bind address was `0.0.0.0:8080`, exposing the service on all network interfaces without TLS. Combined with the lack of rate limiting, this makes the sidecar accessible to any network-adjacent attacker.

## Fix

Changed default to `127.0.0.1:8080`. Operators who need network exposure can set `SUBSTRATE_BIND=0.0.0.0:8080`.
