---
number: "250"
title: TSA response unbounded read allows memory exhaustion
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [timestamping, dos]
related: ["239"]
---

## Problem

`submit_to_tsa()` calls `resp.read()` with no size limit. A compromised or misconfigured TSA server could return an arbitrarily large response, exhausting server memory. The same class of bug was fixed for witness delivery (BC-239) but the TSA path was not protected.

## Fix

Changed to `resp.read(1_000_000)` (1MB cap), matching the witness delivery response limit.
