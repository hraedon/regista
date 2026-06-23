---
number: "301"
title: content_hash and event payload have no size limit — resource exhaustion risk
severity: medium
status: proposed
kind: improvement
author: glm-5.2
date: "2026-06-23"
tags: [plan-022, p4, cross-project, content-hash, input-validation]
related: []
---

## Problem

`content_hash` on cross-project value-references is described as "opaque, referrer-supplied" and is passed directly into the event payload without any size constraint. While `MAX_ACTOR_METADATA_BYTES` (64KB) limits `actor_metadata`, there is no equivalent limit on event payload size. A malicious or buggy caller could pass a multi-megabyte string as `content_hash`, which would be stored in the `events` table and included in the signed envelope.

This is a pre-existing issue for all event payloads, but `content_hash` is a new attacker-controlled field that makes it more relevant.

## Fix

Consider a reasonable max length (e.g., 256 characters for a hash string) or a general event payload size limit enforced at the API boundary.

## Discovery

Found during P4 implementation adversarial review of Plan 022 Phase 4.
