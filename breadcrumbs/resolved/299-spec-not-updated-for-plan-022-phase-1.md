---
number: "299"
title: Spec not updated for Plan 022 Phase 1 (entity generalization, envelope v4)
severity: medium
status: proposed
kind: improvement
author: glm-5.2
date: "2026-06-23"
tags: [plan-022, spec, entity-generalization, crypto-agility]
related: []
---

## Problem

Plan 022 Phase 1 has been implemented (envelope v4 with `entity_kind`, `entity_id`, `hash_alg`), but `spec.md` still describes envelope v3 with `work_item_id` as the entity key. AGENTS.md says "do not silently diverge from the spec."

The spec needs amendment to document:
- The v4 envelope shape (`entity_kind` + `entity_id` replaces `work_item_id`, `hash_alg` added)
- The new event columns (`entity_kind`, `entity_id`, `hash_alg`)
- The deprecation of `work_item_id` as the entity key
- The default `hash_alg="sha-256"` and that it is not yet load-bearing (Phase 2)
- The trigger that auto-populates `entity_id` from `work_item_id`

## Discovery

Found during adversarial review of Plan 022 Phase 1 by Kimi K2.7 reviewer.
