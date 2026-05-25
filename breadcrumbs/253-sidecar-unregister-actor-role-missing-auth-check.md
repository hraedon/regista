---
number: "253"
title: Sidecar unregister_actor_role endpoint missing authorization check
severity: medium
status: resolved
kind: bug
author: adversarial-review
date: "2026-05-25"
tags: [sidecar, auth, authorization]
related: ["199"]
---

## Problem

`register_actor_role` correctly verifies `body.role in actor.allowed_roles` before allowing registration. However, `unregister_actor_role` had no such check. Any authenticated user could unregister any role for their actor ID, including roles they were not authorized to hold.

## Fix

Added the same authorization check to `unregister_actor_role`.
