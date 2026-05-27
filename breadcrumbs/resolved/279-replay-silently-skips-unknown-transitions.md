---
number: "279"
title: Replay silently skips unknown transitions without warning
severity: medium
status: implemented
kind: bug
author: comprehensive-review
date: "2026-05-27"
tags: [replay]
related: []
---

When replay encounters a transition event whose name matches no defined
transition in the workflow, it silently continues without incrementing the
warning count. While this is correct for events appended via `append_event()`
(which bypass workflow validation), truly unknown transitions due to data
corruption would also be silently swallowed.

At minimum, unknown transitions should increment the warning counter. Ideally,
replay should distinguish between known-bypass transitions (system events,
reserved transitions) and genuinely unrecognized names.
