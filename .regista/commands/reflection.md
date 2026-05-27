# /reflection — Write a Session Reflection

Write a reflection on the current session and save it to `.regista/reflections/`.

## Steps

### 1. Gather session metadata

Determine:
- **Model**: which model you are (e.g. `glm-5.1`, `claude-opus-4-7`)
- **Invocation**: `opencode`
- **Datetime**: current date and time (ISO 8601)
- **Work summary**: 2–3 sentences — what was actually accomplished this session

Look at recent worklog entries in `.regista/worklog.md` and any git changes staged or committed since session start to ground the work summary in specifics.

### 2. Write the reflection

Use the template below. All sections are required. Length is up to you — write as much as is honest, not as much as looks thorough.

---

## Template

```
---
model: <model-id>
invocation: opencode
datetime: <YYYY-MM-DDTHH:MM>
---

# Session Reflection — <YYYY-MM-DD>

**Model:** <model-id>
**Invocation:** opencode
**Date:** <YYYY-MM-DD>

**Work done:** <2–3 sentence summary — what was built, fixed, or decided>

---

## Project State

Honest assessment of where regista is. What's solid. What's fragile. What's
being carried as debt. Don't repeat the last reflection — say what's changed or
what you see that the prior reflection missed.

## Working with the User

What the collaboration felt like. What the user does well. Where things were
unclear or required rework. What questions were left unresolved. Be direct —
this is more useful than flattery.

## Friction and Improvements

Concrete friction points encountered: things that slowed work, tooling gaps,
ambiguities in the spec or codebase, conventions that conflicted. For each, suggest
a specific improvement if one is obvious.

## Observations

Unconstrained. Anything worth recording that doesn't fit above. What surprised
you. What you think the project is actually for, at a level deeper than its
stated purpose. What you'd do differently if starting over. What you're
uncertain about.
```

---

### 3. Save the file

Filename: `.regista/reflections/YYYY-MM-DD-<model-slug>-opencode.md`

Where `<model-slug>` is a short identifier: `glm-5-1`, `opus-4-7`, `sonnet-4-6`, etc.

Example: `.regista/reflections/2026-05-05-glm-5-1-opencode.md`

If a file with that name already exists (two sessions same day), append `-2`, `-3`, etc.

### 4. Report

Confirm the filename written. No summary of the reflection content — the file speaks for itself.
