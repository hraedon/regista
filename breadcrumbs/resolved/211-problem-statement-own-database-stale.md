---
number: "211"
title: "Problem statement says 'own database' but v4 changed to schema-per-project"
severity: low
status: implemented
kind: bug
author: external-review
date: "2026-05-22"
tags: [spec-drift]
related: []
---

## Problem

Line 22 of `spec.md` says "each project deploys as its own isolated instance (**own database**)". The v4 amendment (line 487) explicitly replaced this with schema-per-project within a shared database, but the problem statement was never updated.

## Fix

Update line 22 to say "each project gets its own isolated Postgres schema within a shared database" or similar.
