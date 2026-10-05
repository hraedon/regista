# Plan 032 C3 — portable baseline admission

The C1/C2 CI failures were caused by default-locale ordering in the catalog
manifest. Local PostgreSQL 15-alpine uses musl ordering even though its locale
name is en_US.utf8; Debian PostgreSQL sorts object names differently.

All eight text sort keys across six catalog aggregate orderings now explicitly
use `COLLATE "C"`. Numeric/OID equality and ordering remain locale-independent;
there are no textual inequalities or locale-formatted data in this query. SQL
deparsers describe built-in types/definitions and retain column collation names.
The manifest and fingerprint share the same query. No other catalog-derived list
is hashed. The complete record and fingerprint match the committed baseline on
Debian PostgreSQL 15, Alpine PostgreSQL 15, and Debian PostgreSQL 16 and 17.
The manifest, fingerprint and schema SQL therefore require no regeneration or
pin change: fingerprint remains
`af7d58303e81cc2c57d3c84d10ffacdbf72894a14dd6144c7ed8e3384bf367f9`.

Regression tests explicitly compare the fresh baseline record and fingerprint
with the installed committed resource. Separate template0 databases exercise
libc en_US UTF-8 and ICU und with shifted punctuation; the test first proves
their default ordering differs from C for the baseline names. Only absent
locale/provider support skips. Alpine lacks libc en_US in pg_collation, but its
ICU arm executes. Permission/creation/admission failures never skip.

CI now runs Python 3.11–3.14 on official Debian postgres:15, and Python 3.14 on
postgres:16 and postgres:17, retaining fail-hard DSN admission and full action
SHA pins. README, spec and operations identify the three tested versions.

Risk: baseline admission affects persistent schemas and fresh installs. Work is
isolated in `/projects/.worktrees/regista-f1b` on `feat/wi364-f1-promote`. Working
set: kernel catalog query, C3 regression tests, CI admission test and CI matrix,
mutation proof declaration, version guidance and Plan 032 qualification evidence.
Tracker writes/claims and private provenance attachments are not authorized;
none are asserted. This note records intent/evidence in the authorized repository.
Independent source review and the complete C2 gate set plus multi-server suites
and final-commit GitHub CI are required before reporting C3 complete.

Detailed server comparisons: [server record](032-c3-server-baselines.json).
Qualification and CI results will be recorded after all checks finish.
