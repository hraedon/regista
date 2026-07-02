-- Plan 012: Projects catalog — a shared-schema registry of regista projects.
--
-- A regista project is a Postgres schema (schema-per-project isolation, §3).
-- Before this migration there was no central catalog: projects were discovered
-- only by listing schemas, and there was no owner field.  This table is the
-- source of truth for "which projects exist" and "who owns each one."
--
-- Lives in the public schema (not the project's schema) because it is
-- cross-project state — the same softening of §3's isolation tenet that
-- Plan 022 accepted for cross-project value-references.  The table is
-- schema-qualified (public.projects) so it is reachable regardless of the
-- caller's search_path.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS leaves existing tables untouched.
-- Each project's migration runner will encounter this migration; the first
-- to run creates the table, the rest are no-ops.

CREATE TABLE IF NOT EXISTS public.projects (
    schema_name    TEXT PRIMARY KEY,
    display_name  TEXT,
    owner_actor_id TEXT,
    created_by    TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
