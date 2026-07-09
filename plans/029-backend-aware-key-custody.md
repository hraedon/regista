# Plan 029 — Backend-aware principal key custody

**Status:** Implemented 2026-07-07 (Phases 1–3; Phase 4 WI-4.1 is hand-back to dossier).
**Proposed:** 2026-07-06, from a post-1.0 cross-repo review (Claude, Opus 4.8).
**Author:** Claude (Opus 4.8)
**Strategic role:** Closes the one load-bearing gap the "1.0" overnight push left
open. Plan 026 promises, as its central provenance guarantee, that a principal's
**private key lives only in the configured secret backend** and a human never
handles raw key material. The implementation delivers that guarantee **for the
`file:` backend only**. On a Vault or Azure Key Vault deployment — the backends the
suite blueprint names for the actual pilot — enrollment silently writes the freshly
generated Ed25519 private key to **plaintext on local disk** and records a `file:`
ref, regardless of configuration. This plan makes custody **backend-aware**: a new
key lands where the configured backend says it lands, or enrollment fails loudly —
it never silently falls back to disk.

## Ground truth at time of writing

- `Regista.enroll_principal(...)` (`src/regista/_api_meta.py:309`) delegates custody
  to `provision_principal` (`src/regista/_provision.py:262`), which **unconditionally**
  writes the private key to a local file (`_os.write(fd, private_key)`,
  `_provision.py:337`, mode `0o600`) and records `"secret_ref": f"file:{path}"`
  (`_provision.py:409`). It never consults the configured backend.
- `regista._secrets` is **read-only**: `resolve(ref)` supports
  `file:/env:/literal:/vault:/azure:/windows:` (`_secrets.py`). There is **no
  `store(ref, bytes)` write companion.**
- The Windows path already has a write primitive — `protect_windows_secret(data)`
  produces a DPAPI `windows:` blob (`_secrets.py:406`) — but it is **not wired into
  custody**. Even a Windows deployment writes a plaintext `.key` file today.
- Consequence: Plan 026 WI-3.3's AC ("the private key lives in the backend";
  "humans never handle raw key material") holds only for `file:`. The suite's
  regulated use case rests on Vault/AKV custody that does not exist.
- **Why the suite can't see it:** every provision/enroll test exercises `file:`
  custody (83 green). The gap is invisible because nothing asserts custody under a
  non-file backend, and nothing asserts a key is *absent* from local disk.

## Principles this plan must hold

- **The configured backend is the source of truth for where a new private key
  lands.** Custody must not hardcode `file:`.
- **No silent fallback.** A backend that regista cannot write to must produce a
  *typed, loud* error naming the ref an operator must populate — never a quiet
  write-to-disk that looks successful.
- **The private key is never returned to the caller** (preserve today's behavior).
- **Idempotency is preserved** — re-enroll of an active principal stays a no-op.
- **Surface the write-vs-operator-writes decision** (Plan 026's brief flagged this
  as the crux and it was buried; this plan's WI-1 exists to un-bury it).

## Phase 1 — A write side for the secret backend

### WI-1.1 — `secrets.store(ref, data)` provider protocol
- Add a `store(self, ref: str, data: bytes) -> str` method to the `SecretProvider`
  protocol, symmetric with `resolve`. Returns the canonical ref that `resolve` will
  later read (may differ from the input, e.g. a Vault version).
- `file:` — write `0o600`, atomic (temp + rename), return `file:<path>`. This is the
  logic **extracted** from `_provision.py`, not duplicated.
- `windows:` — call `protect_windows_secret(data)`, return `windows:<blob>`. Wire the
  existing DPAPI primitive.
- `env:` / `literal:` — **unsupported for write**: raise a typed
  `SecretWriteUnsupported` (you cannot custody a generated key into a literal or a
  read-only env var). Fail loud.

### WI-1.2 — Vault / Azure write, or an explicit operator-writes seam **(the crux)**
- **Decide and surface**, per backend:
  - If the deployment's Vault/AKV token carries write scope, implement the write
    (Vault KV v2 `PUT`, Azure `set_secret`) and return the resulting ref.
  - If regista is intentionally read-only against the backend (operator populates
    secrets out-of-band), `store` raises `SecretWriteExternal` carrying the exact ref
    the operator must populate and the public key to register — so enrollment can
    still record the ref without ever holding the private key on regista's host.
- This decision is the deliverable of this WI. Document it in `docs/suite-config.md`
  §3 next to the resolve table. **Do not let it default silently to `file:`.**

## Phase 2 — Make custody backend-aware

### WI-2.1 — Shared custody helper
- Extract the keypair-generate → backend-write → ref-record sequence out of
  `provision_principal` into one helper (e.g. `_custody.store_private_key`). Both
  `provision_principal` and any future caller use it. It resolves the configured
  backend and calls `secrets.store` — it does **not** hardcode a path.

### WI-2.2 — Backend selection from config
- Provisioning/enrollment honor a configured backend (e.g. `REGISTA_SECRET_BACKEND`,
  or a documented key-ref-prefix policy) via `regista._config`. `private_key_dir`
  remains meaningful only for `file:`. Record the ref `store` returns — never a
  synthesized `file:` string.
- **AC:** with the backend set to `windows:` (or a mocked vault), `enroll_principal`
  writes **no** plaintext `.key` file to local disk, and the recorded `secret_ref`
  carries the configured scheme.

## Phase 3 — Prove it, and prevent silent regression

### WI-3.1 — Custody round-trip tests per writable backend
- `file:` (always), `windows:` (where DPAPI available; else skip with reason), and
  vault via testcontainer or a fake write-provider. Each: enroll → assert
  `resolve(recorded_ref)` returns a key that verifies against the registered public
  key; assert the private key is **never** in `enroll_principal`'s return value.
- **The test that would have caught this gap:** under a non-`file:` backend, assert
  the local principals dir contains **no** new `.key` file.

### WI-3.2 — `doctor` custody-consistency check
- `regista doctor` warns when a principal's recorded `secret_ref` scheme does not
  match the configured backend (e.g. a `file:` ref on a Vault deployment) — the
  operator-visible signal that a key landed in the wrong place.

## Phase 4 — Downstream verification (hand-back)

### WI-4.1 — dossier Plan 015 key UX against a real backend
- Re-run dossier's key-lifecycle UX end-to-end against live regista + Postgres + a
  **non-file** backend. Verify: the human never touches key material **and** no
  private key appears on any host's local disk. This is the acceptance the
  completion plan's Task 2 deferred; it only becomes true once WI-2 lands.

## Sequencing & notes

- WI-1.2 is the gate — the write-vs-operator-writes decision drives everything after
  it. Make it first and make it visible.
- **Not in scope:** HSM / hardware-token-held keys, threshold/multi-sig (Plan 026's
  existing non-goals stand).
- **Blast radius:** provisioning and enrollment only; the signing/verify read path
  already uses `resolve` and is unaffected. Existing `file:`-backend deployments
  keep working unchanged (file remains a first-class writable backend).
