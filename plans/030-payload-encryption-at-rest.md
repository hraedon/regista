# Plan 030 — Encryption-at-rest primitive for event payloads

**Status:** Proposed 2026-07-08.
**Author:** GLM-5.2, cross-filed from agent-provenance Plan 010 (session-content
capture and the authorized-viewer portal).
**Strategic role:** agent-provenance v2 (Plan 010) captures session content
(prompts, responses, transcripts) as event payload. Content in the log is a
new risk surface v1 did not have — the log would hold every secret, PII
string, and internal datum that flowed through a session. cairn can encrypt at
the application layer (AES-256-GCM in the adapter, before writing to regista),
but a regista-native encryption-at-rest primitive is the cleaner seam: it keeps
encryption in the system of record, not in each consumer, and it serves any
future consumer that needs to store sensitive payloads.

This plan adds the primitive. cairn Plan 010 depends on it (or falls back to
app-layer encryption if this plan is not yet landed).

## Motivation

- **v1 payloads are hashes/digests.** No content, no encryption needed.
  v2 (cairn Plan 010) adds content payloads. The honest stance is
  "captured + encrypted; review the redaction policy."
- **regista's secrets module (`_secrets.py`)** resolves *signing keys* from
  backends (env, vault, DPAPI) but does not encrypt event payloads. This
  plan extends the same key-custody path (Plan 029) to a payload-encryption
  key.
- **One primitive, many consumers.** A regista-native primitive avoids N
  consumers each implementing their own encryption and getting it wrong.

## Decision question

**App-layer encryption (cairn) vs regista-native encryption-at-rest.**

- **App-layer (cairn):** cairn encrypts content fields before writing.
  regista stores opaque ciphertext in JSONB. Simpler for regista; each
  consumer reimplements; the digest-vs-ciphertext boundary is consumer-
  specific.
- **Regista-native:** regista offers an `encrypt_payload`/`decrypt_payload`
  API surface; the event store encrypts designated payload fields at write
  time and decrypts at read time. One implementation; the boundary is
  defined once.

**Recommendation:** regista-native, but **only if** it can stay consumer-
agnostic (regista does not know which fields are "content" — that's cairn's
schema). Concretely: regista offers a field-level encryption primitive
("encrypt this JSONB sub-tree, store ciphertext, return a handle"), and cairn
decides which fields to encrypt. This keeps the schema in cairn and the
crypto in regista.

If the regista-native primitive is not ready when cairn Plan 010 Phase 3
lands, cairn encrypts at the app layer and migrates when this plan ships.

## Work items

### WI-1 — Field-level encryption primitive
- A regista API: given a payload dict and a set of field paths, encrypt
  those fields with a content-encryption key (resolved via Plan 029 key
  custody), store ciphertext + nonce in place of the plaintext, return
  the encrypted payload. Inverse for decryption.
- Algorithm: AES-256-GCM (authenticated encryption).
- **AC:** a payload with designated content fields is stored as
  ciphertext; decryption with the key yields the original; decryption
  without the key fails; the digest of the plaintext is verifiable
  without decryption (the digest is stored outside the encrypted
  sub-tree).

### WI-2 — Schema/versioning
- The encrypted payload records `"encrypted": true, "alg": "aes-256-gcm",
  "key_id": "..."` so a reader knows to decrypt. Backward-compatible:
  unencrypted payloads (v1) read as-is.
- **AC:** an old (v1, unencrypted) event reads correctly under the new
  code; a new (encrypted) event reads as ciphertext without the key and
  as plaintext with it.

### WI-3 — Verifier integration
- The verifier (`cairn verify`) decrypts content fields when the key is
  provided (new `--content-key` flag, or reuse the witness-key path) and
  reports content integrity (digest of decrypted plaintext == `*_digest`).
  When the key is absent, the verifier reports "content not decrypted
  (no key)" — a warning, not a failure (integrity is verifiable via the
  digest without decryption).
- **AC:** a v2 bundle verifies with and without the content key; with
  the key, content digests match; without, the report names the gap.

## Dependencies

| Dependency | Plan | Status |
|------------|------|--------|
| Backend-aware key custody | regista Plan 029 | Landed |
| Consumer (cairn) | agent-provenance Plan 010 Phase 3 | Proposed |

## Out of scope

- Full-database TDE (that's a Postgres-level control, already an option
  via the `"external"` content-encryption stance in cairn Plan 010).
- Redaction (that's a consumer policy, not a regista primitive).
- Content-addressed blob storage for large transcripts (separate plan
  if transcripts are too large for JSONB).