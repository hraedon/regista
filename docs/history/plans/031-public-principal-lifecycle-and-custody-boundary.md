# Plan 031 — Public principal lifecycle and custody boundary

**Status:** In Progress — Phase 0 and the non-durable public contract foundation
implemented 2026-07-12: versioned types/digests, non-mutating prepare operations,
process-local one-use proof-of-possession, public facade, JSON-safe result
shapes, tests, and threat model. Durable persistence, approval, atomic commit,
effective receipts, and reconciliation remain.  
**Owner:** regista.  
**Consumers:** dossier Plan 015/024, agent-suite Plan 013, Windows Agent Suite
Setup, agent-notes, and cairn.  
**Depends:** Plans 025, 026, and 029.  
**Strategic role:** Provide a stable, transactional, UI-safe public contract for
principal enrollment, proof of possession, rotation, revocation, reconciliation,
and historical verification without requiring a web process to import private
regista modules or hold private-key bytes.

## 1. Problem

Regista has the underlying principal registry and custody mechanics, and dossier
already demonstrates enrollment/rotation/revocation workflows. The consumer
currently imports `_custody.store_private_key` and `_provision._update_key_file`
for some paths. That creates four problems:

1. private implementation details have become a cross-repository API;
2. a web process performs key generation in its own address space;
3. multi-project fan-out can partially succeed without a durable operation;
4. registration can be reported complete before the intended client proves it
   can use the private key.

Full v1 separates lifecycle truth from custody transport. Regista validates and
records the public lifecycle. A custody provider or Windows-local helper creates
and uses private material. Consumers receive only public metadata, operation
digests, challenges, and receipts.

## 2. Security properties

- No public lifecycle return type contains private key bytes, wrapped private
  keys, secret values, bearer credentials, or provider authentication material.
- Public-key registration requires proof of possession unless an explicitly
  named migration/recovery policy permits an independently approved exception.
- Human identity bindings use immutable IdP identifiers supplied by an
  authenticated consumer; display names and email never authorize.
- Every prepare/approve/commit/revoke/reconcile operation has an idempotency key,
  immutable digest, actor, subject, scope, policy version, reason, and expiry.
- Registration/rotation is atomic inside one project. Multi-project operations
  expose per-project receipts and converge safely; they do not pretend to be a
  distributed transaction.
- Historical signatures remain verifiable after rotation/revocation.
- Unknown schemes, custody modes, policy versions, operation states, or proof
  formats fail closed.
- Regista does not claim that a valid signature proves human intent against a
  compromised signing service. Reports name the custody/authorization assurance
  actually evidenced.

## 3. Public model

### Principal descriptor

- stable principal ID and kind (`human`, `agent`, `service`, `break_glass`);
- optional immutable identity binding type + digest, with display data outside
  the authorization value;
- active/superseded/revoked keys with public fingerprint, scheme, validity,
  custody mode label, and project;
- enrollment/effective/reconciliation status;
- last verified proof-of-possession and client receipt;
- policy version and required next action.

### Lifecycle operation

Closed states:

`draft`, `prepared`, `awaiting_proof`, `awaiting_approval`, `approved`,
`committing`, `committed`, `effective`, `partially_effective`, `failed`,
`expired`, `cancelled`, `repair_required`, `superseded`.

The canonical digest covers operation ID/type, principal, principal kind,
project, public key/fingerprint/scheme, custody mode, old key where applicable,
actor, requested authority, reason, policy version, created/expiry times, and
all protected options. Approval or proof for one digest cannot authorize an
edited operation.

### Proof of possession

Use a versioned challenge signed by the proposed private key. Bind the challenge
to operation ID/digest, project, principal, public key, verifier nonce, issued
and expiry times, and domain separator. Challenges are one-use and short-lived.
The verifier checks scheme, signature, exact binding, expiry, replay, and key
status before commit.

### Effective client receipt

After registry commit, the intended signer signs a second challenge through the
real client path (dossier signing provider or Windows harness helper). The
receipt identifies client type/version, key fingerprint, project, operation,
and observed time without exposing device secrets. Registry state and effective
client state remain distinct.

## 4. Public API and CLI

Exact names may change during implementation, but the supported surface must
cover:

```python
reg.principal_lifecycle.describe(principal_id, project=...)
reg.principal_lifecycle.prepare_enrollment(request, idempotency_key=...)
reg.principal_lifecycle.submit_possession(operation_id, proof)
reg.principal_lifecycle.record_approval(operation_id, approval)
reg.principal_lifecycle.commit(operation_id, expected_digest=...)
reg.principal_lifecycle.prepare_rotation(...)
reg.principal_lifecycle.prepare_revocation(...)
reg.principal_lifecycle.record_effective_receipt(operation_id, receipt)
reg.principal_lifecycle.reconcile(principal_id, project=...)
reg.principal_lifecycle.cancel(operation_id, expected_digest=...)
```

CLI equivalents emit the same versioned JSON and are suitable for Agent Suite
Setup. CLI and library call the same core; neither is a wrapper around private
consumer-specific behavior.

The public API accepts a custody provider protocol only where process-local
custody is explicitly appropriate. Its preferred web/Windows shape accepts an
already-generated public key plus possession proof. Private-key generation is
not required inside the regista process.

## 5. Custody provider contract

Provider capabilities are described, not guessed:

- generate locally/remotely;
- sign challenge;
- destroy/revoke provider object;
- export public key only;
- user-presence or step-up support;
- key non-exportability;
- provider audit receipt;
- supported principal/client kinds;
- supported Windows service/user locality;
- availability and effective-health probe.

Initial modes:

1. **Remote organizational custody** — AKV/HSM or a narrow signing service.
2. **Windows local custody** — Agent Suite Setup generates under the target
   Windows account/DPAPI context and submits only public material and proofs.
3. **File custody** — development/recovery mode with explicit support label and
   filesystem-permission checks.

`env:` is read-only and cannot custody generated material. A provider unable to
meet an operation returns a named unsupported result before registry mutation.

## 6. Work plan

### Phase 0 — Contract and threat model

#### WI-0.1 — Versioned fixtures

Define principal descriptor, lifecycle operation, possession challenge/proof,
approval, registry receipt, effective receipt, reconciliation report, and error
fixtures. Include JSON-schema or equivalent structural validation and closed
enum tests.

#### WI-0.2 — Threat model

Cover compromised dossier, compromised Windows helper, malicious admin/DBA,
provider administrator, proof replay, substitution, stale approval, weak
identity binding, duplicate active key, cross-project confusion, partial
fan-out, key loss, backend outage, rollback, and false non-repudiation claims.

### Phase 1 — Public single-project lifecycle

#### WI-1.1 — Describe and prepare

Expose stable public types and prepare enrollment/rotation/revocation without
mutation. Validate policy, current state, identity binding, scheme, and target;
return exact digest, required proof/approval, expiry, and consequences.

#### WI-1.2 — Possession and approval

Issue and consume one-use possession challenges. Record consumer-verified
step-up/approval evidence through a typed verifier/trust policy; do not accept a
free-form “approved by” string.

#### WI-1.3 — Atomic commit and signed lifecycle evidence

Commit under row/advisory locks with optimistic expected digest/state. Register
or transition exactly one key and append the corresponding signed generic
principal event atomically. Repeated idempotency keys return the same receipt.

### Phase 2 — Effective status and reconciliation

#### WI-2.1 — Client effective receipt

Verify a post-commit challenge through the intended signing client and record
effective status separately from registry commit. Expired/unreceived receipts
produce `committed_not_effective`, not success.

#### WI-2.2 — Reconciliation

Compare registry, key manifest/reference, provider public metadata, and client
receipt without retrieving private bytes. Name orphan provider key, missing
manifest ref, wrong fingerprint, extra active key, revoked-but-usable client,
unreconciled project, stale receipt, and unavailable provider.

### Phase 3 — Multi-project composition

Provide a deterministic coordinator/helper returning one child operation and
receipt per project. It supports idempotent retry and roll-forward guidance.
It never promises cross-project atomicity or deletes a committed key to simulate
rollback.

**AC:** failure at every boundary leaves a reconstructable state; retry reaches
the same intended active-key set without duplicate lifecycle evidence.

### Phase 4 — Consumer migration

- migrate dossier Plan 015 off private imports;
- migrate `regista provision-principal` to the public lifecycle core;
- add Agent Suite Setup local-helper exchange;
- migrate direct component registration paths;
- retain a compatibility facade for one release with warnings and identical
  receipts, then remove it at the declared deprecation boundary.

### Phase 5 — Qualification

- property/state-machine tests over all lifecycle transitions;
- concurrency for duplicate enrollment/rotation/revocation;
- possession replay/substitution/expiry negatives;
- Windows DPAPI user/service locality;
- AKV/HSM permission, outage, rollover, and audit receipt;
- partial multi-project failure and repair;
- historical verification across multiple rotations and revocation;
- compromised-consumer tests proving public responses/logs contain no private
  bytes or provider credentials;
- offline bundle verification of lifecycle chronology and signer binding.

## 7. Completion gate

The plan is complete when dossier and Agent Suite Setup can execute every
supported principal lifecycle journey using public APIs, without a web process
generating local-user private material or importing regista private modules;
registration, possession, approval, effectiveness, and reconciliation are
distinct evidenced states; and historical verification survives every supported
rotation, revocation, recovery, and partial-failure path.

## 8. Non-goals

- a regista web UI;
- a generic secrets manager or remote signing product;
- storing private key bytes in regista;
- silently merging IdP identities;
- cross-project distributed transactions;
- claiming protection from a compromised custody/signing authority without
  external evidence for that property.
