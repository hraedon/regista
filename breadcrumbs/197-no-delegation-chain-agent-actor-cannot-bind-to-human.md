---
external_refs:
  plans:
  - 008
  related:
  - '100'
  - '101'
  - '172'
  - '174'
  - '196'
  tags:
  - trust-model
  - signing
  - delegation
  - on-behalf-of
  - agent-provenance
  - auth
identifier: '197'
kind: design
severity: medium
status: proposed
title: Event signing has no delegation chain — agent actor cannot be bound to authorizing
  human principal
---
## Failure mode

Substrate events carry a single `actor_id` and a single HMAC signature. There
is no first-class representation of *delegation* — the case where one
principal (an agent, a service) acts on behalf of another (a human, an
organization). For every event in the log, the only verifiable claim
substrate can make is "the holder of key K signed this payload." Everything
else about *who authorized* the action lives in `actor_metadata`, which is
self-attested (BC-101) and structurally indistinguishable from forged data.

This was originally noticed in the compliance-substrate context, where the
narrow framing was "we need to know which human reviewer performed each
transition; right now there's only one signer." The minimum-viable fix in
that framing was an additional field for the human user; the better fix was
multiple signing keys. With compliance tabled, the gap reshapes rather than
retiring:

Under agent-provenance (the direction substrate is being repositioned for),
the agent is correctly the actor — the agent is what actually executed the
tool call, edited the file, made the API request. But a regulated buyer
asking *"who is accountable for what this agent did?"* needs a verifiable
chain back to a human principal who authenticated, accepted a session scope,
and bears responsibility. Substrate today can record "agent A did X"; it
cannot record "agent A did X on behalf of human H, under session S
authenticated at time T, with scope σ" in any form an auditor can verify
without trusting `actor_metadata`.

This is the same primitive that OIDC `act`/`sub` claims and AWS STS
`AssumeRole` session tags exist to express. Substrate does not have it.

## Why this matters more under agent-provenance than under compliance

- Compliance framing: the human *is* the actor. The fix is largely
  bookkeeping (capture the user, optionally per-user keys).
- Agent-provenance framing: the agent is the actor (correctly), but
  accountability lives with a human upstream. Without delegation as a
  first-class concept, every event has a load-bearing piece of context
  (the authorizing human) that is captured only in unverified
  `actor_metadata`. For regulated buyers this is a structural gap, not
  an oversight to be papered over in the application layer.
- Schema decisions made now constrain what's possible later. Adding
  `on_behalf_of` as a typed, signed sub-object before the agent-provenance
  pivot ships is materially cheaper than retrofitting it once events are
  in production logs.

## Evidence

- `Substrate.transition()` and `Substrate.create_work_item()` take a single
  `actor_id` and a free-form `actor_metadata` dict. There is no parameter
  shape that distinguishes "the principal performing this call" from "the
  principal that authorized this call."
- spec.md §FR-15 / §17.9 define a single signer per event. Trust tier 3
  ("Actor-claimed" — `actor_metadata`) is explicitly self-attested per
  BC-101.
- compliance-substrate's workflow uses `actor_metadata.role` and a free-form
  user-ish field by convention; nothing in substrate validates or signs
  that convention.
- No session concept exists in substrate. Auth, if performed at all, is
  performed by the caller (sidecar bearer token, application-layer
  middleware) and is not represented in the event payload.

## Relationship to neighboring breadcrumbs

- **BC-101** (self-attested roles): the same root cause — substrate trusts
  the caller to honestly populate metadata. Delegation chain is the
  structured-data fix; multi-key signing (BC-196) is the cryptographic fix;
  together they retire BC-101's category of risk for the delegation case.
- **BC-196** (HMAC is symmetric — no external verifiability): orthogonal but
  composes. Delegation chain answers "who"; BC-196 answers "verifiable to
  whom." A delegation chain signed with a single symmetric key is still
  forgeable by the operator; a delegation chain where each link is signed
  by its own asymmetric key (human's key signs the session grant; agent's
  key signs the action; verifier checks both) is the defensible form.
- **Plan 008** (trust-model hardening): this is the natural home for the
  design work. Plan 008 already maps the multi-tenant trust gaps; adding
  a delegation-chain workstream alongside the existing five is consistent
  with that plan's scope.

## Proposed remedies (sketch — design belongs in a plan)

Ordered from minimum-viable to fully-defensible. (1) is the cheap fix that
unblocks the agent-provenance pivot; (2)–(4) are the path to a credible
regulated-buyer offering.

1. **Typed `on_behalf_of` sub-object on events.** Add a structured,
   signed-as-part-of-the-canonical-payload field that carries:
   - `principal_id` (the authorizing human / org)
   - `session_id` (the auth session under which the agent operates)
   - `authenticated_at` (when the human auth occurred)
   - `scope` (optional — what the session is authorized to do)

   Still signed by a single substrate key. Does not solve "is the
   principal_id honest?" but moves it from `actor_metadata` (unstructured,
   schemaless) to a first-class, schema-validated, canonical-JSON-signed
   field. Cheap, forward-compatible, unblocks the agent-provenance pivot.

2. **Optional auth-required mode.** A project-level config that causes
   substrate to reject events lacking a complete `on_behalf_of` chain
   (or with a chain whose `authenticated_at` is older than a configured
   max-age). This is the regulated-mode setting buyers will look for.

3. **Per-principal signing keys.** Each principal in the delegation chain
   independently signs the canonical payload. Verifier checks N signatures.
   Composes naturally with BC-196's pluggable-scheme work — asymmetric per-
   principal keys are the defensible form. Closes the residual "operator
   forges chain with their own key" risk.

4. **External auth-provider integration.** Accept signed assertions from an
   external IdP (OIDC ID tokens, SAML assertions, mTLS client certs) as the
   `principal_id` evidence, so the human-auth link in the chain is signed
   by an entity that is not the operator. This is what closes the loop for
   adversarial external audit.

The minimum viable shipable for the agent-provenance pivot is (1) + (2).
(3) requires BC-196 to land first. (4) is a real integration project and
belongs after the v1 demo.

## Acceptance criteria

- [ ] Event schema gains a typed, optional `on_behalf_of` sub-object with
      at minimum `principal_id`, `session_id`, `authenticated_at` fields.
- [ ] The sub-object is included in the canonical JSON that the existing
      signature covers — no separate signature path needed for v1.
- [ ] Projection / replay round-trips the field with no drift.
- [ ] `Substrate.transition()` / `create_work_item()` accept an
      `on_behalf_of` parameter and refuse to silently swallow it if
      passed alongside conflicting `actor_metadata` fields.
- [ ] Project-level config (or workflow-level — design call) can require
      the field's presence; events missing it are rejected with a clear
      error code (e.g., `DELEGATION_REQUIRED`).
- [ ] spec.md §FR-15 / §17.9 / §20 are updated to describe the delegation
      model and explicitly state which links are signed by whom under each
      mode (v1 single-signer, future multi-key).
- [ ] compliance-substrate and any agent-provenance positioning docs are
      reviewed for claims that this gap now lets them honestly make.
- [ ] (Stretch) An end-to-end example demonstrates an agent action whose
      `on_behalf_of` chain references a human authenticated via OIDC —
      even if the IdP integration is stubbed for now.

## Non-goals (for the v1 fix)

- Solving impersonation cryptographically. v1 makes delegation
  schema-visible; cryptographic enforcement is BC-196 + future work.
- Building an IdP. Substrate accepts external auth evidence; it does not
  issue it.
- Retrofitting historical events. Forward-only. Existing events without
  the field remain valid; verifiers treat missing field as "no delegation
  claim made," not "delegation claim is false."