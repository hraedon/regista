---
model: glm-5.1
invocation: opencode
datetime: 2026-05-06T00:05
---

# Session Reflection — 2026-05-06

**Model:** glm-5.1
**Invocation:** opencode
**Date:** 2026-05-06

**Work done:** Implemented Phase 3 of regista: actor → allowed_roles enforcement (FR-24), continue-on-revoked replay flag (FR-25), update_not_before API (FR-26), custom field validation at transitions (FR-27), and E2E integration tests. Resolved §16 decision items. Updated spec to v4. 111 tests passing.

---

## Project State

The project is in strong shape. All three phases (MVP, Phase 2, Phase 3) are implemented with zero open breadcrumbs. The spec is authoritative and v4 matches the implementation. 111 tests + 3 benchmarks cover stated guarantees across 11 test files.

The codebase is clean — no debt I can identify. The only remaining deferred items are genuine future work (OIDC, federated UI, month-partitioning, workflow file composition) that require external requirements or scale triggers.

One observation: the test suite is getting large enough (111 tests in ~34s) that test organization matters. The E2E test file was a good addition — it exercises the system as a whole rather than individual features. More E2E scenarios would be valuable as the system gets used for real workflows.

## Working with the User

The user was clear and decisive. They chose "all three" for both batches of work, which gave me a defined scope to execute against without ambiguity. The two-batch approach (first batch: actor roles + replay flag + §16 decisions, second batch: update_not_before + field validation + E2E tests) was natural — I delivered the first set, then the user asked what else would be useful, and I proposed three more items which they approved.

No rework was needed on the user's direction. The test failures I hit were all my own mistakes (wrong match strings, wrong assertions about claim attempt numbering, wrong assumptions about which transitions allow which roles).

## Friction and Improvements

**Test iteration speed.** Running the full 111-test suite takes ~34s. During development I was running subsets, which is fine, but the full-suite runs add up. No specific improvement to suggest beyond what's standard.

**The `claim_acquired` same-actor path is subtle.** When `acquire_claim` is called by the same actor who already holds the claim, it silently extends the TTL without emitting an event or incrementing the attempt number. This is correct but surprised me during the E2E test — I expected attempt_number=2 after a claim+transition+re-claim cycle. The transition releases the claim (delete), so the next acquire starts fresh at attempt 1. This is by design (clean release = new attempt cycle) but worth noting for future test writers.

**Field validation at transition time was a gap I should have caught sooner.** The spec says custom fields have types and are validated (FR-02, FR-17), but the update path through `custom_fields_update` in transitions wasn't validated. The fix was straightforward once identified. A systematic audit of "which spec guarantees are checked at creation but not at mutation" would be useful.

## Observations

The regista is now a complete coordination library for agent pipelines. With FR-24 (actor roles) and FR-27 (field validation at transitions), the enforcement story is solid: actors authenticate via HMAC, roles are enforced if registered, custom field types are validated on both creation and update, and the event log provides a signed audit trail.

The most interesting remaining work isn't code — it's operational. The first real workflow deployed on regista will surface UX gaps that no amount of spec review can predict. The E2E test gets at this, but it's still a test, not a production workload.

If I were starting over, I'd have written the E2E test first, before any Phase 3 features. It would have caught the "claim attempt numbering after transition" subtlety earlier and provided a natural integration point for each new feature. Instead, I added features first and the E2E test last, which meant I had to fix the E2E test's assumptions about claim behavior.
