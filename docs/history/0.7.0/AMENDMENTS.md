# Regista 0.7.0 Contract Amendments

**Status:** Normative for regista 0.7.0. This document amends the frozen 0.6.0
contract set only where stated below. All other 0.6.0 v6 rules remain in force.

## 1. Entity Registry

The closed v6 entity-kind registry contains eight values:

```text
work_item | project | principal | trust_domain | project_instance | workflow | spec | note
```

`note` is a non-work-item, UUID-addressed, independently readable entity. A note
event carries `workflow: null` and a required non-empty transition. Unknown kinds
remain invalid. Adding `note` changes registry membership; it does not make the
registry extensible.

This amends `docs/0.6.0/V6-ENVELOPE.md` sections 1.2, 1.6, and DD-7,
`docs/0.6.0/TRUST-DOMAIN.md` section 5.2, and
`docs/0.6.0/RECONCILIATION.md` sections 1.2 and 1.3.

## 2. Action Delegation

A `regista.action-delegation/v1` scope is exactly one of these shapes:

1. A workflow-bound work-item scope has `entity_kinds: ["work_item"]` and a
   non-empty `workflow_names` list.
2. A non-workflow note scope has `entity_kinds: ["note"]` and
   `workflow_names: []`.

Mixed kinds, workflow names on a note scope, an empty workflow axis on a
work-item scope, and every other entity kind are invalid. The terminal scope
must authorize the candidate project, entity kind, transition, and workflow axis.
Registrar delegation remains lifecycle administration and never authorizes these
event writes.

This amends `docs/0.6.0/TRUST-DOMAIN.md` section 5.11 and the action-delegation
resolution in `docs/0.6.0/RECONCILIATION.md`.

## 3. Reviewer Lineage

For a v6 review verdict, the signed envelope producer is the sole source of the
reviewer's model and model lineage. Both `producer.model` and
`producer.model_lineage` must be non-null, and the lineage must belong to the
closed model-lineage registry. The validator evaluates the same producer object
that the writer signs. Persisted verification reads it from the canonical
envelope.

The `reviewer_claims` payload member is obsolete in v6 and is rejected at writer,
validator, and verifier boundaries. It cannot override or duplicate the producer.
Concrete persisted v4 replay retains its historical payload/actor-metadata reader;
that fallback never participates in a v6 gate or assurance result.

Same-lineage acknowledgment compares the author lineage with the signed reviewer
producer lineage. A payload claim cannot manufacture a distinct-lineage result.

This supersedes the v6 `reviewer_claims` vehicle described by
`docs/0.6.0/REVIEW-VERDICTS.md` section 2.2. The 0.6.0 document remains unchanged
as the record of the released 0.6.0 contract.

## 4. Replay Bootstrap Applicability

Replay treats an externally unpinned bootstrap as the expected applicability gap
only for these exact pairs:

| Transition | Entity kind |
|---|---|
| `trust_domain_established` | `trust_domain` |
| `project_cryptographic_epoch_started` | `project` |
| `project_initialized` | `project` |

The verification result must also be `UNVERIFIABLE` solely because
`KEY_BINDING_UNRESOLVED`. A note or any other entity cannot obtain the exemption
by reusing a bootstrap transition string.

## 5. Consumer Testing Surface

`regista.testing.make_v6_keyset` and `regista.testing.open_v6_epoch` are public,
test-only helpers for consumer integration suites. They create caller-owned
throwaway Ed25519 material and execute the production genesis path. Constructing
a production `Regista` or `InMemoryRegista` handle never opens an epoch implicitly.
