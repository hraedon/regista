# Plan 032 F1 Stage B2 — cross-lineage review fixes

The Stage B kernel move remains unchanged. These fixes restore retained-tool
coverage, bind schema identity to its actual version and published bytes, and
correct namespace admission and its per-write cost. Package version/publication
remain F4/F5 work. No tracker transition or publication is claimed here.

## Restored retained-code coverage (H1)

Restored byte-for-byte from `84bb2ec`:

- `tests/test_identifier_gate.py`: 69 test definitions.
- `tests/test_identifier_gate_visibility.py`: 51 test definitions.
- `tests/test_publish_preflight.py`: 2 test definitions.

With parameter expansion these collect 164 nodes. The first restored run was
`164 passed, 67 subtests passed`. This environment resolves Git 2.55.0; it did
not encounter the coordinator's Git 2.43 objectmode caveat. Assertions were not
weakened or skipped. Both CI and publishing run the whole `tests/` directory.

Audited every deleted Python test against references to `scripts/`, `githooks/`,
`.github/`, `publication.toml` and the publication guards. The only additional
retained-code suite was `test_published_migrations.py`, ported below. The
`test_epoch_blocked_meta.py` reference concerns deleted `check-epoch-debt.py`;
its epoch inventory/governance was retired with the old trust implementation.
No other retained publication-tool test was found in that deletion audit.

## Schema binding (H2)

Manifest format 4 contains append-only `schema_versions` pairs, keyed by
`KERNEL_SCHEMA_VERSION`. `baseline_version` selects the current pair, and its
hash must match `baseline.schema.sql`. The code must speak that exact version.
An appended pin must arrive with the current version bump; existing entries
cannot be rewritten or removed. The original format-3 version-1 pin remains an
immutable ancestor. Workflow bytes are pinned separately and its identifier is
now `urn:regista:workflow-document:1` (L6).

`verify-baseline` reads full Git ancestry, refuses shallow or missing pin
history, refuses replacement/alternate stores, and rehashes historical pin
blobs. It detects dirty repins and already committed rewrites. This local guard
is evidence of committed schema identity, not authentication of Git history.

`verify-ledger` and `check-release` fetch PyPI's index, download every published
wheel for releases >= 0.8.0 (including yanked wheels), verify the download digest,
run the retained wheel reader and RECORD checks, and read the wheel's literal
kernel version without executing it. All wheels of a release must agree; every
published version/hash must equal a pinned pair. `check-release` also refuses
republishing or downgrading. When there is no post-cutover release the command
explicitly prints:

> no published 0.8.x release yet; PyPI binding not applicable

CI runs `verify-ledger`; the publishing workflow's existing `check-release`
now performs that PyPI verification itself. No 0.8 release was published here.

`scripts/reproduce_b2_bypass.py --revision 8c6365d --expect pass` reproduced both
old CLI commands accepting the reviewer's ALTER-and-repin, exit 0. The same
script against the fixed HEAD requires both commands to refuse, exit 1. Unit
coverage also commits the repin to ensure the history check is not merely a
working-tree dirty check. Tests cover code-version mismatch, missing/new pins,
released-pair mismatch, download mismatch, disagreeing wheels, yanked wheels,
missing kernel code and the explicit pre-publication message.

## Distribution regression vectors (M1)

The former suite had 91 test definitions. `test_distribution_vectors.py`
preserves 75 definitions, expanding to 178 nodes. The republish/downgrade test
is in `test_schema_binding.py`, so 76 old definitions have current counterparts.
The old symlink/directory migration test maps to
`test_a_symlink_or_directory_in_baseline_fails`; good/bad tree tests now use
fresh baseline files. All retained BYPASSES and ROUND_N1 shapes remain, including
retired migration paths as forbidden artifact inputs. Edited/dropped migrations
became edited/dropped pinned schema vectors. Duplicate/collision fixtures now
use real baseline names so they still exercise the intended assertion.

Retained protections include ZIP contiguity/headers/modes, tar/name/PAX rules,
RECORD content/metadata completeness, installer-view relocation, trusted backend
closure, pip and uv rebuild equality, generated metadata, committed-tree byte
binding, clean-tree requirements, replacement/graft/alternate-store rejection,
forged-object rehash/fsck, SHA-256 repositories and authoritative environment
checks. Both adversarial (2,000 examples) and positive (300 examples) name fuzz
remain. Hypothesis is restored only to development dependencies.

Fifteen definitions are retired solely with the old migration-chain data model:

| Old definition | Reason |
| --- | --- |
| `test_the_ledger_is_well_formed_and_records_the_measured_releases` | Requires the retired 0.5/0.6/0.7 migration inventory and 50-file chain. Current manifest shape/version matching has its own tests. |
| `test_frozen_violations_are_exactly_the_two_measured_in_0_6_0` | The two historical migration rewrites are no longer allowlisted. |
| `test_a_declared_unreleased_migration_passes` | No unreleased migration-chain append model exists. |
| `test_unreleased_bytes_that_differ_fail` | No unreleased migration-chain append model exists; baseline drift and version/hash mismatch remain tested. |
| `test_a_declared_unreleased_migration_that_is_missing_fails` | No unreleased migration-chain append model exists. |
| `test_bad_unreleased_declarations_fail` | Bare-number/colliding migration declarations no longer exist; their artifact paths remain refusal vectors. |
| `test_multiplicity_beyond_the_frozen_set_fails` | Migration-name hash multiplicity and the frozen exception set were deleted. |
| `test_the_frozen_set_cannot_shrink_silently` | The old migration rewrite exception set was deleted. |
| `test_a_release_that_drops_a_published_migration_fails` | No release migration-chain inventory exists; dropping a pinned schema/version is still refused. |
| `test_verify_ledger_passes_when_equal` | Compares old migration release inventory; current published schema/version equality has a replacement test. |
| `test_verify_ledger_fails_on_a_fabricated_release` | Compares the deleted manually recorded migration-release list. Current binding inspects all actual PyPI wheels. |
| `test_verify_ledger_fails_on_a_dropped_release` | Compares the deleted manually recorded migration-release list. Version/hash pairs remain append-only. |
| `test_verify_ledger_fails_loudly_on_a_release_deleted_from_pypi` | The old migration-release inventory/deletion claim is retired; removing a pair from Git history's manifest is refused even if its release disappears. |
| `test_verify_ledger_fails_on_a_rewritten_release` | Old `files/migrations` inventory equality is gone; published schema/version rewrite and digest checks have replacement tests. |
| `test_fuzz_canonical_migrations_are_accepted` | Canonical migrations are intentionally rejected now, not accepted; retained negative fuzz covers forbidden migration paths. |

## Namespace admission, performance and remaining low findings

L2 uses `pg_class`/`pg_namespace` plus `pg_proc` to recognize any relation,
sequence, view or function. It queries the explicit destination name rather than
`current_schema()`, which becomes NULL when the caller lacks USAGE. Admission
refuses old tables whether the role has namespace USAGE or not. Tests also
refuse sequence-only/function-only destinations and late legacy objects in an
already initialized schema; refusal leaves stored rows unchanged.

The first H2/L2 run failed nine new cases against the original implementation.
An additional failing-first no-USAGE case failed before the explicit-namespace
fix (`1 failed, 1 passed`). Unmodified controls subsequently passed. B2 proof
requires JUnit test-body assertion failures, excluding setup errors and skips.
`scripts/prove_b2.py` kills ten targeted mutants, including the H2 bypass,
code-version check, PyPI pairs/message, namespace occupancy and hidden objects,
late legacy writes, removed-key acceptance, ZIP collisions and RECORD hashes.
The existing `prove_f1.py` anchors remain and are rerun with all named mutants.

L3 benchmark: PostgreSQL 15 in a disposable container over loopback TCP,
CPython 3.14.8, seven alternating batches, 1,000 query iterations or 200 complete
`create_work_item` writes per batch. Median admission query cost was 594.845 µs
for the original information-schema query plus version read, 196.633 µs for
the folded catalog/version query, and 154.945 µs for a version-only control.
Median complete write cost was 6.004 ms versus 5.409 ms (about 9.9% lower).
These are local measurements, not a production latency forecast.
[samples](F1-b2-benchmark.json) and
[runner](../../scripts/benchmark_schema_guard.py) retain the experiment.
The write check remains per-operation, folded into the query each write already
needed, so changes made after checkout cannot evade refusal.

L1 restores the removed-key/accepted-schema disjointness assertion and two
controls which deliberately make the pin fail, without the 0.7 source tree.
L4 removes the branch-specific CI push trigger. L5 prints the actual `regista`
command in both example prompts. L6 uses the versioned URN described above.

## Final acceptance contract

After the last repository edit/commit, run ruff, strict mypy, the whole suite
on 3.14 and 3.11, every F1 mutant and B2 mutants, standalone mutation checks,
both examples with distinct disposable databases, `uv build`, installed-wheel
smoke in a clean venv, the authoritative distribution guard, PyPI binding, and
the HEAD bypass reproduction. Final exact outputs are reported in the response;
this document records scope and reproducible probes rather than predeclaring
that future checks passed. No fresh cross-lineage acceptance verdict or
tracker completion transition is asserted.
