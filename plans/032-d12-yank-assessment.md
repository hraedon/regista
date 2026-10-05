# D12 older-release yank assessment — 2026-10-05

D12 (ruled 2026-10-04): **yank older releases where possible; non-blocking for
0.8.0.** This is an assessment, not authorization or an executed yank. No PyPI
mutation, advisory, upload or tag was made. Retiring a subsystem in 0.8.0 does
not fix old packages, and a yank does not delete artifacts or invalidate installed
copies/exact pins. Preserve old environments and dumps before changing anything.

## Evidence and limits

Rechecked the [regista-hraedon PyPI JSON](https://pypi.org/pypi/regista-hraedon/json)
on 2026-10-05: nine releases, each with one wheel and one sdist, all **unyanked**.
Downloaded every published wheel, checked its SHA-256 against that metadata, and
read the actual shipped source. Artifact hashes below bind the static assessment;
it does not equate a local tag with uploaded bytes. Tracker WI-351–362 bodies and
history supply the confirmed finding mechanisms and qualifications. This pass did
not re-exploit old versions; reachability below is static source assessment and
explicitly distinguishes a shipped mechanism from a later offline consumer.

The source commands were:

```bash
agent-notes work-item find --path /projects/regista --text SEC --limit 100 --json
agent-notes work-item find --path /projects/regista --status open --limit 500 --json
agent-notes work-item get WI-351 --with-body --path /projects/regista --json
# Repeat get for WI-352 through WI-362, read-only; no tracker writes.
git log --all --oneline --grep='bundle.*v3' --grep='WI-260' --grep='WI-302'
```

For each release, fetch its `bdist_wheel` URL from PyPI JSON, assert
`hashlib.sha256(blob).hexdigest() == file['digests']['sha256']`, and inspect the
zip member source without importing or executing it. These are published source
inspections and tracker finding summaries, not claims of a new security test run.

## SEC finding reachability

| Finding / tracker | Published reachability and qualification |
| --- | --- |
| SEC-01 / WI-351 | 0.6.0–0.7.2 contain `_action_delegation._issuer_trust_evidence` with the optional-referent guard and fallthrough; issuer evidence incompleteness/supersession is not fully enforced. Requires previously accepted issuer credentials; live/project-chain paths remain relevant. Bundle-v3 credential export is a **later unshipped** path, not an affected published interface. No action-delegation module in 0.5.x. |
| SEC-02 / WI-352 | 0.6.0–0.7.2 ship detached `root_signature_input(payload)` without unique event context and the current-root threshold verifier. Root/registrar governance ceremony path exists. Not an unauthenticated outsider path. Absent in 0.5.x. |
| SEC-03 / WI-353 | 0.6.0–0.7.2 trust replay stores key bytes/status without retaining validity intervals. The finding's `_trust_log_export_material`/externally-pinned bundle-v3 consumer is post-0.7.2 and **absent from every published wheel**. Online verification enforces windows; do not claim the later offline verdict was demonstrated on published versions. 0.5.x lacks that trust replay. |
| SEC-04 / WI-354 | 0.6.0–0.7.2 ship trust-log replay/admission timestamp and endpoint logic. Tracker qualifies replay backdating as requiring direct database changes plus registrar authority; public admission checks the current clock. No claim of a former registrar acting through the public API alone. Absent in 0.5.x. |
| SEC-05 | No separately filed SEC-05 finding was returned by the SEC tracker census. A historical reproduction filename mentioning 05 is not a finding or affected-version proof. No invented assessment. |
| SEC-06 / WI-357 | `_estate_catalog` and its genesis-root verification helper are **absent from all nine published wheels**. The tracker finding concerns later private-library code and warns the CLI was already constrained. Not a published-release yank reason by itself. |
| SEC-07 / WI-358 | 0.6.0–0.7.2 compare action credential windows against event `occurred_at`. Caller-facing APIs set database/application time; the finding requires a private writer and existing signing/append authority. An audit-semantics limitation, not an unauthenticated escalation. Absent in 0.5.x. |
| SEC-08 / WI-356 | 0.6.0–0.7.2 trust state lacks a canonical registration/kind map and enrollment independently supplies kind. Registration parser alone does not enforce registration before enrollment. Tracker says no current gate turns on this trust-log kind. Absent in 0.5.x. |
| SEC-09 / WI-359 | All nine ship lifecycle `_operation()` returning cached state. Later versions add row locking but decisions still use cached state; approval updates are not adequately conditional. Multi-instance canceled-operation handling remains a correctness concern. 0.5-era code is an earlier implementation of the same stale-state class, not asserted byte-identical to the reported 0.7-era reproduction. |
| SEC-10 / WI-360 | All nine trust caller-provided approval attribution; 0.6/0.7 expose `approval_verifier=None` and record unverified evidence. Old 0.5 code predates that verifier option and provides weaker caller trust. The finding requires an already authorized lifecycle caller; later release-qualification gates fail closed without verifier evidence. |
| SEC-11 / WI-355 | All nine ship assurance over row/dataclass fields rather than verified canonical history. Requires database write capability; replay provides detection in later v6 paths. It affects callers consulting assurance without verification and is not proof signatures themselves can be forged. |
| SEC-12 / WI-361 | Trust-log export and estate-catalog offline readers are **absent from published wheels**; those later uncapped readers are not a published reachability claim. Published bundle readers have their own historical issues, assessed separately below. |
| SEC-13 / WI-362 | The rotated-root record shape is present in 0.6/0.7, but the identified export/catalog `signer_id` verification consumers are **absent from published wheels**. Not a demonstrated published attribution-forgery interface; underlying identity limitation only. |

## Other findings and retained limitations

All nine wheels still contain bundle v1/v2 verification: v1 may skip event
signature enforcement; bundle membership/completeness relies on an unkeyed manifest
hash. The post-0.7.2 bundle-v3 work (history c6b9839/bb19674/dc03daa, WI-289) addresses
these claims but was **not published** in those wheels. Per-event signatures do
not independently authenticate an entire v1/v2 bundle's membership.

WI-260's old migration runner holds one pool connection while requiring another;
a single-connection pool can starve initialization. It is a retained historical
operational limitation across the old writer line, not a 0.8 migration path.
WI-259/261 describe old bundle export/live-versus-archived coverage and stale output
on rejection; preserve the artifact and matching environment without claiming
complete recoverable history solely from a bundle. WI-268's old revoked-key policy,
WI-342's CLI-only genesis trust-reference checks, WI-344's unauthenticated gate
reports, and WI-346's trust-log entity binding remain reasons to avoid treating
old policy/report claims as authentication. These paths and policy concepts are
removed in 0.8.0. Their presence is not proof every old artifact reaches every
later exact reproduction; the SEC table and published source are the bounded
assessment, not a blanket assertion that all tracker reports affected all versions.

WI-247/328/341 concern leak guards, diagnostics/test flakiness and schema cleanup;
they are qualification weaknesses rather than evidence of a published runtime
exploit. Local credential incidents, private deployment attribution, and consumer
pin hazards are deployment-specific and are not assigned package-wide CVEs or
republished here. Historical HMAC cannot establish asymmetric non-repudiation;
transport/storage/key protection remains an operator concern.

## Recommendation for every Regista release

| Published version | Known shipped concerns | Recommendation | Published wheel SHA-256 |
| --- | --- | --- | --- |
| 0.5.1 | Old lifecycle cached-state/approval trust (SEC-09/10 mechanisms), unverified assurance rows (SEC-11), bundle v1/v2 authenticity/completeness gaps, migration pool starvation (WI-260); SEC-01/02/03/04/07/08 trust/delegation paths absent. | Yank wheel and sdist when separately authorized. | `451d42c739b0f8a15a73d469832e5bcd60bab1fb29129318d83748375b27bbae` |
| 0.5.2 | Old lifecycle cached-state/approval trust (SEC-09/10 mechanisms), unverified assurance rows (SEC-11), bundle v1/v2 authenticity/completeness gaps, migration pool starvation (WI-260); SEC-01/02/03/04/07/08 trust/delegation paths absent. | Yank wheel and sdist when separately authorized. | `e0c99d9ed82162811ea6f1219b9460f495c41848c11437779665537e45fdacd1` |
| 0.5.3 | Old lifecycle cached-state/approval trust (SEC-09/10 mechanisms), unverified assurance rows (SEC-11), bundle v1/v2 authenticity/completeness gaps, migration pool starvation (WI-260); SEC-01/02/03/04/07/08 trust/delegation paths absent. | Yank wheel and sdist when separately authorized. | `2b6df95b0ce07d0da21c68db83c7ca29252183c51e14b54bb09b81da08929b8a` |
| 0.5.4 | Old lifecycle cached-state/approval trust (SEC-09/10 mechanisms), unverified assurance rows (SEC-11), bundle v1/v2 authenticity/completeness gaps, migration pool starvation (WI-260); SEC-01/02/03/04/07/08 trust/delegation paths absent. | Yank wheel and sdist when separately authorized. | `b4d3890fc9f20f84ce629abf3bad9664f3940819868643dc83c2a48b0cd7c1a6` |
| 0.5.5 | Old lifecycle cached-state/approval trust (SEC-09/10 mechanisms), unverified assurance rows (SEC-11), bundle v1/v2 authenticity/completeness gaps, migration pool starvation (WI-260); SEC-01/02/03/04/07/08 trust/delegation paths absent. | Yank wheel and sdist when separately authorized. | `5e87ae381aab93b03ff75c6efac544401e66a9544d1770d8ff0842b5dedfcf60` |
| 0.6.0 | Old lifecycle cached-state/approval trust (SEC-09/10 mechanisms), unverified assurance rows (SEC-11), bundle v1/v2 authenticity/completeness gaps, migration pool starvation (WI-260); SEC-01/02/04/07/08 mechanisms in trust/delegation paths; SEC-03 replay drops key windows (published offline export consumer absent). | Yank wheel and sdist when separately authorized. | `28b539ee292773a24a0d225b1392185d9a73d2df82944ad503b318c05b0fa5d6` |
| 0.7.0 | Old lifecycle cached-state/approval trust (SEC-09/10 mechanisms), unverified assurance rows (SEC-11), bundle v1/v2 authenticity/completeness gaps, migration pool starvation (WI-260); SEC-01/02/04/07/08 mechanisms in trust/delegation paths; SEC-03 replay drops key windows (published offline export consumer absent). | Yank wheel and sdist when separately authorized. | `0689e44815ebbfc2acfeb7b1135aad426c3d235f60c5aea1a5b246b2949f9352` |
| 0.7.1 | Old lifecycle cached-state/approval trust (SEC-09/10 mechanisms), unverified assurance rows (SEC-11), bundle v1/v2 authenticity/completeness gaps, migration pool starvation (WI-260); SEC-01/02/04/07/08 mechanisms in trust/delegation paths; SEC-03 replay drops key windows (published offline export consumer absent). | Yank wheel and sdist when separately authorized. | `a5ea7f27eedfd4b59cbd20e0d9cf652b871268443b9a990ac62cd664d3d3f227` |
| 0.7.2 | Old lifecycle cached-state/approval trust (SEC-09/10 mechanisms), unverified assurance rows (SEC-11), bundle v1/v2 authenticity/completeness gaps, migration pool starvation (WI-260); SEC-01/02/04/07/08 mechanisms in trust/delegation paths; SEC-03 replay drops key windows (published offline export consumer absent). | Yank wheel and sdist when separately authorized. | `5c34cfedcf02c085c2197f4140b70c49a02e2b264432855920d95acd3541df1d` |

Yank both file types for each version when the owner separately approves it,
using a reason pointing to the 0.8 scope break, preservation guidance and known
legacy verification/lifecycle limitations. Do not describe removed code as fixed
in the old release. Owners should account for deliberately pinned private
consumers; yanking is non-blocking and 0.8.0 itself is the due diligence.

## The pre-rename `substrate` name

The [current substrate PyPI JSON](https://pypi.org/pypi/substrate/json) belongs to
an unrelated **Substrate Python SDK** (author `vprtwn`, description points to
substrate.run; releases use date-like versions). This repository's historical
`v0.4.0-pre-rename` metadata instead names `substrate` version `0.3.0` and describes
the PostgreSQL coordination plane. PyPI currently has no such 0.x version at that
name. We cannot infer that it was never uploaded/deleted from current metadata.

Every currently published version of that unrelated package is listed below,
with the same recommendation: **no Regista-attributed defect is established;
do not request a yank of another project's files**. This is not a security audit
or general endorsement of that SDK.

| Current `substrate` version | Known Regista defects | Yank recommendation |
| --- | --- | --- |
| 120240315.0.0 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240315.0.1 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240403.0.1 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240403.0.2 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240405.0.2 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240405.0.3 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240411.0.4 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240411.0.5 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240416.0.5 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240416.0.6 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240416.0.7 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240416.0.8 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240416.0.9 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240418.0.10 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240430.0.0 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240430.0.1 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240502.0.0 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240502.0.1 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240502.0.2 | Unrelated project; none attributed. | No Regista-based yank. |
| 120240502.0.3 | Unrelated project; none attributed. | No Regista-based yank. |
| 220240509.0.0 | Unrelated project; none attributed. | No Regista-based yank. |
| 220240530.0.0 | Unrelated project; none attributed. | No Regista-based yank. |
| 220240612.0.0 | Unrelated project; none attributed. | No Regista-based yank. |
| 220240617.0.0 | Unrelated project; none attributed. | No Regista-based yank. |
| 220240617.0.1 | Unrelated project; none attributed. | No Regista-based yank. |
| 220240617.0.2 | Unrelated project; none attributed. | No Regista-based yank. |
| 220240617.0.3 | Unrelated project; none attributed. | No Regista-based yank. |
| 220240617.1.3 | Unrelated project; none attributed. | No Regista-based yank. |
| 220240617.1.4 | Unrelated project; none attributed. | No Regista-based yank. |
| 220240617.1.5 | Unrelated project; none attributed. | No Regista-based yank. |
| 220240617.1.6 | Unrelated project; none attributed. | No Regista-based yank. |
| 220240617.1.7 | Unrelated project; none attributed. | No Regista-based yank. |
| 220240617.1.8 | Unrelated project; none attributed. | No Regista-based yank. |

No version was yanked, and no owner-side PyPI access was exercised.
