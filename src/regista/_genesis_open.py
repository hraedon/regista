"""WI-325: assemble a per-project v6 genesis from LIVE trust-log facts.

``_genesis.append_v6_genesis`` is the writer. It takes a finished, ready-to-sign
``project_initialized`` envelope and it is *strict about shape*: every load-bearing
field, the closed ``bootstrap_key_acceptance`` key set, the digest grammar of
``trust_event_hash`` and of the three ``trust_log_checkpoint`` members. What it
cannot do — because it never opens the trust log — is decide whether any of those
well-formed values are **true**. ``_genesis.py`` never queries ``regista_trust``, so
before this module a project could be opened with a self-consistent but entirely
fabricated trust reference: an unenrolled principal, a revoked key, a
``trust_event_hash`` naming nothing, a checkpoint naming a head that never existed.

This module is where those values come from, and it resolves every one of them from
the verified trust-log chain walk rather than from a projection row or an operator
flag:

* :func:`resolve_enrolled_key` — the principal's ``principal_key_enrolled`` event,
  found in :func:`~regista._trust_log_writer.verify_trust_log_chain`'s output, with
  its key ACTIVE in the replayed state, its public key byte-equal to the material the
  event enrolled, its fingerprint recomputed from those bytes, and its validity window
  containing the genesis instant. ``principal_keys`` is consulted only as a
  cross-check: a row that disagrees with the chain is a refusal, and an absent row is
  not (§5.9 rule 1 — the projection is never the authority).
* :func:`derive_trust_log_checkpoint` — the ``{checkpoint_seq, head_event_hash,
  document_digest}`` triplet, from the head the same verified walk reached.
* :func:`load_gate_evidence` — the EPOCH-RESET §5 first-write verdict, as the
  ``agent-suite genesis-gate --json`` report, bound to this store fingerprint and this
  project. ``initialize_epoch(..., gate_passed=True)`` is never asserted without it.
* :func:`build_project_initialized_envelope` — the envelope itself, which until now
  existed only in ``tests/_v6_fixtures.py``.

**Where each guarantee lives.** Everything here is CLI-side by nature: it is the
*assembly* of the inputs, and assembly cannot be writer-side because the writer's
argument is the finished envelope. What the writer re-verifies independently, on the
signed bytes, in the same transaction as the insert: the empty-store precondition
(``first_write_admission``), the complete envelope shape, the acceptance's internal
consistency against the resolved signing key, and the signature under the bound
Ed25519 public key. What ONLY this module establishes: that the trust reference in
those signed bytes corresponds to the live trust log. A caller that builds an envelope
by hand and calls ``initialize_epoch`` directly still gets the writer's guarantees and
does NOT get these — which is why ``regista genesis init`` is the supported path.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
import subprocess
import uuid as _uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, NoReturn

from ._connection import DictConn
from ._errors import ErrorCode, RegistaError

#: The default project-local scopes granted to the bootstrap key by its own
#: acceptance. ``project`` is mandatory (``_genesis._validate_bootstrap_acceptance``
#: refuses an acceptance that does not authorise project genesis) and the other three
#: are what a freshly opened project needs in order to be usable at all: accept a
#: second writer's key, register a workflow, create a work item. Narrower is
#: expressible with ``--scope-entity-kind``; wider is the operator's explicit choice,
#: never a default.
DEFAULT_SCOPE_ENTITY_KINDS: Final[tuple[str, ...]] = (
    "project",
    "principal",
    "workflow",
    "work_item",
)

#: The ``agent-suite genesis-gate --json`` report versions this code understands. An
#: unrecognised version is a refusal, not a best-effort parse: a v2 report could move
#: ``epoch_may_open``'s meaning, and reading it as v1 would turn a BLOCKED gate into a
#: PASS. Fail closed on the version, always.
SUPPORTED_GATE_REPORT_VERSIONS: Final[frozenset[int]] = frozenset({1})
_GATE_REQUIRED_PROBE_CHECKS: Final[Mapping[str, frozenset[str]]] = {
    "regista": frozenset(
        {
            "regista.store_invariant_measurements",
            "regista.load_bearing_fields_refused",
            "regista.closed_lineage_registry",
            "regista.first_write_admission",
            "regista.actor_boundary_signing",
        }
    ),
    "cairn": frozenset(
        {
            "cairn.runtime_model_observed",
            "cairn.unavailable_model_named",
            "cairn.observation_failure_nonblocking",
        }
    ),
    "agent-notes": frozenset({"agent_notes.session_identity_resolvable"}),
}
_GATE_REQUIRED_BEHAVIORAL_FINDINGS: Final[frozenset[str]] = frozenset(
    check_id
    for component, check_ids in _GATE_REQUIRED_PROBE_CHECKS.items()
    for check_id in check_ids
    if check_id != "regista.store_invariant_measurements"
)
_GATE_REPORT_KEYS = frozenset(
    {"report_version", "kind", "ok", "epoch_may_open", "binding", "findings", "probes"}
)
_GATE_BINDING_KEYS = frozenset(
    {
        "expected_store_fingerprint",
        "reported_store_fingerprint",
        "project",
        "observation_snapshot",
    }
)
_GATE_FINDING_KEYS = frozenset({"check_id", "status", "detail"})
_PROBE_REPORT_KEYS = frozenset({"report_version", "kind", "ok", "probes"})
_PROBE_RESULT_KEYS = frozenset({"component", "status", "ok", "detail", "checks"})
_MEASUREMENT_KEYS = frozenset({"id", "status", "store_fingerprint", "projects", "errors"})
_PROJECT_MEASUREMENT_KEYS = frozenset(
    {
        "project",
        "event_count",
        "declared_lineage_event_count",
        "lineage_coverage",
        "distinct_lineage_tokens",
        "unresolvable_lineage_tokens",
        "unresolvable_lineage_value_count",
        "ambiguous_lineage_event_count",
        "scheme_counts",
        "undeclared_agent_author_event_count",
        "model_observation_status_counts",
        "snapshot_id",
    }
)
_PG_SNAPSHOT_RE = re.compile(r"pg:[0-9]+:[0-9]+:(?:[0-9]+(?:,[0-9]+)*)?")

#: The type tag on the locally derived, unsigned trust-log observation whose digest
#: fills ``trust_log_checkpoint.document_digest`` when no PUBLISHED checkpoint document
#: is supplied. Deliberately NOT ``regista.trust-checkpoint``: a §4.3 checkpoint is a
#: signed, published, sequence-numbered document, and minting one of those here — with
#: no signer and no publication — would be exactly the "unobserved claim in a field
#: that reads as observed" EPOCH-RESET §6 rule 3 forbids. This document says only what
#: it is: one process's verified observation of the trust log at one instant.
TRUST_LOG_OBSERVATION_TYPE: Final[str] = "regista.trust-log-observation"
TRUST_CHECKPOINT_TYPE: Final[str] = "regista.trust-checkpoint"
TRUST_CHECKPOINT_SIGNATURE_DOMAIN: Final[bytes] = b"regista.trust-checkpoint.v1\x00"

_CHECKPOINT_KEYS = frozenset(
    {
        "type",
        "version",
        "trust_domain_id",
        "trust_domain_core_digest",
        "checkpoint_seq",
        "trust_log",
        "root_governance",
        "active_root_fingerprints",
        "prev_checkpoint_digest",
        "prev_commit",
        "created_at",
        "root_signatures",
        "countersignatures",
        "anchors",
    }
)
_CHECKPOINT_LOG_KEYS = frozenset(
    {
        "project_instance_id",
        "event_count",
        "genesis_event_hash",
        "head_event_hash",
        "max_global_seq",
    }
)
_CHECKPOINT_GOVERNANCE_KEYS = frozenset({"mode", "threshold", "signer_count"})
_ROOT_SIGNATURE_KEYS = frozenset({"signer_id", "fingerprint", "signature"})
_PUBLICATION_INDEX_KEYS = frozenset({"type", "version", "entries"})
_PUBLICATION_ENTRY_KEYS = frozenset({"path", "sha256", "published_at", "prev_commit"})
_GIT_COMMIT_RE = re.compile(r"[0-9a-f]{40}")

_ENROLLED = "principal_key_enrolled"
_ROTATED = "principal_key_rotated"


def _refuse(code: ErrorCode, message: str, reason: str, **detail: Any) -> NoReturn:
    raise RegistaError(code, message, {"reason": reason, **detail})


def _unverified(message: str, reason: str, **detail: Any) -> NoReturn:
    _refuse(ErrorCode.GENESIS_TRUST_REFERENCE_UNVERIFIED, message, reason, **detail)


def _fingerprint_of(public_key: bytes) -> str:
    return "ed25519:sha256:" + hashlib.sha256(public_key).hexdigest()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _checkpoint_signature_input(document: Mapping[str, Any]) -> bytes:
    from ._jcs import canonicalize

    core = {
        key: value
        for key, value in document.items()
        if key not in {"signature", "root_signatures", "countersignatures", "anchors"}
    }
    canonical = canonicalize(core)
    return TRUST_CHECKPOINT_SIGNATURE_DOMAIN + struct.pack(">Q", len(canonical)) + canonical


def _require_digest_text(value: Any, field: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        _unverified(
            f"the checkpoint's {field} must be sha256:<64 lowercase hex>",
            "checkpoint_field_invalid",
            field=field,
        )


def _git(repo: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ("git", "-C", str(repo), *args),
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        _unverified(
            "could not verify the checkpoint publication repository",
            "checkpoint_publication_git_error",
            error_type=type(exc).__name__,
        )
    if completed.returncode != 0:
        _unverified(
            "the checkpoint publication repository did not satisfy the requested git check",
            "checkpoint_publication_git_check_failed",
            operation=args[0] if args else "git",
            exit_code=completed.returncode,
        )
    return completed.stdout.strip()


def _index_entries(raw: Any) -> list[Mapping[str, Any]]:
    if not isinstance(raw, Mapping) or set(raw) != _PUBLICATION_INDEX_KEYS:
        _unverified(
            "publication index.json must be a closed regista.publication-index/v1 object",
            "checkpoint_publication_index_malformed",
        )
    if (
        raw.get("type") != "regista.publication-index"
        or type(raw.get("version")) is not int
        or raw.get("version") != 1
    ):
        _unverified(
            "publication index.json has an unsupported type or version",
            "checkpoint_publication_index_malformed",
        )
    entries = raw.get("entries")
    if not isinstance(entries, list) or not all(isinstance(entry, Mapping) for entry in entries):
        _unverified(
            "publication index.json entries must be an array of objects",
            "checkpoint_publication_index_malformed",
        )
    assert isinstance(entries, list)
    return [entry for entry in entries if isinstance(entry, Mapping)]


def _verify_checkpoint_publication(
    path: Path,
    document_digest: str,
    trust_domain_id: str,
    checkpoint_seq: int,
    document_prev_commit: str | None,
    *,
    publication_repo: str | None,
    publication_commit: str | None,
) -> str:
    if publication_repo is None or publication_commit is None:
        _unverified(
            "a published checkpoint requires --trust-publication-repo and an out-of-band "
            "--trust-publication-commit pin",
            "checkpoint_publication_pin_absent",
        )
    if _GIT_COMMIT_RE.fullmatch(publication_commit) is None:
        _unverified(
            "--trust-publication-commit must be a full lowercase 40-hex git commit",
            "checkpoint_publication_commit_invalid",
        )
    repo = Path(publication_repo).resolve()
    root = Path(_git(repo, "rev-parse", "--show-toplevel")).resolve()
    if root != repo:
        _unverified(
            "--trust-publication-repo must name the repository root",
            "checkpoint_publication_root_mismatch",
            stated=str(repo),
            actual=str(root),
        )
    try:
        relative = path.resolve().relative_to(repo).as_posix()
    except ValueError:
        _unverified(
            "the checkpoint file is outside --trust-publication-repo",
            "checkpoint_outside_publication_repo",
        )
    expected_prefix = f"checkpoints/{trust_domain_id}/"
    if not relative.startswith(expected_prefix):
        _unverified(
            "the checkpoint is not in the §4.2 checkpoints/<trust-domain-id>/ layout",
            "checkpoint_publication_layout_invalid",
            path=relative,
        )
    filename = Path(relative).name
    if not filename.startswith(f"{checkpoint_seq:08d}-") or not filename.endswith(".json"):
        _unverified(
            "the checkpoint filename does not carry its zero-padded checkpoint_seq",
            "checkpoint_publication_filename_invalid",
            path=relative,
        )

    head = _git(repo, "rev-parse", "HEAD")
    _git(repo, "rev-parse", "--verify", f"{publication_commit}^{{commit}}")
    _git(repo, "merge-base", "--is-ancestor", publication_commit, head)
    for tracked in (relative, "index.json", "trust-domain.json"):
        _git(repo, "ls-files", "--error-unmatch", "--", tracked)
        _git(repo, "diff", "--quiet", "HEAD", "--", tracked)
        _git(repo, "diff", "--cached", "--quiet", "HEAD", "--", tracked)
        try:
            worktree_bytes = (repo / tracked).read_bytes()
            committed_bytes = _git(repo, "show", f"HEAD:{tracked}").encode("utf-8")
        except OSError as exc:
            _unverified(
                "could not compare publication worktree bytes with the pinned commit",
                "checkpoint_publication_bytes_unreadable",
                path=tracked,
                error_type=type(exc).__name__,
            )
        if worktree_bytes != committed_bytes:
            _unverified(
                "publication worktree bytes differ from HEAD (including an "
                "assume-unchanged path)",
                "checkpoint_publication_worktree_mismatch",
                path=tracked,
            )
    _git(repo, "diff", "--quiet", publication_commit, "HEAD", "--", "trust-domain.json")

    try:
        current_index_raw = json.loads((repo / "index.json").read_text(encoding="utf-8"))
        pinned_index_raw = json.loads(_git(repo, "show", f"{publication_commit}:index.json"))
    except (OSError, ValueError, UnicodeError) as exc:
        _unverified(
            "could not parse current and pinned publication indexes",
            "checkpoint_publication_index_malformed",
            error_type=type(exc).__name__,
        )
    current_entries = _index_entries(current_index_raw)
    pinned_entries = _index_entries(pinned_index_raw)
    if current_entries[: len(pinned_entries)] != pinned_entries:
        _unverified(
            "publication index.json is not an append-only extension of the pinned commit",
            "checkpoint_publication_index_rewritten",
        )

    paths: list[str] = []
    matched = 0
    matching_entry: Mapping[str, Any] | None = None
    trust_domain_entries = 0
    previous_seq = 0
    for ordinal, entry in enumerate(current_entries):
        if set(entry) != _PUBLICATION_ENTRY_KEYS:
            _unverified(
                "publication index contains an entry with an unknown or missing field",
                "checkpoint_publication_index_malformed",
            )
        entry_path = entry.get("path")
        if not isinstance(entry_path, str) or not entry_path:
            _unverified(
                "publication index entry path is invalid",
                "checkpoint_publication_index_malformed",
            )
        paths.append(entry_path)
        pure_path = Path(entry_path)
        if (
            pure_path.is_absolute()
            or ".." in pure_path.parts
            or "\\" in entry_path
            or entry_path == "index.json"
        ):
            _unverified(
                "publication index entry path is unsafe or self-referential",
                "checkpoint_publication_index_malformed",
                path=entry_path,
            )
        published_at = entry.get("published_at")
        try:
            datetime.strptime(str(published_at), "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            _unverified(
                "publication index entry published_at is not canonical UTC",
                "checkpoint_publication_index_malformed",
                path=entry_path,
            )
        prev_commit = entry.get("prev_commit")
        if prev_commit is not None and (
            not isinstance(prev_commit, str) or _GIT_COMMIT_RE.fullmatch(prev_commit) is None
        ):
            _unverified(
                "publication index entry prev_commit is invalid",
                "checkpoint_publication_index_malformed",
                path=entry_path,
            )
        if ordinal == 0:
            if prev_commit is not None:
                _unverified(
                    "the first publication index entry must have prev_commit=null",
                    "checkpoint_publication_index_link_invalid",
                )
        else:
            if not isinstance(prev_commit, str):
                _unverified(
                    "every later publication index entry must name its prior commit",
                    "checkpoint_publication_index_link_invalid",
                    path=entry_path,
                )
            try:
                previous_raw = json.loads(_git(repo, "show", f"{prev_commit}:index.json"))
            except (ValueError, UnicodeError) as exc:
                _unverified(
                    "publication index prev_commit does not expose a valid prior index",
                    "checkpoint_publication_index_link_invalid",
                    path=entry_path,
                    error_type=type(exc).__name__,
                )
            if _index_entries(previous_raw) != current_entries[:ordinal]:
                _unverified(
                    "publication index prev_commit does not commit to the exact prior prefix",
                    "checkpoint_publication_index_link_invalid",
                    path=entry_path,
                )
            _git(repo, "merge-base", "--is-ancestor", prev_commit, head)
        artifact = _git(repo, "show", f"HEAD:{entry_path}").encode("utf-8")
        artifact_digest = "sha256:" + hashlib.sha256(artifact).hexdigest()
        if entry.get("sha256") != artifact_digest:
            _unverified(
                "publication index digest does not match the committed artifact bytes",
                "checkpoint_publication_historical_digest_mismatch",
                path=entry_path,
            )
        if entry_path == "trust-domain.json":
            trust_domain_entries += 1
        if entry_path.startswith(expected_prefix) and entry_path.endswith(".json"):
            try:
                seq = int(Path(entry_path).name.split("-", 1)[0])
            except ValueError:
                _unverified(
                    "publication index checkpoint path has no numeric sequence",
                    "checkpoint_publication_index_malformed",
                    path=entry_path,
                )
            if seq <= previous_seq:
                _unverified(
                    "publication index checkpoint sequences are not monotone",
                    "checkpoint_publication_index_not_monotone",
                )
            previous_seq = seq
        if entry_path == relative and entry.get("sha256") == document_digest:
            matched += 1
            matching_entry = entry
    if len(paths) != len(set(paths)) or matched != 1 or trust_domain_entries != 1:
        _unverified(
            "publication index must name trust-domain.json and the checkpoint path/digest "
            "exactly once",
            "checkpoint_publication_entry_mismatch",
            path=relative,
        )
    if matching_entry is None or matching_entry.get("prev_commit") != document_prev_commit:
        _unverified(
            "checkpoint prev_commit disagrees with its publication index entry",
            "checkpoint_publication_prev_commit_mismatch",
            path=relative,
        )
    return head


# ---------------------------------------------------------------------------
# The trust-log checkpoint triplet
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustLogCheckpoint:
    """The ``{checkpoint_seq, head_event_hash, document_digest}`` acceptance member.

    ``source`` records HOW the triplet was obtained, and it is reported everywhere the
    checkpoint is: ``"published"`` when an operator supplied a signed §4.3 checkpoint
    document that was then reconciled against the live log, ``"derived"`` when this
    process observed the log itself. The two are not equivalent evidence and the
    difference is never left implicit.
    """

    checkpoint_seq: int
    head_event_hash: str
    document_digest: str
    source: str
    document: Mapping[str, Any] = field(default_factory=dict)
    publication_commit: str | None = None

    def as_payload_member(self) -> dict[str, Any]:
        """Exactly the three keys ``_genesis._validate_bootstrap_acceptance`` allows."""
        return {
            "checkpoint_seq": self.checkpoint_seq,
            "head_event_hash": self.head_event_hash,
            "document_digest": self.document_digest,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.as_payload_member(),
            "source": self.source,
            "publication_commit": self.publication_commit,
        }


def _max_global_seq(conn: DictConn) -> int | None:
    """The trust log's highest ``global_seq``, informational only.

    ``TRUST-DOMAIN.md`` §4.3: "``max_global_seq`` is informational and is never the
    binding". It is reported because a checkpoint document declares it, and it is
    never compared for equality by anything here.
    """
    row = conn.execute("SELECT MAX(global_seq) AS max_seq FROM events").fetchone()
    if row is None or row["max_seq"] is None:
        return None
    return int(row["max_seq"])


def derive_trust_log_checkpoint(
    conn: DictConn,
    genesis_document: Mapping[str, Any],
    *,
    checkpoint_seq: int = 1,
    observed_at: datetime | None = None,
    verified: Any | None = None,
) -> TrustLogCheckpoint:
    """Observe the live trust log and mint the checkpoint triplet from that observation.

    The head is taken from :func:`verify_trust_log_chain`'s own return value, so the
    hash that lands in signed genesis bytes is one an authority-verified walk arrived
    at — not one read back off an unverified row. ``document_digest`` is the JCS digest
    of the observation document this function builds, which is emitted alongside the
    triplet so the operator can publish or archive the exact bytes the digest covers.
    """
    from ._jcs import canonicalize
    from ._trust_domain import parse_trust_genesis
    from ._trust_log_writer import verify_trust_log_chain

    if not isinstance(checkpoint_seq, int) or isinstance(checkpoint_seq, bool):
        _refuse(
            ErrorCode.INVALID_ARGUMENT,
            "checkpoint_seq must be an integer",
            "checkpoint_seq_not_integer",
        )
    if checkpoint_seq < 1:
        _refuse(
            ErrorCode.INVALID_ARGUMENT,
            f"checkpoint_seq must be >= 1 (§5.8 requires it); got {checkpoint_seq}",
            "checkpoint_seq_below_one",
            checkpoint_seq=checkpoint_seq,
        )
    if checkpoint_seq != 1:
        _refuse(
            ErrorCode.INVALID_ARGUMENT,
            "a derived observation has no prior published checkpoint to link, so its "
            "checkpoint_seq must be exactly 1",
            "derived_checkpoint_sequence_unlinked",
            checkpoint_seq=checkpoint_seq,
        )

    chain = verified if verified is not None else verify_trust_log_chain(conn, genesis_document)
    doc = parse_trust_genesis(genesis_document)
    document = {
        "type": TRUST_LOG_OBSERVATION_TYPE,
        "version": 1,
        "trust_domain_id": str(doc.trust_domain_id),
        "trust_domain_core_digest": doc.trust_domain_core_digest,
        "checkpoint_seq": checkpoint_seq,
        "trust_log": {
            "project_instance_id": str(doc.trust_log.project_instance_id),
            "event_count": chain.event_count,
            "genesis_event_hash": chain.state.genesis_event_hash,
            "head_event_hash": chain.head_event_hash,
            "max_global_seq": _max_global_seq(conn),
        },
        "root_governance": {
            "threshold": chain.state.governance.threshold,
            "signer_count": len(chain.state.governance.signer_fingerprints),
        },
        "active_root_fingerprints": sorted(chain.state.governance.signer_fingerprints),
        "prev_checkpoint_digest": None,
        "observed_at": _iso_micro_z(observed_at or datetime.now(UTC)),
    }
    return TrustLogCheckpoint(
        checkpoint_seq=checkpoint_seq,
        head_event_hash=chain.head_event_hash,
        document_digest="sha256:" + hashlib.sha256(canonicalize(document)).hexdigest(),
        source="derived",
        document=document,
    )


def load_published_checkpoint(
    path: str,
    conn: DictConn,
    genesis_document: Mapping[str, Any],
    *,
    verified: Any | None = None,
    publication_repo: str | None = None,
    publication_commit: str | None = None,
) -> TrustLogCheckpoint:
    """Read a published §4.3 checkpoint document and reconcile it with the live log.

    A published checkpoint is stronger evidence than a local observation only if it is
    actually checked against the log it claims to describe. Every field that can be
    contradicted is contradicted here: the trust domain, the trust-log project
    instance, the genesis event hash, the head, and the event count. A checkpoint that
    describes a different log, or a stale state of this one, is refused rather than
    signed into a project's first event.
    """
    import nacl.exceptions
    import nacl.signing

    from ._jcs import canonicalize
    from ._trust_domain import derive_governance_mode, parse_trust_genesis
    from ._trust_log_writer import verify_trust_log_chain

    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        _unverified(
            f"cannot read --trust-checkpoint {path!r}: {exc}",
            "checkpoint_file_unreadable",
            path=path,
        )
    except (ValueError, UnicodeError) as exc:
        _unverified(
            f"--trust-checkpoint {path!r} is not valid JSON: {exc}",
            "checkpoint_file_invalid_json",
            path=path,
        )
    if not isinstance(raw, Mapping):
        _unverified(
            f"--trust-checkpoint {path!r} must contain a JSON object",
            "checkpoint_document_not_object",
            path=path,
        )
    assert isinstance(raw, Mapping)

    if set(raw) != _CHECKPOINT_KEYS:
        _unverified(
            "the checkpoint document has unknown or missing fields",
            "checkpoint_document_shape_invalid",
            unknown=sorted(set(raw) - _CHECKPOINT_KEYS),
            missing=sorted(_CHECKPOINT_KEYS - set(raw)),
        )
    if (
        raw.get("type") != TRUST_CHECKPOINT_TYPE
        or type(raw.get("version")) is not int
        or raw.get("version") != 1
    ):
        _unverified(
            "the checkpoint must be regista.trust-checkpoint/v1",
            "checkpoint_type_or_version_invalid",
            type=raw.get("type"),
            version=raw.get("version"),
        )
    canonical_document = canonicalize(raw)
    if Path(path).read_bytes() != canonical_document:
        _unverified(
            "the published checkpoint file is not exact canonical JCS bytes",
            "checkpoint_not_canonical_publication_bytes",
        )

    seq = raw.get("checkpoint_seq")
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 1:
        _unverified(
            "the checkpoint document's checkpoint_seq must be an integer >= 1",
            "checkpoint_seq_invalid",
            checkpoint_seq=seq,
        )
    assert isinstance(seq, int)

    log = raw.get("trust_log")
    if not isinstance(log, Mapping):
        _unverified(
            "the checkpoint document has no trust_log object",
            "checkpoint_trust_log_absent",
        )
    assert isinstance(log, Mapping)
    if set(log) != _CHECKPOINT_LOG_KEYS:
        _unverified(
            "the checkpoint trust_log object has unknown or missing fields",
            "checkpoint_document_shape_invalid",
        )
    event_count = log.get("event_count")
    max_global_seq = log.get("max_global_seq")
    if (
        not isinstance(event_count, int)
        or isinstance(event_count, bool)
        or event_count < 1
        or not isinstance(max_global_seq, int)
        or isinstance(max_global_seq, bool)
        or max_global_seq < 1
    ):
        _unverified(
            "checkpoint trust_log counts must be positive integers",
            "checkpoint_document_shape_invalid",
        )
    _require_digest_text(raw.get("trust_domain_core_digest"), "trust_domain_core_digest")
    _require_digest_text(log.get("genesis_event_hash"), "trust_log.genesis_event_hash")
    _require_digest_text(log.get("head_event_hash"), "trust_log.head_event_hash")
    _require_digest_text(
        raw.get("prev_checkpoint_digest"), "prev_checkpoint_digest", nullable=True
    )
    try:
        datetime.strptime(str(raw.get("created_at")), "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        _unverified(
            "checkpoint created_at must be canonical UTC with microseconds",
            "checkpoint_created_at_invalid",
        )
    prev_commit = raw.get("prev_commit")
    if prev_commit is not None and (
        not isinstance(prev_commit, str) or _GIT_COMMIT_RE.fullmatch(prev_commit) is None
    ):
        _unverified(
            "checkpoint prev_commit must be null or a full lowercase git commit",
            "checkpoint_prev_commit_invalid",
        )

    chain = verified if verified is not None else verify_trust_log_chain(conn, genesis_document)
    doc = parse_trust_genesis(genesis_document)

    governance = raw.get("root_governance")
    if not isinstance(governance, Mapping) or set(governance) != _CHECKPOINT_GOVERNANCE_KEYS:
        _unverified(
            "checkpoint root_governance has the wrong shape",
            "checkpoint_governance_invalid",
        )
    if (
        type(governance.get("threshold")) is not int
        or type(governance.get("signer_count")) is not int
    ):
        _unverified(
            "checkpoint governance counts must be strict integers",
            "checkpoint_governance_invalid",
        )
    expected_governance = {
        "mode": derive_governance_mode(
            chain.state.governance.threshold,
            len(chain.state.governance.signer_fingerprints),
        ),
        "threshold": chain.state.governance.threshold,
        "signer_count": len(chain.state.governance.signer_fingerprints),
    }
    if dict(governance) != expected_governance:
        _unverified(
            "checkpoint root_governance disagrees with the verified live trust log",
            "checkpoint_governance_mismatch",
            stated=dict(governance),
            actual=expected_governance,
        )
    active_roots = raw.get("active_root_fingerprints")
    if (
        not isinstance(active_roots, list)
        or not all(isinstance(item, str) for item in active_roots)
        or active_roots != sorted(chain.state.governance.signer_fingerprints)
    ):
        _unverified(
            "checkpoint active_root_fingerprints disagree with the verified live trust log",
            "checkpoint_active_roots_mismatch",
        )
    if raw.get("countersignatures") != [] or raw.get("anchors") != []:
        _unverified(
            "checkpoint countersignatures and anchors are not verified in 0.6.0 and must "
            "be separate immutable attestation records",
            "checkpoint_inline_attestations_unsupported",
        )

    root_signatures = raw.get("root_signatures")
    if not isinstance(root_signatures, list) or not root_signatures:
        _unverified(
            "checkpoint requires direct root-threshold signatures; registrar checkpoint "
            "authority remains deferred to P2.4",
            "checkpoint_root_signatures_absent",
        )
    message = _checkpoint_signature_input(raw)
    verified_fingerprints: set[str] = set()
    for index, signature in enumerate(root_signatures):
        if not isinstance(signature, Mapping) or set(signature) != _ROOT_SIGNATURE_KEYS:
            _unverified(
                "checkpoint root signature has the wrong shape",
                "checkpoint_root_signature_invalid",
                index=index,
            )
        fingerprint = signature.get("fingerprint")
        signer_id = signature.get("signer_id")
        encoded = signature.get("signature")
        if (
            not isinstance(fingerprint, str)
            or not isinstance(signer_id, str)
            or not signer_id
            or not isinstance(encoded, str)
            or fingerprint in verified_fingerprints
        ):
            _unverified(
                "checkpoint root signatures must be distinct, named canonical entries",
                "checkpoint_root_signature_invalid",
                index=index,
            )
        public_key = chain.state.root_public_keys.get(fingerprint)
        if (
            public_key is None
            or fingerprint not in chain.state.governance.signer_fingerprints
        ):
            _unverified(
                "checkpoint was signed by a key outside the current root set",
                "checkpoint_root_signer_not_current",
                fingerprint=fingerprint,
            )
        try:
            raw_signature = base64.b64decode(encoded, validate=True)
            if len(raw_signature) != 64:
                raise ValueError("signature length")
            nacl.signing.VerifyKey(public_key).verify(message, raw_signature)
        except (ValueError, TypeError, nacl.exceptions.BadSignatureError) as exc:
            _unverified(
                "checkpoint root signature did not verify",
                "checkpoint_root_signature_invalid",
                index=index,
                error_type=type(exc).__name__,
            )
        verified_fingerprints.add(fingerprint)
    if len(verified_fingerprints) < chain.state.governance.threshold:
        _unverified(
            "checkpoint root signatures do not meet the current governance threshold",
            "checkpoint_root_threshold_not_met",
            verified=len(verified_fingerprints),
            required=chain.state.governance.threshold,
        )

    for field_name, stated, actual in (
        ("trust_domain_id", raw.get("trust_domain_id"), str(doc.trust_domain_id)),
        (
            "trust_domain_core_digest",
            raw.get("trust_domain_core_digest"),
            doc.trust_domain_core_digest,
        ),
        (
            "trust_log.project_instance_id",
            log.get("project_instance_id"),
            str(doc.trust_log.project_instance_id),
        ),
        (
            "trust_log.genesis_event_hash",
            log.get("genesis_event_hash"),
            chain.state.genesis_event_hash,
        ),
        ("trust_log.head_event_hash", log.get("head_event_hash"), chain.head_event_hash),
    ):
        if stated != actual:
            _unverified(
                f"the supplied checkpoint's {field_name} is {stated!r}, but the live "
                f"trust log's is {actual!r}; a checkpoint that does not describe this "
                "log's current state is not evidence about it",
                "checkpoint_disagrees_with_live_log",
                field=field_name,
                stated=stated,
                actual=actual,
            )
    stated_count = log.get("event_count")
    if stated_count != chain.event_count:
        _unverified(
            f"the supplied checkpoint states event_count {stated_count!r}, but the "
            f"verified walk reached {chain.event_count} event(s)",
            "checkpoint_event_count_mismatch",
            stated=stated_count,
            actual=chain.event_count,
        )
    document_digest = "sha256:" + hashlib.sha256(canonical_document).hexdigest()
    published_commit = _verify_checkpoint_publication(
        Path(path),
        document_digest,
        str(doc.trust_domain_id),
        seq,
        prev_commit,
        publication_repo=publication_repo,
        publication_commit=publication_commit,
    )
    return TrustLogCheckpoint(
        checkpoint_seq=seq,
        head_event_hash=chain.head_event_hash,
        document_digest=document_digest,
        source="published",
        document=dict(raw),
        publication_commit=published_commit,
    )


# ---------------------------------------------------------------------------
# The enrolled key, resolved from the verified chain
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EnrolledKey:
    """One principal's live, ACTIVE, chain-verified enrolment or rotation."""

    principal_id: str
    principal_kind: str
    key_id: str
    public_key: bytes
    fingerprint: str
    #: The key-introduction event's own hash — what
    #: ``bootstrap_key_acceptance.trust_event_hash`` must name.
    trust_event_hash: str
    trust_event_transition: str
    not_before: datetime
    not_after: datetime | None
    #: ``"agree"`` when a ``principal_keys`` row was found and matched the chain,
    #: ``"absent"`` when the projection has no row for this key. Never ``"disagree"``:
    #: a disagreeing row is a refusal, not a report.
    projection: str

    @property
    def public_key_b64(self) -> str:
        return _b64(self.public_key)

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal_id": self.principal_id,
            "principal_kind": self.principal_kind,
            "key_id": self.key_id,
            "fingerprint": self.fingerprint,
            "public_key": self.public_key_b64,
            "trust_event_hash": self.trust_event_hash,
            "trust_event_transition": self.trust_event_transition,
            "not_before": _iso_micro_z(self.not_before),
            "not_after": None if self.not_after is None else _iso_micro_z(self.not_after),
            "projection": self.projection,
        }


def _iso_micro_z(value: datetime) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def _projection_cross_check(
    conn: DictConn, principal_id: str, key_id: str, public_key: bytes, source_hash: str
) -> str:
    """Compare the ``principal_keys`` row against the chain, or report its absence.

    §5.9 rule 1: no verifier resolves a key FROM this table. So an absent row is not an
    error — the projection may simply not have been rebuilt. A row that CONTRADICTS the
    verified chain is a different matter: it means the table and the log disagree about
    the key a project is about to bind its whole history to, and the honest response is
    to stop and make the operator rebuild.
    """
    present = conn.execute(
        "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE "
        "table_schema = current_schema() AND table_name = 'principal_keys') AS present"
    ).fetchone()
    if present is None or not present["present"]:
        # A trust-log schema without the projection table cannot contradict anything.
        # Reported, not raised: §5.9 rule 1 means the table's absence is never grounds
        # to refuse, and a raw UndefinedTable here would be an unnamed failure.
        return "absent"
    row = conn.execute(
        "SELECT principal_id, key_id, public_key, fingerprint, status, source_event_hash "
        "FROM principal_keys WHERE principal_id = %s AND key_id = %s",
        [principal_id, key_id],
    ).fetchone()
    if row is None:
        return "absent"
    mismatches: list[str] = []
    if bytes(row["public_key"]) != public_key:
        mismatches.append("public_key")
    if row["fingerprint"] != _fingerprint_of(public_key):
        mismatches.append("fingerprint")
    if row["status"] != "active":
        mismatches.append("status")
    if row["source_event_hash"] != source_hash:
        mismatches.append("source_event_hash")
    if mismatches:
        _unverified(
            f"the principal_keys projection row for {principal_id}/{key_id} "
            f"contradicts the verified trust-log chain on: {', '.join(mismatches)}. "
            "The projection is not the authority (§5.9 rule 1), but a projection that "
            "disagrees with the log is not evidence of anything either — run "
            "`regista trust rebuild-projection` and re-check before opening an epoch.",
            "projection_disagrees_with_chain",
            principal_id=principal_id,
            key_id=key_id,
            fields=mismatches,
        )
    return "agree"


def resolve_enrolled_key(
    conn: DictConn,
    genesis_document: Mapping[str, Any],
    *,
    principal_id: str,
    key_id: str | None = None,
    expected_trust_event_hash: str | None = None,
    at: datetime | None = None,
    verified: Any | None = None,
) -> EnrolledKey:
    """Resolve one principal's live enrolled key from the VERIFIED trust-log chain.

    ``at`` is the instant the enrolment must be valid at — the genesis's own
    ``occurred_at`` — and it defaults to now. Every refusal names a distinct reason
    because the operator's next action differs for each: enrol the principal, rotate a
    revoked key, wait for a not-yet-valid window, re-enrol an expired one, or pass
    ``--key-id`` to disambiguate.
    """
    from ._trust_log import parse_principal_key_enrolled, parse_principal_key_rotated
    from ._trust_log_writer import verify_trust_log_chain

    moment = at or datetime.now(UTC)
    chain = verified if verified is not None else verify_trust_log_chain(conn, genesis_document)

    # Every key-introduction event the verified walk accepted for this principal.
    # TRUST-DOMAIN §5.10 explicitly permits an enrolment OR rotation referent.
    candidates: list[tuple[Any, Any]] = []
    for record in chain.verified:
        parsed: Any
        if record.transition == _ENROLLED:
            parsed = parse_principal_key_enrolled(record.payload)
        elif record.transition == _ROTATED:
            parsed = parse_principal_key_rotated(record.payload)
        else:
            continue
        if parsed.principal_id != principal_id:
            continue
        candidates.append((record, parsed))

    # This principal's rotations, and the key_ids they SUPERSEDE. This matters more than
    # it looks: `_trust_log_writer._classify_rotation` does NOT flip the superseded key's
    # entry in `principal_key_status` — a rotation only records the incoming key as
    # "active" (`_remember_principal_key`). So after a rotation the outgoing key is
    # STILL "active" in the replayed status map, and an "is it active?" test alone would
    # happily resolve a superseded key and sign a project's genesis with it. Supersession
    # has to be read off the rotation events themselves.
    rotations = [
        r
        for r in chain.verified
        if r.transition == _ROTATED
        and isinstance(r.payload, Mapping)
        and r.payload.get("principal_id") == principal_id
    ]
    superseded_key_ids = {
        r.payload["supersedes_key_id"]
        for r in rotations
        if isinstance(r.payload.get("supersedes_key_id"), str)
    }

    if not candidates:
        _unverified(
            f"{principal_id!r} has no principal_key_enrolled or "
            "principal_key_rotated event in the verified trust log; enrol the principal "
            "before opening a project epoch as it",
            "principal_has_no_key_introduction",
            principal_id=principal_id,
        )

    if key_id is not None:
        narrowed = [(r, p) for r, p in candidates if p.key.key_id == key_id]
        if not narrowed:
            _unverified(
                f"{principal_id!r} has no enrolment or rotation event for key_id "
                f"{key_id!r}; introduced key ids are: "
                + ", ".join(sorted(p.key.key_id for _r, p in candidates)),
                "key_id_not_introduced",
                principal_id=principal_id,
                key_id=key_id,
                introduced_key_ids=sorted(p.key.key_id for _r, p in candidates),
            )
        candidates = narrowed

    # Drop superseded enrolments BEFORE the active test, so the more specific reason
    # wins: "your enrolled key was rotated away" is actionable, "it is not active" would
    # be both vaguer and — given the status map above — wrong.
    unsuperseded = [(r, p) for r, p in candidates if p.key.key_id not in superseded_key_ids]
    if not unsuperseded:
        _unverified(
            f"every matching key for {principal_id!r} was superseded by a later "
            "principal_key_rotated event",
            "key_superseded",
            principal_id=principal_id,
            key_ids=sorted(p.key.key_id for _r, p in candidates),
            superseded_key_ids=sorted(superseded_key_ids),
        )
    candidates = unsuperseded

    status = chain.state.principal_key_status
    live = [
        (r, p) for r, p in candidates if status.get((principal_id, p.key.key_id)) == "active"
    ]
    if not live:
        _unverified(
            f"every current key for {principal_id!r} is revoked in the verified trust "
            "log; a revoked key may not sign a project's genesis",
            "trust_key_not_active",
            principal_id=principal_id,
            key_ids=sorted(p.key.key_id for _r, p in candidates),
            statuses={
                p.key.key_id: status.get((principal_id, p.key.key_id))
                for _r, p in candidates
            },
        )
    if len(live) > 1:
        _unverified(
            f"{principal_id!r} has {len(live)} active trust-log keys "
            f"({', '.join(sorted(p.key.key_id for _r, p in live))}); pass --key-id to "
            "name the one that signs this genesis rather than letting the tool choose "
            "which key a project's whole history is bound to",
            "trust_key_ambiguous",
            principal_id=principal_id,
            key_ids=sorted(p.key.key_id for _r, p in live),
        )

    record, parsed = live[0]
    resolved_key_id = parsed.key.key_id

    # The validity window is the introduction event's own claim about usability.
    # verify_trust_log_chain evaluates registrar liveness at each event's occurred_at;
    # nothing there checks the ENROLLED key against the instant it is about to sign.
    if moment < parsed.not_before:
        _unverified(
            f"the trust event for {principal_id}/{resolved_key_id} is not valid until "
            f"{_iso_micro_z(parsed.not_before)}, which is after the genesis instant "
            f"{_iso_micro_z(moment)}",
            "trust_key_not_yet_valid",
            principal_id=principal_id,
            key_id=resolved_key_id,
            not_before=_iso_micro_z(parsed.not_before),
            at=_iso_micro_z(moment),
        )
    if parsed.not_after is not None and moment >= parsed.not_after:
        _unverified(
            f"the trust event for {principal_id}/{resolved_key_id} expired at "
            f"{_iso_micro_z(parsed.not_after)}, before the genesis instant "
            f"{_iso_micro_z(moment)}",
            "trust_key_expired",
            principal_id=principal_id,
            key_id=resolved_key_id,
            not_after=_iso_micro_z(parsed.not_after),
            at=_iso_micro_z(moment),
        )

    # The replayed state's key bytes and the introducing payload's must agree, and the
    # fingerprint must be recomputed from the bytes rather than trusted as stated.
    replayed = chain.state.principal_public_keys.get((principal_id, resolved_key_id))
    if replayed is None or replayed != parsed.key.public_key:
        _unverified(
            f"the replayed public key for {principal_id}/{resolved_key_id} does not "
            "match the key material its trust event carries",
            "replayed_public_key_mismatch",
            principal_id=principal_id,
            key_id=resolved_key_id,
        )
    recomputed = _fingerprint_of(parsed.key.public_key)
    if parsed.key.fingerprint != recomputed:
        _unverified(
            f"the trust event for {principal_id}/{resolved_key_id} states fingerprint "
            f"{parsed.key.fingerprint!r}, which is not the digest of the public key it "
            "carries",
            "trust_key_fingerprint_mismatch",
            principal_id=principal_id,
            key_id=resolved_key_id,
        )
    if parsed.key.scheme_id != "ed25519":
        _unverified(
            f"the trust event for {principal_id}/{resolved_key_id} declares scheme "
            f"{parsed.key.scheme_id!r}; a v6 project genesis is Ed25519-only",
            "trust_key_scheme_not_ed25519",
            principal_id=principal_id,
            key_id=resolved_key_id,
            scheme_id=parsed.key.scheme_id,
        )

    # An operator-claimed trust_event_hash is checked, never taken. This is the
    # concrete hole `_genesis.py:396` leaves open: there, the value only has to LOOK
    # like a digest.
    if expected_trust_event_hash is not None and expected_trust_event_hash != record.event_hash:
        _unverified(
            f"--trust-event-hash {expected_trust_event_hash!r} is not the "
            f"key-introduction event for {principal_id}/{resolved_key_id}; that "
            f"event's hash is {record.event_hash!r}",
            "trust_event_hash_mismatch",
            principal_id=principal_id,
            key_id=resolved_key_id,
            claimed=expected_trust_event_hash,
            actual=record.event_hash,
        )

    projection = _projection_cross_check(
        conn, principal_id, resolved_key_id, parsed.key.public_key, record.event_hash
    )
    return EnrolledKey(
        principal_id=principal_id,
        principal_kind=parsed.principal_kind,
        key_id=resolved_key_id,
        public_key=parsed.key.public_key,
        fingerprint=recomputed,
        trust_event_hash=record.event_hash,
        trust_event_transition=record.transition,
        not_before=parsed.not_before,
        not_after=parsed.not_after,
        projection=projection,
    )


# ---------------------------------------------------------------------------
# The whole verified reference
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustReference:
    """Everything a ``project_initialized`` envelope needs, all of it verified."""

    trust_domain_id: str
    trust_domain_core_digest: str
    genesis_document_digest: str
    trust_log_project_instance_id: str
    key: EnrolledKey
    checkpoint: TrustLogCheckpoint

    def to_dict(self) -> dict[str, Any]:
        return {
            "trust_domain_id": self.trust_domain_id,
            "trust_domain_core_digest": self.trust_domain_core_digest,
            "genesis_document_digest": self.genesis_document_digest,
            "trust_log_project_instance_id": self.trust_log_project_instance_id,
            "key": self.key.to_dict(),
            "checkpoint": self.checkpoint.to_dict(),
        }


def resolve_trust_reference(
    conn: DictConn,
    genesis_document: Mapping[str, Any],
    *,
    principal_id: str,
    key_id: str | None = None,
    expected_trust_event_hash: str | None = None,
    expected_trust_domain_id: str | None = None,
    at: datetime | None = None,
    checkpoint_seq: int = 1,
    published_checkpoint_path: str | None = None,
    publication_repo: str | None = None,
    publication_commit: str | None = None,
    allow_derived_checkpoint: bool = False,
) -> TrustReference:
    """One verified walk; every genesis input derived from it.

    ``verify_trust_log_chain`` is run ONCE and its result threaded through the key
    resolution and the checkpoint derivation, so the enrolment and the head cannot be
    read from two different views of the log.
    """
    from ._trust_domain import genesis_document_digest, parse_trust_genesis
    from ._trust_log_writer import verify_trust_log_chain

    chain = verify_trust_log_chain(conn, genesis_document)
    doc = parse_trust_genesis(genesis_document)
    trust_domain_id = str(doc.trust_domain_id)

    # verify_trust_log_chain already refuses a stored genesis whose trust_domain_id
    # differs from the pinned document, and every lifecycle event that names another
    # domain. This is the operator's own expectation, checked against the same
    # verified document: `--trust-domain-id` is how a ceremony script asserts "the
    # domain I think I am joining" and gets told if it is wrong.
    if expected_trust_domain_id is not None and expected_trust_domain_id != trust_domain_id:
        _unverified(
            f"the verified trust log's domain is {trust_domain_id!r}, not the expected "
            f"{expected_trust_domain_id!r}",
            "trust_domain_id_mismatch",
            expected=expected_trust_domain_id,
            actual=trust_domain_id,
        )

    key = resolve_enrolled_key(
        conn,
        genesis_document,
        principal_id=principal_id,
        key_id=key_id,
        expected_trust_event_hash=expected_trust_event_hash,
        at=at,
        verified=chain,
    )
    if published_checkpoint_path is not None:
        checkpoint = load_published_checkpoint(
            published_checkpoint_path,
            conn,
            genesis_document,
            verified=chain,
            publication_repo=publication_repo,
            publication_commit=publication_commit,
        )
    else:
        if not allow_derived_checkpoint:
            _unverified(
                "an evidence-grade genesis requires a root-threshold-signed checkpoint "
                "from the pinned publication channel; derived observations are available "
                "only to --dry-run",
                "published_checkpoint_required",
            )
        checkpoint = derive_trust_log_checkpoint(
            conn,
            genesis_document,
            checkpoint_seq=checkpoint_seq,
            observed_at=at,
            verified=chain,
        )
    return TrustReference(
        trust_domain_id=trust_domain_id,
        trust_domain_core_digest=doc.trust_domain_core_digest,
        genesis_document_digest=genesis_document_digest(genesis_document),
        trust_log_project_instance_id=str(doc.trust_log.project_instance_id),
        key=key,
        checkpoint=checkpoint,
    )


# ---------------------------------------------------------------------------
# EPOCH-RESET §5: the first-write verdict, as evidence
# ---------------------------------------------------------------------------


def _gate_measurement_valid(
    check: Mapping[str, Any],
    *,
    project: str,
    store_fingerprint: object,
    snapshot: object,
) -> bool:
    if (
        set(check) != _MEASUREMENT_KEYS
        or check.get("id") != "regista.store_invariant_measurements"
        or check.get("status") != "measured"
        or check.get("store_fingerprint") != store_fingerprint
        or check.get("errors") != []
        or not isinstance(check.get("projects"), list)
    ):
        return False
    projects = check["projects"]
    if len(projects) != 1 or not isinstance(projects[0], Mapping):
        return False
    row = projects[0]
    return (
        set(row) == _PROJECT_MEASUREMENT_KEYS
        and row.get("project") == project
        and type(row.get("event_count")) is int
        and row.get("event_count") == 0
        and type(row.get("declared_lineage_event_count")) is int
        and row.get("declared_lineage_event_count") == 0
        and row.get("lineage_coverage") == {"numerator": 0, "denominator": 0}
        and row.get("distinct_lineage_tokens") == []
        and row.get("unresolvable_lineage_tokens") == []
        and type(row.get("unresolvable_lineage_value_count")) is int
        and row.get("unresolvable_lineage_value_count") == 0
        and type(row.get("ambiguous_lineage_event_count")) is int
        and row.get("ambiguous_lineage_event_count") == 0
        and row.get("scheme_counts") == {}
        and type(row.get("undeclared_agent_author_event_count")) is int
        and row.get("undeclared_agent_author_event_count") == 0
        and row.get("model_observation_status_counts") == {}
        and row.get("snapshot_id") == snapshot
    )


@dataclass(frozen=True)
class GateEvidence:
    """A validated ``agent-suite genesis-gate --json`` report for THIS target."""

    path: str
    report_version: int
    store_fingerprint: str
    project: str
    observation_snapshot: str | None
    finding_count: int
    report_digest: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "report_version": self.report_version,
            "store_fingerprint": self.store_fingerprint,
            "project": self.project,
            "observation_snapshot": self.observation_snapshot,
            "findings": self.finding_count,
            "report_digest": self.report_digest,
            "epoch_may_open": True,
        }


def _gate_refuse(message: str, reason: str, **detail: Any) -> NoReturn:
    _refuse(ErrorCode.GENESIS_GATE_EVIDENCE_INVALID, message, reason, **detail)


def load_gate_evidence(path: str | None, *, dsn: str, project: str) -> GateEvidence:
    """Validate the §5 gate report, or refuse. There is no default-true.

    ``initialize_epoch``'s ``gate_passed`` is a bare boolean, and a CLI that defaulted
    it to ``True`` would make EPOCH-RESET §5 ("the store conformance check gates the
    epoch; if it does not pass, the epoch does not open") a comment. So the flag is
    only ever set from a report that: is the version this code understands, says
    ``ok`` AND ``epoch_may_open`` are both exactly ``True``, carries no non-passing
    finding, has healthy probes, and is BOUND to the store fingerprint and project
    about to be written. The binding is the part that matters most: a PASS report for
    a throwaway fixture store is a real report about the wrong store, and without the
    fingerprint check it would open an epoch anywhere.

    There is deliberately no override. A gate that cannot pass is a gate telling the
    truth about a store that is not ready.
    """
    from ._invariant_probe import postgres_database_fingerprint

    if path is None:
        _gate_refuse(
            "no genesis-gate evidence: pass --gate-report PATH pointing at the output "
            "of `agent-suite genesis-gate --json --exit-code`. EPOCH-RESET §5 makes the "
            "gate a precondition on the FIRST WRITE, so there is no default and no "
            "override — an epoch does not open on an unevidenced assertion that it may.",
            "gate_report_absent",
        )
    assert path is not None
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        _gate_refuse(
            f"cannot read --gate-report {path!r}: {exc}",
            "gate_report_unreadable",
            path=path,
        )
    except (ValueError, UnicodeError) as exc:
        _gate_refuse(
            f"--gate-report {path!r} is not valid JSON: {exc}",
            "gate_report_invalid_json",
            path=path,
        )
    if not isinstance(raw, Mapping):
        _gate_refuse(
            f"--gate-report {path!r} must contain a JSON object",
            "gate_report_not_object",
            path=path,
        )
    assert isinstance(raw, Mapping)

    if set(raw) != _GATE_REPORT_KEYS:
        _gate_refuse(
            "the gate report has unknown or missing top-level fields",
            "gate_report_shape_invalid",
            unknown=sorted(set(raw) - _GATE_REPORT_KEYS),
            missing=sorted(_GATE_REPORT_KEYS - set(raw)),
        )

    if raw.get("kind") != "genesis_gate":
        _gate_refuse(
            f"--gate-report {path!r} has kind {raw.get('kind')!r}; this must be the "
            "`agent-suite genesis-gate --json` report (kind 'genesis_gate'), not the "
            "`invariant-probes` report, which carries no first-write verdict",
            "gate_report_wrong_kind",
            kind=raw.get("kind"),
        )
    version = raw.get("report_version")
    if type(version) is not int:
        _gate_refuse(
            "the gate report has no integer report_version",
            "gate_report_version_absent",
            report_version=version,
        )
    assert isinstance(version, int)
    if version not in SUPPORTED_GATE_REPORT_VERSIONS:
        _gate_refuse(
            f"the gate report declares report_version {version}, which this regista "
            f"does not understand (supported: {sorted(SUPPORTED_GATE_REPORT_VERSIONS)}). "
            "Refusing to interpret an unknown report version — a later version could "
            "change what epoch_may_open means.",
            "gate_report_version_unsupported",
            report_version=version,
        )

    if raw.get("epoch_may_open") is not True or raw.get("ok") is not True:
        _gate_refuse(
            "the gate report does not say the epoch may open "
            f"(ok={raw.get('ok')!r}, epoch_may_open={raw.get('epoch_may_open')!r}). "
            "Resolve the blocking findings and re-run the gate; the epoch does not "
            "open on a BLOCKED verdict.",
            "gate_did_not_pass",
            ok=raw.get("ok"),
            epoch_may_open=raw.get("epoch_may_open"),
        )

    # Check the target project before deriving the dynamic v1 finding IDs. Otherwise
    # an honestly formed report for the wrong project is diagnosed as generic finding
    # incompleteness rather than the binding error the operator must fix.
    early_binding = raw.get("binding")
    if not isinstance(early_binding, Mapping) or set(early_binding) != _GATE_BINDING_KEYS:
        _gate_refuse(
            "the gate report has no complete binding object",
            "gate_report_binding_invalid",
        )
    if early_binding.get("project") != project:
        _gate_refuse(
            f"the gate report is bound to project {early_binding.get('project')!r}, not "
            f"the target project {project!r}",
            "gate_report_project_mismatch",
            report_project=early_binding.get("project"),
            target_project=project,
        )
    early_snapshot = early_binding.get("observation_snapshot")
    if not isinstance(early_snapshot, str) or _PG_SNAPSHOT_RE.fullmatch(early_snapshot) is None:
        _gate_refuse(
            "the gate report has no canonical PostgreSQL transaction snapshot label",
            "gate_report_snapshot_invalid",
        )

    findings = raw.get("findings")
    if not isinstance(findings, Sequence) or isinstance(findings, str | bytes):
        _gate_refuse(
            "the gate report has no findings list",
            "gate_report_findings_absent",
        )
    assert isinstance(findings, Sequence)
    if not findings:
        _gate_refuse(
            "the gate report carries zero findings; a gate that checked nothing is not "
            "a PASS, whatever its ok flag says",
            "gate_report_findings_empty",
        )
    # `ok` is not taken on trust: a report whose top-level flag disagrees with its own
    # findings is self-contradictory, and the safe reading of a contradiction is the
    # pessimistic one.
    finding_ids: list[str] = []
    malformed_finding = False
    for finding in findings:
        if (
            not isinstance(finding, Mapping)
            or set(finding) != _GATE_FINDING_KEYS
            or not isinstance(finding.get("check_id"), str)
            or not finding.get("check_id")
            or finding.get("status") != "pass"
            or not isinstance(finding.get("detail"), str)
            or not finding.get("detail")
        ):
            malformed_finding = True
            break
        finding_ids.append(str(finding["check_id"]))
    expected_findings = _GATE_REQUIRED_BEHAVIORAL_FINDINGS | frozenset(
        {
            "regista.target_store_bound",
            "regista.target_project_bound",
            "regista.observation_snapshot_bound",
            f"regista.store_empty:{project}",
            f"regista.lineage_population_empty:{project}",
            f"regista.lineage_tokens_resolvable:{project}",
            f"regista.lineage_unambiguous:{project}",
            f"regista.asymmetric_only:{project}",
            f"regista.authors_declared:{project}",
            f"regista.model_observation_population_empty:{project}",
        }
    )
    if (
        malformed_finding
        or len(finding_ids) != len(set(finding_ids))
        or frozenset(finding_ids) != expected_findings
    ):
        _gate_refuse(
            "the gate report's findings are malformed, duplicated, non-passing, or do "
            "not exactly cover the v1 genesis contract",
            "gate_report_findings_invalid",
            reported_checks=sorted(finding_ids),
            expected_checks=sorted(expected_findings),
        )
    probes = raw.get("probes")
    if (
        not isinstance(probes, Mapping)
        or set(probes) != _PROBE_REPORT_KEYS
        or type(probes.get("report_version")) is not int
        or probes.get("report_version") != 1
        or probes.get("kind") != "invariant_probes"
        or probes.get("ok") is not True
        or not isinstance(probes.get("probes"), list)
    ):
        _gate_refuse(
            "the gate report's nested invariant-probe report is malformed or unhealthy",
            "gate_probe_report_invalid",
        )
    nested = probes["probes"]
    assert isinstance(nested, list)
    seen_components: set[str] = set()
    for probe in nested:
        if (
            not isinstance(probe, Mapping)
            or set(probe) != _PROBE_RESULT_KEYS
            or not isinstance(probe.get("component"), str)
            or probe.get("status") != "pass"
            or probe.get("ok") is not True
            or not isinstance(probe.get("detail"), str)
            or not probe.get("detail")
            or not isinstance(probe.get("checks"), list)
        ):
            _gate_refuse(
                "the gate report contains a malformed or unhealthy component probe",
                "gate_probe_result_invalid",
            )
        component = str(probe["component"])
        if component in seen_components or component not in _GATE_REQUIRED_PROBE_CHECKS:
            _gate_refuse(
                "the gate report contains a duplicate or unexpected component probe",
                "gate_probe_result_invalid",
                component=component,
            )
        seen_components.add(component)
        checks = probe["checks"]
        assert isinstance(checks, list)
        check_ids: list[str] = []
        for check in checks:
            if (
                not isinstance(check, Mapping)
                or not isinstance(check.get("id"), str)
                or check.get("status")
                != (
                    "measured"
                    if check.get("id") == "regista.store_invariant_measurements"
                    else "pass"
                )
            ):
                _gate_refuse(
                    "the gate report contains a malformed or non-passing probe check",
                    "gate_probe_check_invalid",
                    component=component,
                )
            check_ids.append(str(check["id"]))
            check_id = str(check["id"])
            if check_id == "regista.store_invariant_measurements":
                if not _gate_measurement_valid(
                    check,
                    project=project,
                    store_fingerprint=early_binding.get("reported_store_fingerprint"),
                    snapshot=early_snapshot,
                ):
                    _gate_refuse(
                        "the regista measurement body does not prove an empty target at "
                        "the report's named snapshot",
                        "gate_measurement_body_invalid",
                    )
            elif not isinstance(check.get("detail"), str) or not check.get("detail"):
                _gate_refuse(
                    "a behavioral probe check has no non-empty evidence detail",
                    "gate_probe_check_body_invalid",
                    check_id=check_id,
                )
            if check_id == "regista.actor_boundary_signing" and (
                check.get("claim") != "r10.no_arbitrary_principal.project_v6"
                or check.get("basis") != "behavioral_attempt_ephemeral_epoch"
                or not isinstance(check.get("paths_proven"), list)
                or not all(isinstance(item, str) for item in check["paths_proven"])
                or len(check["paths_proven"]) != 2
                or set(check["paths_proven"])
                != {
                    "regista._genesis.append_v6_genesis",
                    "regista._v6_writer.append_v6_event",
                }
                or not isinstance(check.get("shared_boundary_consumers"), list)
                or not all(
                    isinstance(item, str) for item in check["shared_boundary_consumers"]
                )
                or len(check["shared_boundary_consumers"]) != 1
                or set(check["shared_boundary_consumers"])
                != {"regista._trust_log_writer.append_trust_log_event"}
                or not isinstance(check.get("excluded_paths"), list)
                or not all(isinstance(item, str) for item in check["excluded_paths"])
                or len(check["excluded_paths"]) != 4
                or set(check["excluded_paths"])
                != {
                    "regista._cli.cmd_trust_init_log",
                    "regista._cli.cmd_trust_delegate_registrar",
                    "regista._cli._resolve_trust_root_actor",
                    "regista._trust_log_writer.write_trust_genesis",
                }
                or not isinstance(check.get("exclusion_reason"), str)
                or "WI-320" not in check["exclusion_reason"]
            ):
                _gate_refuse(
                    "the actor-boundary check does not carry the exact scoped R-10 evidence",
                    "gate_actor_boundary_scope_invalid",
                )
        if (
            len(check_ids) != len(set(check_ids))
            or frozenset(check_ids) != _GATE_REQUIRED_PROBE_CHECKS[component]
        ):
            _gate_refuse(
                "the gate report's component check coverage is incomplete or duplicated",
                "gate_probe_check_coverage_invalid",
                component=component,
            )
    if seen_components != set(_GATE_REQUIRED_PROBE_CHECKS):
        _gate_refuse(
            "the gate report does not contain every required component probe",
            "gate_probe_component_coverage_invalid",
            reported=sorted(seen_components),
            expected=sorted(_GATE_REQUIRED_PROBE_CHECKS),
        )

    binding = raw.get("binding")
    if not isinstance(binding, Mapping):
        _gate_refuse(
            "the gate report has no binding object, so it cannot be shown to be about "
            "this store and project",
            "gate_report_binding_absent",
        )
    assert isinstance(binding, Mapping)
    if set(binding) != _GATE_BINDING_KEYS:
        _gate_refuse(
            "the gate report binding has unknown or missing fields",
            "gate_report_binding_invalid",
        )
    expected_fp = postgres_database_fingerprint(dsn)
    if expected_fp is None:
        _gate_refuse(
            "could not compute the credential-free store fingerprint for the target "
            "DSN, so the gate report cannot be bound to it",
            "target_store_fingerprint_unavailable",
        )
    assert expected_fp is not None
    reported = binding.get("reported_store_fingerprint")
    declared = binding.get("expected_store_fingerprint")
    if reported != expected_fp or declared != expected_fp:
        _gate_refuse(
            "the gate report is bound to a different store than the one about to be "
            f"written: it reports {reported!r} (expected {declared!r}) but the target "
            f"DSN fingerprints as {expected_fp!r}. A PASS about another store is a real "
            "report about the wrong thing.",
            "gate_report_store_mismatch",
            reported_store_fingerprint=reported,
            expected_store_fingerprint=declared,
            target_store_fingerprint=expected_fp,
        )
    snapshot = binding.get("observation_snapshot")
    assert isinstance(snapshot, str)
    from ._jcs import canonicalize

    report_digest = "sha256:" + hashlib.sha256(canonicalize(raw)).hexdigest()
    return GateEvidence(
        path=path,
        report_version=version,
        store_fingerprint=expected_fp,
        project=project,
        observation_snapshot=snapshot,
        finding_count=len(findings),
        report_digest=report_digest,
    )


# ---------------------------------------------------------------------------
# The envelope
# ---------------------------------------------------------------------------


def _actor_kind_for(principal_id: str) -> str:
    """The v6 ``actor.kind`` implied by a canonical principal's kind (§2.6).

    ``service`` is spelled ``system`` on the row, so the mapping is not the identity.
    Derived rather than asked for: an operator-supplied actor kind that contradicts the
    principal id is a fact the envelope would sign.
    """
    from ._principals import classify_principal_id

    classification = classify_principal_id(principal_id)
    if not classification.canonical or classification.kind is None:
        _refuse(
            ErrorCode.INVALID_ARGUMENT,
            f"{principal_id!r} is not a canonical kind:subject principal id "
            "(TRUST-DOMAIN.md §2.1)",
            "principal_id_not_canonical",
            principal_id=principal_id,
        )
    return {"agent": "agent", "human": "human", "service": "system"}[
        str(classification.kind)
    ]


def validate_scope_entity_kinds(kinds: Sequence[str]) -> tuple[str, ...]:
    """Normalise and check the acceptance's ``entity_kinds``, refusing early.

    ``_genesis._validate_bootstrap_acceptance`` enforces the same rules on the finished
    envelope; doing it here means an operator typo is a clear CLI refusal naming the
    closed registry rather than a GENESIS_INVALID from deep inside the writer.
    """
    from ._verification import V6_ENTITY_KINDS

    ordered: list[str] = []
    for raw in kinds:
        for piece in str(raw).split(","):
            kind = piece.strip()
            if not kind:
                continue
            if kind not in V6_ENTITY_KINDS:
                _refuse(
                    ErrorCode.INVALID_ARGUMENT,
                    f"{kind!r} is not a v6 entity kind; the registry is closed: "
                    + ", ".join(sorted(V6_ENTITY_KINDS)),
                    "entity_kind_not_in_registry",
                    entity_kind=kind,
                )
            if kind not in ordered:
                ordered.append(kind)
    if not ordered:
        _refuse(
            ErrorCode.INVALID_ARGUMENT,
            "the bootstrap acceptance needs at least one entity kind",
            "entity_kinds_empty",
        )
    if "project" not in ordered:
        _refuse(
            ErrorCode.INVALID_ARGUMENT,
            "the bootstrap acceptance must include the 'project' entity kind, or it "
            "does not authorise the very genesis event it travels in",
            "entity_kinds_missing_project",
            entity_kinds=ordered,
        )
    return tuple(ordered)


@dataclass(frozen=True)
class PreviousEpoch:
    """The measured state of whatever the target store held before genesis.

    Under EPOCH-RESET there is no seam and no legacy prefix, so for a legitimate
    genesis every number here is zero or null — but they are MEASURED from the target
    store, not asserted. An honest zero and an assumed zero look identical in the
    signed bytes and are not the same claim (EPOCH-RESET §6 rule 3).
    """

    event_count: int
    archived_event_count: int
    head_event_hash: str | None
    genesis_event_hash: str | None
    max_global_seq: int | None
    scheme_counts: Mapping[str, int]

    @property
    def empty(self) -> bool:
        return (
            self.event_count == 0
            and self.archived_event_count == 0
            and self.head_event_hash is None
        )

    def as_payload_member(self) -> dict[str, Any]:
        return {
            "event_count": self.event_count,
            "genesis_event_hash": self.genesis_event_hash,
            "head_event_hash": self.head_event_hash,
            "head_hash_construction": "sha256(canonical_envelope||signature)",
            "max_global_seq": self.max_global_seq,
            "scheme_counts": dict(self.scheme_counts),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.as_payload_member(),
            "archived_event_count": self.archived_event_count,
        }


def measure_previous_epoch(conn: DictConn) -> PreviousEpoch:
    """Measure the target store's pre-genesis state on a read-only connection."""
    from ._genesis import _archived_count, _count_rows

    live = _count_rows(conn, "events")
    archived = _archived_count(conn)
    head_row = conn.execute(
        "SELECT head_hash FROM event_chain_head WHERE id = TRUE"
    ).fetchone()
    head = (
        None
        if head_row is None or head_row["head_hash"] is None
        else "sha256:" + bytes(head_row["head_hash"]).hex()
    )
    seq_row = conn.execute("SELECT MAX(global_seq) AS max_seq FROM events").fetchone()
    max_seq = None if seq_row is None or seq_row["max_seq"] is None else int(seq_row["max_seq"])
    scheme_rows = conn.execute(
        "SELECT scheme_id, COUNT(*) AS n FROM events GROUP BY scheme_id"
    ).fetchall()
    counts = {
        (row["scheme_id"] or "unset"): int(row["n"]) for row in scheme_rows
    }
    # Read rather than hardcode null. On the only store state that can legitimately
    # reach signed bytes this IS null (an empty store has no identity row), but a
    # hardcoded null would report a falsehood in the --dry-run plan for a store that
    # has already opened an epoch — and "measured null" and "assumed null" are not the
    # same claim even when they print identically.
    identity = conn.execute(
        "SELECT genesis_event_hash FROM project_identity WHERE id = TRUE"
    ).fetchone()
    genesis_hash = (
        None
        if identity is None or identity["genesis_event_hash"] is None
        else "sha256:" + bytes(identity["genesis_event_hash"]).hex()
    )
    return PreviousEpoch(
        event_count=live,
        archived_event_count=archived,
        head_event_hash=head,
        genesis_event_hash=genesis_hash,
        max_global_seq=max_seq,
        scheme_counts=counts,
    )


def build_project_initialized_envelope(
    *,
    project_instance_id: str,
    reference: TrustReference,
    producer: Mapping[str, Any],
    previous_epoch: PreviousEpoch,
    gate: GateEvidence,
    occurred_at: datetime,
    event_id: str | None = None,
    scope_entity_kinds: Sequence[str] = DEFAULT_SCOPE_ENTITY_KINDS,
    may_sign_bundles: bool = False,
) -> dict[str, Any]:
    """Build the ``project_initialized`` envelope from verified inputs.

    Every field that could be invented is instead taken from ``reference`` (verified
    against the live trust log) or ``previous_epoch`` (measured on the target store).
    The only free choices are the project instance id, the event id, the acceptance's
    project-local scopes — which have no trust-log counterpart, because §5.8 acceptance
    scopes ARE project-local — and the instant.

    ``may_accept_keys`` and ``may_sign_checkpoints`` are not parameters: the writer
    requires both to be exactly ``True`` (``_genesis.py:468``), because a bootstrap key
    that cannot accept another key leaves the project with no way to admit a second
    writer, which is the circularity RECONCILIATION Resolution 1 removed.
    """
    entity_kinds = validate_scope_entity_kinds(scope_entity_kinds)
    key = reference.key
    acceptance = {
        "principal_id": key.principal_id,
        "key_id": key.key_id,
        "scheme_id": "ed25519",
        "public_key": key.public_key_b64,
        "fingerprint": key.fingerprint,
        "trust_event_hash": key.trust_event_hash,
        "trust_log_checkpoint": reference.checkpoint.as_payload_member(),
        "scopes": {
            "entity_kinds": list(entity_kinds),
            # None means "no transition restriction". A list here would have to include
            # project_initialized or the acceptance would refuse the event carrying it.
            "transitions": None,
            "may_accept_keys": True,
            "may_sign_checkpoints": True,
            "may_sign_bundles": bool(may_sign_bundles),
        },
    }
    return {
        "type": "regista.event",
        "version": 6,
        "project_instance_id": project_instance_id,
        "trust_domain_id": reference.trust_domain_id,
        "event_id": event_id or str(_uuid.uuid4()),
        "entity": {"kind": "project", "id": project_instance_id},
        "entity_seq": 1,
        "actor": {
            "principal_id": key.principal_id,
            "kind": _actor_kind_for(key.principal_id),
            "metadata": {
                # Signed attribution of the exact suite verdict the actor accepted.
                # This authenticates the actor's assertion, not agent-suite as issuer;
                # report v1 has no issuer signature. The writer's locked
                # first_write_admission remains the current-store authority.
                "genesis_gate": {
                    "report_version": gate.report_version,
                    "report_digest": gate.report_digest,
                    "observation_snapshot": gate.observation_snapshot,
                    "store_fingerprint": gate.store_fingerprint,
                    "project": gate.project,
                }
            },
        },
        "signing": {
            "scheme_id": "ed25519",
            "key_id": key.key_id,
            # The genesis key's binding is EXTERNAL — the trust log — so there is no
            # preceding project event to point at. The writer refuses a non-null value.
            "key_binding_event_hash": None,
        },
        "authorization": {"mode": "direct", "credentials": []},
        "workflow": None,
        "occurred_at": _iso_micro_z(occurred_at),
        "transition": "project_initialized",
        "payload": {
            "bootstrap_key_acceptance": acceptance,
            "genesis_document_digest": reference.genesis_document_digest,
            "previous_epoch": previous_epoch.as_payload_member(),
            "trust_domain_core_digest": reference.trust_domain_core_digest,
            "trust_log_checkpoint": reference.checkpoint.as_payload_member(),
        },
        "chain": {
            "hash_algorithm": "sha-256",
            "previous_entity_event_hash": None,
            "previous_project_event_hash": None,
        },
        "producer": dict(producer),
    }


__all__ = [
    "DEFAULT_SCOPE_ENTITY_KINDS",
    "SUPPORTED_GATE_REPORT_VERSIONS",
    "TRUST_CHECKPOINT_SIGNATURE_DOMAIN",
    "TRUST_CHECKPOINT_TYPE",
    "TRUST_LOG_OBSERVATION_TYPE",
    "EnrolledKey",
    "GateEvidence",
    "PreviousEpoch",
    "TrustLogCheckpoint",
    "TrustReference",
    "build_project_initialized_envelope",
    "derive_trust_log_checkpoint",
    "load_gate_evidence",
    "load_published_checkpoint",
    "measure_previous_epoch",
    "resolve_enrolled_key",
    "resolve_trust_reference",
    "validate_scope_entity_kinds",
]
