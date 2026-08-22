from __future__ import annotations

import pytest

from regista._replay import _is_expected_unpinned_bootstrap
from regista._verification import Applicability, FailureReason


@pytest.mark.parametrize(
    ("entity_kind", "transition"),
    [
        ("trust_domain", "trust_domain_established"),
        ("project", "project_cryptographic_epoch_started"),
        ("project", "project_initialized"),
    ],
)
def test_only_legal_bootstrap_targets_receive_the_external_anchor_exemption(
    entity_kind: str,
    transition: str,
) -> None:
    assert _is_expected_unpinned_bootstrap(
        entity_kind=entity_kind,
        transition=transition,
        applicability=Applicability.UNVERIFIABLE,
        reasons=(FailureReason.KEY_BINDING_UNRESOLVED,),
    )


def test_note_cannot_claim_the_external_bootstrap_exemption() -> None:
    assert not _is_expected_unpinned_bootstrap(
        entity_kind="note",
        transition="project_initialized",
        applicability=Applicability.UNVERIFIABLE,
        reasons=(FailureReason.KEY_BINDING_UNRESOLVED,),
    )
