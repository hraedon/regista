"""Removed-key explanations must never overlap schema acceptance."""
from __future__ import annotations

import copy
from typing import Any

import pytest

from regista.kernel import WORKFLOW_DOCUMENT_REMOVED_KEYS, workflow_schema


def assert_removed_keys_disjoint(schema: dict[str, Any]) -> None:
    shapes = {
        'document': schema['properties'],
        'transition': schema['properties']['transitions']['items']['properties'],
    }
    for context, keys in WORKFLOW_DOCUMENT_REMOVED_KEYS.items():
        assert not (keys.keys() & shapes[context].keys()), context


def test_removed_keys_do_not_overlap_accepted_schema_keys() -> None:
    assert_removed_keys_disjoint(workflow_schema())


@pytest.mark.parametrize('context', ['document', 'transition'])
def test_removed_key_pin_can_fail(context: str) -> None:
    schema = copy.deepcopy(workflow_schema())
    properties = schema['properties']
    if context == 'transition':
        properties = properties['transitions']['items']['properties']
    properties[next(iter(WORKFLOW_DOCUMENT_REMOVED_KEYS[context]))] = {}
    with pytest.raises(AssertionError, match=context):
        assert_removed_keys_disjoint(schema)
