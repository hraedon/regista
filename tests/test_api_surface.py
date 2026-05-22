from __future__ import annotations

import inspect
import uuid
from pathlib import Path

import pytest

from substrate.testing import drop_project_schema

DSN = "postgresql://substrate_test:substrate_test@localhost:5432/substrate_test"
KEY_PATH = str(Path(__file__).parent / "test_keys.json")


class TestAC33PreSignedRejection:
    def test_public_api_has_no_signature_params(self):
        from substrate import Substrate

        methods = [
            Substrate.append_event,
            Substrate.transition,
            Substrate.create_work_item,
            Substrate.register_workflow,
        ]
        for method in methods:
            sig = inspect.signature(method)
            assert "signature" not in sig.parameters, (
                f"{method.__name__} accepts a 'signature' parameter"
            )
            assert "canonical_hash" not in sig.parameters, (
                f"{method.__name__} accepts a 'canonical_hash' parameter"
            )


class TestAC34NoPostgresTypesLeak:
    PG_TYPES: frozenset[str] = frozenset({"psycopg", "Connection", "Cursor", "ConnectionPool"})

    def test_event_no_pg_types(self):
        from substrate._types import Event

        annotations = Event.__dataclass_fields__
        for field_name, field in annotations.items():
            type_str = str(field.type)
            for pg in self.PG_TYPES:
                assert pg not in type_str, (
                    f"Event.{field_name} references Postgres type: {type_str}"
                )

    def test_work_item_no_pg_types(self):
        from substrate._types import WorkItem

        annotations = WorkItem.__dataclass_fields__
        for field_name, field in annotations.items():
            type_str = str(field.type)
            for pg in self.PG_TYPES:
                assert pg not in type_str, (
                    f"WorkItem.{field_name} references Postgres type: {type_str}"
                )

    def test_claim_no_pg_types(self):
        from substrate._types import Claim

        annotations = Claim.__dataclass_fields__
        for field_name, field in annotations.items():
            type_str = str(field.type)
            for pg in self.PG_TYPES:
                assert pg not in type_str, (
                    f"Claim.{field_name} references Postgres type: {type_str}"
                )

    def test_substrate_public_api_no_pg_imports(self):
        import substrate

        public_names = [name for name in dir(substrate) if not name.startswith("_")]
        for name in public_names:
            obj = getattr(substrate, name)
            if inspect.isclass(obj):
                module = getattr(obj, "__module__", "")
                assert "psycopg" not in module, (
                    f"substrate.{name} is from psycopg module: {module}"
                )


class TestBC195ConstructorPositionalContract:
    # BC-195: pin the positional signature Substrate(dsn, project, hmac_key_path)
    # used by downstream consumers (sf2 build_failure_corpus.py:148).
    # Any change to __init__ that breaks this shape should fail here first.

    @pytest.fixture(autouse=True)
    def _cleanup(self):
        self._project = f"bc195_{uuid.uuid4().hex[:8]}"
        yield
        drop_project_schema(DSN, self._project)

    def test_positional_constructor_matches_sf2_call_shape(self):
        from substrate import Substrate

        Substrate.create_project(DSN, self._project, KEY_PATH)

        sub = Substrate(DSN, self._project, KEY_PATH)
        try:
            assert sub.connection_info.project == self._project
        finally:
            sub.close()
