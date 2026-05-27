from __future__ import annotations

import inspect
import uuid
from pathlib import Path

import pytest

from regista.testing import drop_project_schema

DSN = "postgresql://regista_test:regista_test@localhost:5432/regista_test"
KEY_PATH = str(Path(__file__).parent / "test_keys.json")


class TestAC33PreSignedRejection:
    def test_public_api_has_no_signature_params(self):
        from regista import Regista

        methods = [
            Regista.append_event,
            Regista.transition,
            Regista.create_work_item,
            Regista.register_workflow,
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
        from regista._types import Event

        annotations = Event.__dataclass_fields__
        for field_name, field in annotations.items():
            type_str = str(field.type)
            for pg in self.PG_TYPES:
                assert pg not in type_str, (
                    f"Event.{field_name} references Postgres type: {type_str}"
                )

    def test_work_item_no_pg_types(self):
        from regista._types import WorkItem

        annotations = WorkItem.__dataclass_fields__
        for field_name, field in annotations.items():
            type_str = str(field.type)
            for pg in self.PG_TYPES:
                assert pg not in type_str, (
                    f"WorkItem.{field_name} references Postgres type: {type_str}"
                )

    def test_claim_no_pg_types(self):
        from regista._types import Claim

        annotations = Claim.__dataclass_fields__
        for field_name, field in annotations.items():
            type_str = str(field.type)
            for pg in self.PG_TYPES:
                assert pg not in type_str, (
                    f"Claim.{field_name} references Postgres type: {type_str}"
                )

    def test_regista_public_api_no_pg_imports(self):
        import regista

        public_names = [name for name in dir(regista) if not name.startswith("_")]
        for name in public_names:
            obj = getattr(regista, name)
            if inspect.isclass(obj):
                module = getattr(obj, "__module__", "")
                assert "psycopg" not in module, (
                    f"regista.{name} is from psycopg module: {module}"
                )


class TestBC195ConstructorPositionalContract:
    # BC-195: pin the positional signature Regista(dsn, project, hmac_key_path)
    # used by downstream consumers (sf2 build_failure_corpus.py:148).
    # Any change to __init__ that breaks this shape should fail here first.

    @pytest.fixture(autouse=True)
    def _cleanup(self):
        self._project = f"bc195_{uuid.uuid4().hex[:8]}"
        yield
        drop_project_schema(DSN, self._project)

    def test_positional_constructor_matches_sf2_call_shape(self):
        from regista import Regista

        Regista.create_project(DSN, self._project, KEY_PATH)

        sub = Regista(DSN, self._project, KEY_PATH)
        try:
            assert sub.connection_info.project == self._project
        finally:
            sub.close()
