from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from regista._errors import ErrorCode, RegistaError
from regista.testing import InMemoryRegista

TESTS_DIR = Path(__file__).parent
WORKFLOW_PATH = str(TESTS_DIR / "test_workflow.yaml")


@pytest.fixture
def insub():
    s = InMemoryRegista(project="test")
    s.register_workflow_file(WORKFLOW_PATH)
    yield s
    s.close()


class TestActorIdValidation:
    def test_create_work_item_rejects_overlong(self, insub):
        long_id = "x" * 256
        with pytest.raises(RegistaError) as exc_info:
            insub.create_work_item(
                workflow_name="test_workflow",
                work_item_type="feature",
                actor_id=long_id,
            )
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_register_actor_role_rejects_overlong(self, insub):
        long_id = "x" * 256
        with pytest.raises(RegistaError) as exc_info:
            insub.register_actor_role(long_id, "agent")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT

    def test_unregister_actor_role_rejects_overlong(self, insub):
        long_id = "x" * 256
        with pytest.raises(RegistaError) as exc_info:
            insub.unregister_actor_role(long_id, "agent")
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT


class TestTokenRegistryValidation:
    def test_rejects_missing_tokens_key(self):
        from regista.sidecar.auth import TokenRegistry

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            import json

            json.dump({"not_tokens": []}, f)
            f.flush()
            path = f.name
        with pytest.raises(RegistaError) as exc_info:
            TokenRegistry.from_file(path)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT
        assert "tokens" in exc_info.value.message.lower()

    def test_rejects_entry_missing_actor_id(self):
        from regista.sidecar.auth import TokenRegistry

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            import json

            json.dump({"tokens": [{"token_sha256": "abc123"}]}, f)
            f.flush()
            path = f.name
        with pytest.raises(RegistaError) as exc_info:
            TokenRegistry.from_file(path)
        assert exc_info.value.code == ErrorCode.INVALID_ARGUMENT
        assert "actor_id" in exc_info.value.message.lower()
