from __future__ import annotations

from regista._lint import resolve_model_lineage, stamp_model_lineage


class TestResolveModelLineage:
    def test_resolves_canonical_var(self):
        assert resolve_model_lineage({"REGISTA_MODEL_LINEAGE": "gpt-sol"}) == "gpt-sol"

    def test_canonical_takes_precedence(self):
        env = {
            "REGISTA_MODEL_LINEAGE": "gpt-sol",
            "AGENT_MODEL_LINEAGE": "other",
            "MODEL_LINEAGE": "fallback",
        }
        assert resolve_model_lineage(env) == "gpt-sol"

    def test_falls_back_through_vars(self):
        assert resolve_model_lineage({"MODEL_LINEAGE": "glm"}) == "glm"
        assert resolve_model_lineage({"AGENT_MODEL_LINEAGE": "kimi"}) == "kimi"

    def test_strips_whitespace(self):
        assert resolve_model_lineage({"REGISTA_MODEL_LINEAGE": "  gpt-sol  "}) == "gpt-sol"

    def test_none_when_unset(self):
        assert resolve_model_lineage({}) is None

    def test_none_when_blank(self):
        assert resolve_model_lineage({"REGISTA_MODEL_LINEAGE": "   "}) is None


class TestStampModelLineage:
    def test_stamps_agent_with_resolved_lineage(self):
        result = stamp_model_lineage(
            {"role": "agent"}, "agent", environ={"REGISTA_MODEL_LINEAGE": "gpt-sol"}
        )
        assert result == {"role": "agent", "model_lineage": "gpt-sol"}

    def test_stamps_none_metadata_for_agent(self):
        result = stamp_model_lineage(None, "agent", environ={"REGISTA_MODEL_LINEAGE": "glm"})
        assert result == {"model_lineage": "glm"}

    def test_never_overwrites_declared_lineage(self):
        result = stamp_model_lineage(
            {"model_lineage": "declared"},
            "agent",
            environ={"REGISTA_MODEL_LINEAGE": "resolved"},
        )
        assert result == {"model_lineage": "declared"}

    def test_passthrough_when_no_lineage_resolvable(self):
        original = {"role": "agent"}
        result = stamp_model_lineage(original, "agent", environ={})
        assert result == {"role": "agent"}

    def test_non_agent_is_untouched(self):
        result = stamp_model_lineage(
            {"role": "reviewer"}, "human", environ={"REGISTA_MODEL_LINEAGE": "gpt-sol"}
        )
        assert result == {"role": "reviewer"}

    def test_does_not_mutate_input(self):
        original = {"role": "agent"}
        stamp_model_lineage(original, "agent", environ={"REGISTA_MODEL_LINEAGE": "gpt-sol"})
        assert original == {"role": "agent"}
