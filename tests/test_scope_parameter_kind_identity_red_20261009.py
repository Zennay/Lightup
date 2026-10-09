"""Offline RED contract: registry parameter kind must be a canonical ParamKind.

No dispatch, network, DNS, live authorization, or target interaction.
Production integration belongs to the ToolRegistry/executor source owners.
"""
import unittest

from lightup.ai.orchestration import (
    OrchestrationError,
    ParamKind,
    ToolDefinition,
    ToolParameter,
)
from lightup.engagements import RiskLevel
from lightup.execution_policy import InteractionKind


def definition(kind):
    return ToolDefinition(
        tool_id="synthetic.shape",
        capability_id="synthetic",
        interaction=InteractionKind.ANALYSIS,
        min_risk=RiskLevel.ANALYSIS_ONLY,
        description="inert shape fixture",
        parameters=(ToolParameter(name="destination", kind=kind),),
    )


class AcceptAnythingKind:
    """Simulates a forged runtime metadata object, never a trusted kind."""

    value = "string"

    def accepts(self, value):
        return True


class ParameterKindIdentityContract(unittest.TestCase):
    def test_canonical_string_accepts_text(self):
        definition(ParamKind.STRING).validate_arguments({"destination": "offline-only"})

    def test_canonical_string_rejects_number(self):
        with self.assertRaises(OrchestrationError):
            definition(ParamKind.STRING).validate_arguments({"destination": 3})

    @unittest.expectedFailure
    def test_forged_parameter_kind_must_not_accept_invalid_value(self):
        # RED until registry-owned metadata validates exact ParamKind identity.
        with self.assertRaises(OrchestrationError):
            definition(AcceptAnythingKind()).validate_arguments({"destination": 3})

    @unittest.expectedFailure
    def test_string_literal_kind_must_not_be_accepted_as_enum(self):
        # A string annotation is not a runtime trust boundary.
        with self.assertRaises(OrchestrationError):
            definition("string").validate_arguments({"destination": "offline-only"})


if __name__ == "__main__":
    unittest.main()
