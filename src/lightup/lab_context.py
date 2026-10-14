"""Shared fail-closed validation for direct lab worker handlers.

ToolExecutor is the primary policy boundary, but worker handlers are callable
Python functions and therefore keep their own defense-in-depth check. A lab
marker alone is not enough provenance: the immutable RunContext must remain a
lab-autonomous context and must never carry real-target authorization.
"""

from __future__ import annotations

from .ai.orchestration import RunContext
from .engagements import AssessmentMode
from .labeval import LabIsolationError


def require_lab_worker_context(context: RunContext) -> None:
    """Reject any context that is not semantically an exact lab run."""
    if context.is_lab is not True:
        raise LabIsolationError("lab workers require an exact boolean lab context")
    if context.mode is not AssessmentMode.LAB_AUTONOMOUS:
        raise LabIsolationError("lab workers require LAB_AUTONOMOUS mode")
    if context.authorization is not None:
        raise LabIsolationError("lab workers cannot carry target authorization")
