"""Test-import shim for the real, still UNWIRED helper in src/lightup.

Review success is a SHAPE observation, not authorization or consent.
No runtime or source owner imports this test module.
"""
from lightup.persisted_scope_entries_639 import (
    PersistedScopeEntries as ReviewedScopeEntries,
    review_persisted_scope_entries as review_scope_entries,
)

__all__ = ("ReviewedScopeEntries", "review_scope_entries")
