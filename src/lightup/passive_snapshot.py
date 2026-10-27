"""Opt-in, network-free passive prospect snapshot reference.

This separate module deliberately does not replace or wire the legacy
``lightup.discovery.ProspectProfile``. It grants no scan authority, does no
target lookup and is a conservative immutable reference for issue #936.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import NamedTuple

from .discovery import ProspectSignal, SignalCategory


MAX_SNAPSHOT_SIGNALS = 256
MAX_TEXT_CHARACTERS = 4096


class AdmittedPublicSignal(NamedTuple):
    """An immutable copy of a separately validated public-only signal."""

    category: SignalCategory
    summary: str
    source: str
    confidence: float
    public_source: bool
    requires_target_interaction: bool


def _canonical_text(value: object, label: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{label} must be exact non-empty text")
    if len(value) > MAX_TEXT_CHARACTERS:
        raise ValueError(f"{label} exceeds snapshot text budget")
    return value


def _validate_public_record(record: AdmittedPublicSignal) -> None:
    if type(record) is not AdmittedPublicSignal:
        raise ValueError("signal record must have canonical identity")
    if type(record.category) is not SignalCategory:
        raise ValueError("signal category must be canonical")
    _canonical_text(record.summary, "signal summary")
    _canonical_text(record.source, "signal source")
    if type(record.confidence) is not float or not math.isfinite(record.confidence):
        raise ValueError("signal confidence must be an exact finite float")
    if not 0.0 <= record.confidence <= 1.0:
        raise ValueError("signal confidence must be in [0, 1]")
    if type(record.public_source) is not bool:
        raise ValueError("public source flag must be an exact bool")
    if type(record.requires_target_interaction) is not bool:
        raise ValueError("interaction flag must be an exact bool")
    if not record.public_source:
        raise PermissionError("only public sources may be admitted")
    if record.requires_target_interaction:
        raise PermissionError("passive snapshots cannot require target interaction")


def _copy_public_signal(signal: ProspectSignal) -> AdmittedPublicSignal:
    # Object identity is checked *before* any user-defined method dispatch.
    if type(signal) is not ProspectSignal:
        raise ValueError("signal must be an exact ProspectSignal")
    copied = AdmittedPublicSignal(
        signal.category,
        signal.summary,
        signal.source,
        signal.confidence,
        signal.public_source,
        signal.requires_target_interaction,
    )
    _validate_public_record(copied)
    return copied


@dataclass(frozen=True, slots=True)
class PassiveProspectSnapshot:
    """Immutable, non-authorizing public-discovery state.

    No mutable caller-owned signal collection is retained. Adding a signal
    returns a new snapshot and never changes the existing one. This is a
    value model for offline review, not a replacement authorization gate.
    """

    prospect_id: str
    organization_name: str
    signals: tuple[AdmittedPublicSignal, ...] = ()

    def __post_init__(self) -> None:
        _canonical_text(self.prospect_id, "prospect id")
        _canonical_text(self.organization_name, "organization name")
        if type(self.signals) is not tuple:
            raise ValueError("signals must be an exact immutable tuple")
        if len(self.signals) > MAX_SNAPSHOT_SIGNALS:
            raise ValueError("snapshot signal limit exceeded")
        for signal in self.signals:
            _validate_public_record(signal)

    @property
    def confidence(self) -> float:
        if not self.signals:
            return 0.0
        return sum(item.confidence for item in self.signals) / len(self.signals)

    @classmethod
    def from_signals(
        cls,
        prospect_id: str,
        organization_name: str,
        signals: tuple[ProspectSignal, ...],
    ) -> PassiveProspectSnapshot:
        if cls is not PassiveProspectSnapshot:
            raise TypeError("snapshot builder must have canonical identity")
        if type(signals) is not tuple:
            raise ValueError("input signals must be an exact tuple")
        if len(signals) > MAX_SNAPSHOT_SIGNALS:
            raise ValueError("snapshot signal limit exceeded")
        # Atomic construction: every item is copied and vetted *before* a
        # snapshot is made available to its caller.
        copied = tuple(_copy_public_signal(item) for item in signals)
        return cls(prospect_id, organization_name, copied)

    def with_signal(self, signal: ProspectSignal) -> PassiveProspectSnapshot:
        if type(self) is not PassiveProspectSnapshot:
            raise TypeError("snapshot instance must have canonical identity")
        if len(self.signals) >= MAX_SNAPSHOT_SIGNALS:
            raise ValueError("snapshot signal limit exceeded")
        return PassiveProspectSnapshot(
            self.prospect_id,
            self.organization_name,
            self.signals + (_copy_public_signal(signal),),
        )
