#!/usr/bin/env python3
"""Continue an original HUMAN workpack without inventing any HUMAN decision.

The same native private-owner and session PATH snapshot admission applies.
This is not an assessment execution, schedule, grant or review approval.
"""
from __future__ import annotations

from pathlib import Path

import human_priorities
import human_workpack
import private_session as privacy
import route_queue
import workpack_progress


def build(session, original_workpack_folder: str, parent_name: str,
          new_name: str, declared_review_date: str) -> Path:
    # Validate the new operator-declared review context independently.
    human_priorities.as_of(declared_review_date)
    if type(original_workpack_folder) is not str:
        raise privacy.Hold("HOLD: original workpack folder must be literal")
    # The new workpack must never be created *inside* the old workpack.
    original_dir = Path(original_workpack_folder).resolve(strict=True)
    output_parent = Path(parent_name).resolve(strict=True)
    if original_dir == output_parent or original_dir in output_parent.parents:
        raise privacy.Hold("HOLD: continued workspace cannot modify old workpack tree")
    base, _ = route_queue.rows_for(session)
    previous_date, rows, pinned_bytes = workpack_progress.original_workpack(
        original_workpack_folder, base)
    # No automated stage transitions, implicit date rollover, team edits,
    # risk decisions, or missing-source repair. Preserve *all* original
    # explicitly entered HUMAN selections and private follow-up questions.
    if len(rows) != len(base) or not previous_date:
        raise privacy.Hold("HOLD: complete original HUMAN workpack is required")
    # The original native composer re-admits EXACTLY these already validated
    # descriptor bytes for every separate child without rereading source.
    return human_workpack.build(
        session, "", parent_name, new_name, declared_review_date,
        original_snapshot=pinned_bytes)
