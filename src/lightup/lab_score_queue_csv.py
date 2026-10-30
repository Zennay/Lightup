"""Bounded, source-free CSV exports for a validated synthetic HUMAN queue.

CSV contains only derived integers, fixed enumerations and explicit global
HOLD/PASS and false authority flags: no formulas or private source fields.
"""
from __future__ import annotations
import csv
from io import StringIO
from typing import Any


def _csv(columns: tuple[str, ...], records: list[dict[str, object]]) -> bytes:
    buffer = StringIO(newline='')
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator='\n',
                            extrasaction='raise')
    writer.writeheader()
    for record in records:
        for key, value in record.items():
            if (type(value) not in (str, int) or
                (type(value) is str and (not value or value[0] in '=+-@\t\r\n'))):
                raise ValueError('unsafe CSV value')
        writer.writerow(record)
    return buffer.getvalue().encode('utf-8')


def render_queue_csv(queue: dict[str, Any], *, global_status: str) -> dict[str, bytes]:
    if global_status not in ('PASS', 'HOLD'):
        raise ValueError('invalid queue status')
    if queue['pairs_checked'] != len(queue['pairs']) or len(queue['pairs']) > 28:
        raise ValueError('queue pair count is not bounded')
    if len(queue['archive_priorities']) > 8:
        raise ValueError('too many archive priorities')
    archives: list[dict[str, object]] = []
    for rank, item in enumerate(queue['archive_priorities'], 1):
        archives.append({
            'priority': rank,
            'archive_index': item['index'],
            'hold_pairs': item['hold_pairs'],
            'evidence_reuse_pairs': item['reused_evidence_pairs'],
            'score_drift_pairs': item['score_drift_pairs'],
            'global_status': global_status,
            'original_source_authenticated': 'false',
            'authorization_granted': 'false',
        })
    pairs: list[dict[str, object]] = []
    for rank, item in enumerate(queue['pairs'], 1):
        pairs.append({
            'priority': rank,
            'previous_archive': item['previous_index'],
            'current_archive': item['current_index'],
            'pair_status': item['review_status'],
            'evidence_reused': str('evidence_reused' in item['hold_reasons']).lower(),
            'score_drift': str('score_drift' in item['hold_reasons']).lower(),
            'global_status': global_status,
            'original_source_authenticated': 'false',
            'authorization_granted': 'false',
        })
    return {
        'queue_archives.csv': _csv(tuple(archives[0]) if archives else (
            'priority', 'archive_index', 'hold_pairs', 'evidence_reuse_pairs',
            'score_drift_pairs', 'global_status', 'original_source_authenticated',
            'authorization_granted'), archives),
        'queue_pairs.csv': _csv(tuple(pairs[0]) if pairs else (
            'priority', 'previous_archive', 'current_archive', 'pair_status',
            'evidence_reused', 'score_drift', 'global_status',
            'original_source_authenticated', 'authorization_granted'), pairs),
    }
