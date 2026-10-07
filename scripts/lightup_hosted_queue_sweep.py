#!/usr/bin/env python3
"""Pure safety helpers for hosted LightUp self-hosted queue recovery."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

CANONICAL_WORKFLOW_NAME = "LightUp CI"
CANONICAL_WORKFLOW_PATH = ".github/workflows/lightup-ci.yml"
SELF_HOSTED_LABEL = "self-hosted"


class PaginationSafetyError(RuntimeError):
    pass


def paged(
    request: Callable[[str], Any],
    path_prefix: str,
    *,
    max_pages: int,
) -> tuple[list[dict[str, Any]], int]:
    if max_pages < 1:
        raise ValueError("max_pages must be positive")
    items: list[dict[str, Any]] = []
    for page in range(1, max_pages + 1):
        separator = "&" if "?" in path_prefix else "?"
        payload = request(f"{path_prefix}{separator}per_page=100&page={page}")
        page_items = payload if isinstance(payload, list) else payload.get("workflow_runs") or []
        if not isinstance(page_items, list):
            raise TypeError("paginated response must contain a list")
        items.extend(page_items)
        if len(page_items) < 100:
            return items, page
    raise PaginationSafetyError(
        f"pagination hit safety cap ({max_pages} pages); refusing partial inventory"
    )


def protected_shas(
    *,
    default_head: str,
    current_sha: str,
    explicit_evidence_sha: str,
    open_prs: list[dict[str, Any]],
) -> tuple[set[str], dict[str, int]]:
    protected = {
        str(default_head).strip(),
        str(current_sha).strip(),
        str(explicit_evidence_sha).strip(),
    }
    protected.discard("")
    pr_by_sha: dict[str, int] = {}
    for pr in open_prs:
        sha = str((pr.get("head") or {}).get("sha") or "").strip()
        number = pr.get("number")
        if not sha or not isinstance(number, int):
            raise ValueError("open PR inventory contains malformed head identity")
        protected.add(sha)
        pr_by_sha[sha] = number
    return protected, pr_by_sha


def queued_self_hosted_jobs(jobs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    selected = []
    for job in jobs:
        labels = {str(label).lower() for label in (job.get("labels") or [])}
        if str(job.get("status") or "") == "queued" and SELF_HOSTED_LABEL in labels:
            selected.append(job)
    return selected


def cancellation_candidate(
    run: dict[str, Any],
    *,
    protected: set[str],
    now: datetime,
    minimum_age_seconds: int,
    jobs: list[dict[str, Any]],
) -> tuple[bool, str]:
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if minimum_age_seconds < 0:
        raise ValueError("minimum_age_seconds must be non-negative")

    if str(run.get("name") or "") != CANONICAL_WORKFLOW_NAME:
        return False, "not-canonical-lightup-ci"
    if str(run.get("path") or "") != CANONICAL_WORKFLOW_PATH:
        return False, "not-canonical-lightup-ci"

    head_sha = str(run.get("head_sha") or "").strip()
    if not head_sha:
        return False, "missing-head-sha"
    if head_sha in protected:
        return False, "protected-head"

    created_raw = str(run.get("created_at") or "")
    try:
        created = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
    except ValueError:
        return False, "invalid-created-at"
    if created.tzinfo is None:
        return False, "invalid-created-at"

    age_seconds = int((now.astimezone(timezone.utc) - created.astimezone(timezone.utc)).total_seconds())
    if age_seconds < minimum_age_seconds:
        return False, "too-recent"
    if not queued_self_hosted_jobs(jobs):
        return False, "not-queued-self-hosted"
    return True, "stale-superseded-queued-self-hosted"
