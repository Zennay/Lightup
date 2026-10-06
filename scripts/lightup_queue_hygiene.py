#!/usr/bin/env python3
"""Fail-closed cleanup of stale superseded self-hosted GitHub Actions runs.

The utility is intentionally conservative:
- dry-run by default;
- protects the current default-branch head, current workflow run, and all open PR heads;
- only stale queued runs with at least one queued self-hosted job can be cancelled.
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any


API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed.astimezone(timezone.utc)


def classify_run(
    run: dict[str, Any],
    jobs: list[dict[str, Any]],
    *,
    protected_shas: set[str],
    now: datetime,
    minimum_age_seconds: int,
    current_run_id: int | None = None,
) -> tuple[bool, str]:
    """Return (candidate_for_cancel, reason)."""

    run_id = int(run["id"])
    if current_run_id is not None and run_id == current_run_id:
        return False, "current-run"

    if str(run.get("status") or "") != "queued":
        return False, "not-queued"

    head_sha = str(run.get("head_sha") or "")
    if not head_sha:
        return False, "missing-head-sha"
    if head_sha in protected_shas:
        return False, "protected-head"

    created_at = parse_utc(str(run["created_at"]))
    age_seconds = int((now - created_at).total_seconds())
    if age_seconds < minimum_age_seconds:
        return False, "too-recent"

    queued_self_hosted = any(
        str(job.get("status") or "") == "queued"
        and "self-hosted" in {str(label).lower() for label in (job.get("labels") or [])}
        for job in jobs
    )
    if not queued_self_hosted:
        return False, "not-queued-self-hosted"

    return True, "stale-superseded-self-hosted"


class GitHubApi:
    def __init__(self, token: str) -> None:
        if not token:
            raise ValueError("GitHub token is required")
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "lightup-queue-hygiene/1",
        }

    def request(self, path: str, *, method: str = "GET") -> Any:
        request = urllib.request.Request(
            API_ROOT + path,
            method=method,
            headers=self.headers,
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read()
            return json.loads(raw) if raw else {}

    def paged(self, path: str, *, key: str | None = None) -> list[dict[str, Any]]:
        page = 1
        items: list[dict[str, Any]] = []
        separator = "&" if "?" in path else "?"
        while True:
            payload = self.request(f"{path}{separator}per_page=100&page={page}")
            chunk = payload.get(key, []) if key else payload
            if not isinstance(chunk, list):
                raise ValueError("GitHub pagination payload is not a list")
            items.extend(chunk)
            if len(chunk) < 100:
                return items
            page += 1


def _run_summary(run: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "id": int(run["id"]),
        "name": str(run.get("name") or ""),
        "head_sha": str(run.get("head_sha") or ""),
        "created_at": str(run.get("created_at") or ""),
        "reason": reason,
    }


def execute(
    *,
    api: GitHubApi,
    repo: str,
    apply: bool,
    minimum_age_seconds: int,
    current_run_id: int | None,
    current_sha: str | None,
    now: datetime,
) -> dict[str, Any]:
    if "/" not in repo:
        raise ValueError("repo must be in owner/name form")
    if minimum_age_seconds < 0:
        raise ValueError("minimum_age_seconds must be non-negative")

    repo_info = api.request(f"/repos/{repo}")
    default_branch = str(repo_info["default_branch"])
    encoded_branch = urllib.parse.quote(default_branch, safe="")
    default_head = str(api.request(f"/repos/{repo}/commits/{encoded_branch}")["sha"])

    open_prs = api.paged(f"/repos/{repo}/pulls?state=open")
    protected_shas = {default_head}
    if current_sha:
        protected_shas.add(current_sha)

    protected_pr_heads: dict[str, int] = {}
    for pull in open_prs:
        sha = str((pull.get("head") or {}).get("sha") or "")
        if not sha:
            continue
        protected_shas.add(sha)
        protected_pr_heads[sha] = int(pull["number"])

    queued_runs = api.paged(
        f"/repos/{repo}/actions/runs?status=queued",
        key="workflow_runs",
    )

    candidates: list[dict[str, Any]] = []
    retained: list[dict[str, Any]] = []

    for run in queued_runs:
        jobs: list[dict[str, Any]] = []
        pre_candidate, pre_reason = classify_run(
            run,
            jobs,
            protected_shas=protected_shas,
            now=now,
            minimum_age_seconds=minimum_age_seconds,
            current_run_id=current_run_id,
        )
        if pre_reason not in {"not-queued-self-hosted"}:
            retained.append(_run_summary(run, pre_reason))
            continue

        jobs = api.paged(
            f"/repos/{repo}/actions/runs/{int(run['id'])}/jobs?filter=latest",
            key="jobs",
        )
        candidate, reason = classify_run(
            run,
            jobs,
            protected_shas=protected_shas,
            now=now,
            minimum_age_seconds=minimum_age_seconds,
            current_run_id=current_run_id,
        )
        summary = _run_summary(run, reason)
        if candidate:
            candidates.append(summary)
        else:
            retained.append(summary)

    cancelled: list[dict[str, Any]] = []
    cancellation_conflicts: list[dict[str, Any]] = []

    if apply:
        for candidate in candidates:
            try:
                api.request(
                    f"/repos/{repo}/actions/runs/{candidate['id']}/cancel",
                    method="POST",
                )
                cancelled.append(candidate)
            except urllib.error.HTTPError as exc:
                if exc.code not in {409, 422}:
                    raise
                conflict = dict(candidate)
                conflict["reason"] = f"cancel-http-{exc.code}"
                cancellation_conflicts.append(conflict)

    return {
        "ok": True,
        "mode": "apply" if apply else "dry-run",
        "repo": repo,
        "default_branch": default_branch,
        "default_head": default_head,
        "protected_open_pr_heads": len(protected_pr_heads),
        "minimum_age_seconds": minimum_age_seconds,
        "queued_run_count": len(queued_runs),
        "candidate_count": len(candidates),
        "candidates": candidates,
        "cancelled_count": len(cancelled),
        "cancelled": cancelled,
        "cancellation_conflicts": cancellation_conflicts,
        "retained_count": len(retained),
        "retained": retained,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    parser.add_argument("--minimum-age-seconds", type=int, default=7200)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument(
        "--current-run-id",
        type=int,
        default=int(os.environ["GITHUB_RUN_ID"]) if os.environ.get("GITHUB_RUN_ID") else None,
    )
    parser.add_argument("--current-sha", default=os.environ.get("GITHUB_SHA"))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
    receipt = execute(
        api=GitHubApi(token),
        repo=args.repo,
        apply=args.apply,
        minimum_age_seconds=args.minimum_age_seconds,
        current_run_id=args.current_run_id,
        current_sha=args.current_sha,
        now=datetime.now(timezone.utc),
    )
    print("LIGHTUP_QUEUE_HYGIENE=" + json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
