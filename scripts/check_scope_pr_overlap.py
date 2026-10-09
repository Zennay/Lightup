#!/usr/bin/env python3
"""Read-only GitHub PR path-ownership preflight for parallel LightUp workers.

This is a coordination gate, NOT an authorization grant or a production security
control. It never runs target requests or modifies GitHub/LightUp state.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class IncompleteEvidence(RuntimeError):
    """Unknown or incomplete remote state must never be reported as clear."""


_REPO_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]+$")
_PAGE_SIZE = 100


def validate_repo(value: str) -> str:
    parts = value.split("/")
    if len(parts) != 2 or not all(_REPO_COMPONENT.fullmatch(x) for x in parts):
        raise ValueError("repo must be an owner/name with plain GitHub components")
    if any(x in {".", ".."} for x in parts):
        raise ValueError("repo may not use dot path components")
    return value


def normalize_path(value: str) -> str:
    if not isinstance(value, str) or not value or value.startswith("/"):
        raise ValueError("paths must be nonempty relative repository paths")
    if "\\" in value or "\x00" in value or "?" in value or "#" in value:
        raise ValueError("path contains ambiguous or unsupported characters")
    directory = value.endswith("/")
    components = value.rstrip("/").split("/")
    if any(x in {"", ".", ".."} for x in components):
        raise ValueError("path must not contain empty, dot or parent components")
    # The trailing slash has a deliberate prefix-directory meaning.
    return "/".join(components) + ("/" if directory else "")


def overlaps(candidate: str, touched: str) -> bool:
    """A directory candidate covers descendants; a file is an exact match."""
    return touched.startswith(candidate) if candidate.endswith("/") else candidate == touched


class GitHubReadOnly:
    """Bounds every paginated read; failure is an UNKNOWN result, not no overlap."""

    def __init__(self, repo: str, token: str | None, opener=None, max_pages: int = 30):
        self.repo = validate_repo(repo)
        if max_pages < 1:
            raise ValueError("max_pages must be at least one")
        self.max_pages = max_pages
        self.opener = opener or urlopen
        self.token = token
        self.api_root = f"https://api.github.com/repos/{self.repo}"

    def _page(self, endpoint: str, number: int) -> list[dict]:
        if not endpoint.startswith("/") or "?" in endpoint or "#" in endpoint:
            raise ValueError("unsafe API endpoint")
        url = f"{self.api_root}{endpoint}?per_page={_PAGE_SIZE}&page={number}"
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "lightup-scope-pr-overlap-preflight",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            with self.opener(Request(url, headers=headers, method="GET"), timeout=20) as response:
                value = json.load(response)
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            # Never print request headers/tokens, URLs returned by untrusted APIs,
            # or a raw upstream response body.
            status = getattr(exc, "code", None)
            raise IncompleteEvidence(
                f"GitHub read failed (HTTP {status})" if status else "GitHub read failed"
            ) from None
        if not isinstance(value, list) or not all(isinstance(x, dict) for x in value):
            raise IncompleteEvidence("GitHub response was not a list of objects")
        return value

    def pages(self, endpoint: str):
        for number in range(1, self.max_pages + 1):
            items = self._page(endpoint, number)
            yield from items
            if len(items) < _PAGE_SIZE:
                return
        # A full final page might hide additional items; never assume complete.
        raise IncompleteEvidence("GitHub pagination cap reached; preflight inconclusive")

    def open_prs(self):
        for pr in self.pages("/pulls"):
            number = pr.get("number")
            head = pr.get("head")
            sha = head.get("sha") if isinstance(head, dict) else None
            if type(number) is not int or number < 1:
                raise IncompleteEvidence("PR response missing canonical number")
            if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
                raise IncompleteEvidence("PR response missing immutable head SHA")
            yield pr

    def touched_paths(self, pr_number: int) -> set[str]:
        paths = set()
        for changed in self.pages(f"/pulls/{pr_number}/files"):
            filename = changed.get("filename")
            if not isinstance(filename, str):
                raise IncompleteEvidence("PR file record missing filename")
            try:
                paths.add(normalize_path(filename))
                prior = changed.get("previous_filename")
                if prior is not None:
                    paths.add(normalize_path(prior))
            except ValueError:
                raise IncompleteEvidence("PR file record contains invalid path") from None
        return paths


def inspect(client: GitHubReadOnly, candidates: list[str], ignore: set[int],
            max_open_prs: int = 5000) -> dict:
    paths = sorted({normalize_path(path) for path in candidates})
    if not paths:
        raise ValueError("at least one candidate path is required")
    # Read the entire PR collection first, then all changed-file pages.
    # Never return a partial CLEAR when pagination or API reads fail.
    prs = list(client.open_prs())
    if len(prs) > max_open_prs:
        raise IncompleteEvidence("too many open PRs to inspect completely")
    before = {p["number"]: p["head"]["sha"] for p in prs}
    if len(before) != len(prs):
        raise IncompleteEvidence("PR pagination returned repeated pull request numbers")
    collisions = []
    inspected = 0
    for pr in prs:
        number = pr["number"]
        if number in ignore:
            continue
        touched = client.touched_paths(number)
        inspected += 1
        for wanted in paths:
            matches = sorted(path for path in touched if overlaps(wanted, path))
            if matches:
                collisions.append({
                    "pr": number,
                    "title": str(pr.get("title", ""))[:180],
                    "candidate": wanted,
                    "changed_paths": matches,
                    "url": f"https://github.com/{client.repo}/pull/{number}",
                })
    # A commit or newly opened PR during the scan invalidates a path-ownership
    # verdict. This second bounded GET snapshot prevents calling a moving list
    # definitively clear; it does not claim an atomic server-side transaction.
    after_prs = list(client.open_prs())
    after = {p["number"]: p["head"]["sha"] for p in after_prs}
    if len(after_prs) > max_open_prs or len(after) != len(after_prs) or before != after:
        raise IncompleteEvidence("open PR set or head SHAs changed during the scan")
    return {
        "status": "overlap" if collisions else "clear",
        "repo": client.repo,
        "candidates": paths,
        "inspected_open_prs": inspected,
        "ignored_prs": sorted(ignore),
        "collisions": sorted(collisions, key=lambda x: (x["pr"], x["candidate"])),
        "note": "Snapshot only: recheck before committing; not target authorization.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default="Zennay/Lightup")
    parser.add_argument("--path", action="append", required=True,
                        help="Relative file or trailing-slash directory; repeatable")
    parser.add_argument("--ignore-pr", action="append", type=int, default=[],
                        help="Skip own existing PR, never another worker's PR")
    parser.add_argument("--max-pages", type=int, default=30)
    args = parser.parse_args(argv)
    try:
        if any(n < 1 for n in args.ignore_pr):
            raise ValueError("ignored PR numbers must be positive")
        client = GitHubReadOnly(
            args.repo, os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),
            max_pages=args.max_pages,
        )
        result = inspect(client, args.path, set(args.ignore_pr))
    except (ValueError, IncompleteEvidence) as exc:
        print(json.dumps({"status": "unknown", "error": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 3 if result["collisions"] else 0


if __name__ == "__main__":
    sys.exit(main())
