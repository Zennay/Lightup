"""Read-only *injected transport* preflight for fictional PR pages (#1553).

NO network client, tokens, GitHub authorization or production wiring exists
here. The *caller* supplies mock/read-only hooks. Hook identity and remote
responses are NOT authenticated by this module. Never releases authority.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from .scope_github_coverage_adapter_1553 import _output
from .scope_github_file_coverage_1553 import _MAX_INPUT_BYTES, _good_path
from .scope_github_pr_pages_1553 import (
    _PAGE_FIELDS, _PAGE_SIZE, _REPOSITORY, _metadata_valid, review_pages,
)

_MAX_PR_NUM = 1_000_000_000


def _snapshot(value: object, budget: int) -> tuple[object, int]:
    """Reject oversized, non-JSON or nonfinite mock transport responses."""
    if budget <= 0:
        raise ValueError("no remaining response budget")
    raw = json.dumps(
        value, ensure_ascii=True, allow_nan=False, separators=(",", ":")
    ).encode("utf-8")
    if len(raw) > budget:
        raise ValueError("response too large")
    return json.loads(raw), len(raw)


def observe(
    fetch_pr: Callable[[str, int], object],
    fetch_page: Callable[[str, int, int, int], object],
    *,
    repository: str,
    pr_number: int,
) -> dict[str, object]:
    """Fetch mock normalized PR metadata, all pages, empty tail, and metadata.

    Simulates the intended ordering for a future authenticated source owner:
    PR(before) -> exact pages -> mandatory empty tail -> PR(after). A HEAD
    change, missing/duplicate/extra page or transport error causes HOLD.
    """
    hold = _output("HOLD")
    if (type(repository) is not str or len(repository) > 180
            or _REPOSITORY.fullmatch(repository) is None
            or any(part in (".", "..") for part in repository.split("/"))
            or type(pr_number) is not int or not 1 <= pr_number <= _MAX_PR_NUM
            or not callable(fetch_pr) or not callable(fetch_page)):
        return hold

    try:
        budget = _MAX_INPUT_BYTES
        before, size = _snapshot(fetch_pr(repository, pr_number), budget)
        budget -= size
        if (not _metadata_valid(before)
                or before["repository"] != repository
                or before["pr_number"] != pr_number):
            return hold

        count = before["changed_files"]
        page_count = (count + _PAGE_SIZE - 1) // _PAGE_SIZE
        pages: list[dict[str, Any]] = []
        seen: set[str] = set()
        total = 0
        for index in range(1, page_count + 2):
            page, size = _snapshot(
                fetch_page(repository, pr_number, index, _PAGE_SIZE), budget
            )
            budget -= size
            if type(page) is not dict or set(page) != _PAGE_FIELDS:
                return hold
            if (type(page["page"]) is not int or page["page"] != index
                    or type(page["per_page"]) is not int
                    or page["per_page"] != _PAGE_SIZE
                    or type(page["files"]) is not list):
                return hold

            items = page["files"]
            expected_length = (
                min(_PAGE_SIZE, count - total)
                if index <= page_count else 0
            )
            if len(items) != expected_length:
                return hold
            for item in items:
                if type(item) is not dict or not _good_path(item.get("filename")):
                    return hold
                name = item["filename"]
                if name in seen:
                    return hold
                seen.add(name)
            if index <= page_count:
                pages.append(page)
                total += len(items)

        if total != count or len(seen) != count:
            return hold
        after, size = _snapshot(fetch_pr(repository, pr_number), budget)
        budget -= size
        if after != before:
            return hold

        # Both transport reads were detached; the original ChangeSet adapter
        # is invoked ONLY inside review_pages after all consistency checks.
        return review_pages(before, pages, after)
    except Exception:
        # Transport hooks are foreign code. Never echo URL, tokens, path or
        # response data, and never confer authority after ANY read failure.
        return hold
