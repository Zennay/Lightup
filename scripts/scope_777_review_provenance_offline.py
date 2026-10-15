"""Offline, non-authorizing review of untrusted direct-grant provenance claims.

Issue #777. This review is NOT a proof of customer consent, an authorization
grant, a dispatch gate, or an installed production component. Synthetic data only.
"""
from __future__ import annotations

import json
import os
import select
import stat
import sys
import time
import unicodedata

MAX_INPUT_BYTES = 4096
MAX_VALUE_BYTES = 128
MAX_INPUT_WAIT_SECONDS = 2.0
AUTHORITY_FLAGS = (
    "authorization_verified", "permit_issued", "dispatch_enabled",
    "merge_approved", "deploy_approved", "release_approved",
)


def _receipt(status: str) -> dict[str, str | bool]:
    # No identifiers or raw data are ever returned (including on error).
    return {"status": status, **dict.fromkeys(AUTHORITY_FLAGS, False)}


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _reject_constant(_token: str) -> None:
    raise ValueError("nonfinite JSON")


def _canonical_claim(value: object) -> bool:
    if type(value) is not str or not value or value != value.strip():
        return False
    try:
        if len(value.encode("utf-8")) > MAX_VALUE_BYTES:
            return False
    except UnicodeEncodeError:
        return False
    # Require one Unicode spelling rather than accepting visually equivalent
    # but byte-distinct provenance claims. This is lexical review, not consent.
    # Compatibility equivalents (e.g. fullwidth letters, ligatures and
    # circled characters) must not silently impersonate ordinary identities.
    if unicodedata.normalize("NFKC", value) != value:
        return False
    letter_scripts: set[str] = set()
    for ch in value:
        category = unicodedata.category(ch)
        # Block a conservative subset of mixed-script lookalikes that NFKC
        # cannot distinguish (e.g. Cyrillic O within Latin "Operator").
        # Single-script international names remain reviewable.
        if category.startswith("L"):
            char_name = unicodedata.name(ch, "")
            for script in ("LATIN", "GREEK", "CYRILLIC", "ARMENIAN"):
                if char_name.startswith(script + " "):
                    letter_scripts.add(script)
                    if len(letter_scripts) > 1:
                        return False
                    break
        # Reject format/control/private/unassigned characters and non-ASCII
        # separators that can obscure provenance in logs and reviewer UIs.
        if category[0] == "C" or (category[0] == "Z" and ch != " "):
            return False
        # Some default-ignorable marks are Mn (not Cf), remain NFKC-stable,
        # and can visually mask an identity. Do not reject *all* combining
        # marks: ordinary names in several scripts legitimately require them.
        cp = ord(ch)
        if (ch == "\u034f"  # COMBINING GRAPHEME JOINER
                or 0x180B <= cp <= 0x180D  # Mongolian free variation selectors
                or cp == 0x180F
                or 0xFE00 <= cp <= 0xFE0F  # VS1 .. VS16
                or 0xE0100 <= cp <= 0xE01EF  # supplementary selectors
                or category == "Me"  # enclosing circles/keycaps
                or "OVERLAY" in unicodedata.name(ch, "")):
            return False
    return True


def review_bytes(data: bytes) -> dict[str, str | bool]:
    """Classify a bounded untrusted JSON claim; always deny authority.

    REVIEW_ONLY means lexical consistency *only*, never an authenticated fact.
    All malformed payloads have one indistinguishable HOLD receipt.
    """
    if type(data) is not bytes or not (1 <= len(data) <= MAX_INPUT_BYTES):
        return _receipt("HOLD")
    if data.startswith(b"\xef\xbb\xbf"):
        return _receipt("HOLD")
    try:
        parsed = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_reject_constant,
        )
        if type(parsed) is not dict or set(parsed) != {"approved_by", "reference"}:
            return _receipt("HOLD")
        if not all(_canonical_claim(parsed[key]) for key in ("approved_by", "reference")):
            return _receipt("HOLD")
    except (ValueError, UnicodeError, RecursionError, OverflowError, TypeError):
        return _receipt("HOLD")
    return _receipt("REVIEW_ONLY")


def _read_bounded_local(fd: int) -> bytes:
    """Read to EOF with a monotonic deadline, never waiting forever on a FIFO."""
    chunks: list[bytes] = []
    total = 0
    deadline = time.monotonic() + MAX_INPUT_WAIT_SECONDS
    was_blocking = os.get_blocking(fd)
    try:
        os.set_blocking(fd, False)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("untrusted input held open")
            if not select.select([fd], [], [], remaining)[0]:
                raise TimeoutError("untrusted input timed out")
            try:
                part = os.read(fd, MAX_INPUT_BYTES + 1 - total)
            except BlockingIOError:
                continue
            if not part:
                break
            chunks.append(part)
            total += len(part)
            if total > MAX_INPUT_BYTES:
                break
    finally:
        os.set_blocking(fd, was_blocking)
    return b"".join(chunks)


def _write_nonblocking_receipt(payload: bytes, fd: int) -> None:
    """One bounded nonblocking write; never wait on an unconsumed output."""
    if len(payload) > 512:
        raise ValueError("oversized receipt")
    was_blocking = os.get_blocking(fd)
    try:
        os.set_blocking(fd, False)
        if os.write(fd, payload) != len(payload):
            raise OSError("partial receipt")
    finally:
        os.set_blocking(fd, was_blocking)



def _regular_input_snapshot(fd: int) -> tuple[int, ...] | None:
    """Accept a complete, bounded, non-seeked regular-file snapshot only."""
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        return None
    if st.st_size < 1 or st.st_size > MAX_INPUT_BYTES:
        raise ValueError("regular input is empty or oversized")
    if os.lseek(fd, 0, os.SEEK_CUR) != 0:
        raise ValueError("regular input was partially consumed")
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size,
            st.st_mtime_ns, st.st_ctime_ns)


def _verify_regular_input(fd: int, original: tuple[int, ...] | None,
                          received_length: int) -> None:
    if original is None:
        return
    st = os.fstat(fd)
    current = (st.st_dev, st.st_ino, st.st_mode, st.st_size,
               st.st_mtime_ns, st.st_ctime_ns)
    if current != original or received_length != st.st_size:
        raise ValueError("regular input changed during review")
    if os.lseek(fd, 0, os.SEEK_CUR) != st.st_size:
        raise ValueError("regular input was not completely consumed")



def _fd_identity(fd: int) -> tuple[int, int, int]:
    """Keep source/destination identity separate from the caller's fd number."""
    st = os.fstat(fd)
    return st.st_dev, st.st_ino, st.st_mode


def _assert_original_fd_is_pinned(original: int, pinned: int) -> None:
    if _fd_identity(original) != _fd_identity(pinned):
        raise ValueError("descriptor rebinding is not permitted")


def _pin_checked_fds() -> tuple[int, int]:
    """Bind both admitted local endpoints before any untrusted I/O."""
    stdin_before, stdout_before = _fd_identity(0), _fd_identity(1)
    if not (stat.S_ISFIFO(stdin_before[2]) or stat.S_ISREG(stdin_before[2])):
        raise ValueError("input must be local FIFO/regular")
    if not (stat.S_ISFIFO(stdout_before[2]) or
            (stat.S_ISCHR(stdout_before[2]) and os.isatty(1))):
        raise ValueError("output must be local FIFO/terminal")
    stdin_fd = os.dup(0)
    try:
        stdout_fd = os.dup(1)
        try:
            if (_fd_identity(stdin_fd) != stdin_before or
                    _fd_identity(stdout_fd) != stdout_before):
                raise ValueError("descriptor changed during pinning")
            _assert_original_fd_is_pinned(0, stdin_fd)
            _assert_original_fd_is_pinned(1, stdout_fd)
            return stdin_fd, stdout_fd
        except BaseException:
            os.close(stdout_fd)
            raise
    except BaseException:
        os.close(stdin_fd)
        raise


def main() -> int:
    if len(sys.argv) != 1:
        return 2
    try:
        stdin_fd, stdout_fd = _pin_checked_fds()
        try:
            try:
                snapshot = _regular_input_snapshot(stdin_fd)
                data = _read_bounded_local(stdin_fd)
                _verify_regular_input(stdin_fd, snapshot, len(data))
                _assert_original_fd_is_pinned(0, stdin_fd)
                receipt = review_bytes(data)
            except (TimeoutError, ValueError):
                receipt = _receipt("HOLD")
            _assert_original_fd_is_pinned(1, stdout_fd)
            encoded = (json.dumps(receipt, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii")
            _write_nonblocking_receipt(encoded, stdout_fd)
        finally:
            os.close(stdout_fd)
            os.close(stdin_fd)
    except (OSError, TimeoutError, ValueError):
        return 2
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
