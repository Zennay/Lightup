"""Private, no-overwrite offline HUMAN queue with original ZIP bound reinspection.

All digests are local consistency checks, NOT origin authentication or permission.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from .lab_score_handoff_verify import verify_portable_review
from .lab_score_portable_queue import render_portable_queue_html
from .lab_score_queue_csv import render_queue_csv
from .lab_score_queue_triage import (render_human_triage_plan, render_human_triage_html, render_human_triage_csv)
from .lab_score_suite import _private_output_directory
from .lab_score_inspect import _private_dir_fd, _artifact_fd

_NAMES_V1 = ('queue.html', 'queue.json', 'manifest.json')
_NAMES_V2 = ('queue.html', 'queue.json', 'queue_archives.csv', 'queue_pairs.csv', 'manifest.json')
_NAMES_V3 = ('queue.html', 'queue.json', 'queue_archives.csv', 'queue_pairs.csv',
             'triage.md', 'triage.html', 'triage.csv', 'manifest.json')
_MAX = 65536


def _payloads(archive: str | Path, *, version: int = 2) -> tuple[dict[str, Any], dict[str, bytes]]:
    if version not in (1, 2, 3):
        raise ValueError("unsupported offline workroom version")
    verified = verify_portable_review(archive, review_queue=True)
    if not verified['history_content_validated']:
        raise ValueError('legacy untrusted HTML cannot be published')
    queue = verified['review_queue']
    review = {
        'schema': f'lightup.lab-score-human-queue-workroom.v{version}',
        'review_status': verified['review_status'],
        'source_zip_sha256': verified['portable_transport_sha256'],
        'original_source_authenticated': False,
        'authorization_granted': False,
        'external_targets_contacted': False,
        'deployment': False,
        'review_queue': queue,
    }
    payloads = {
        'queue.html': render_portable_queue_html(queue, global_status=verified['review_status']).encode('utf-8'),
        'queue.json': (json.dumps(review, sort_keys=True, indent=2, allow_nan=False)+'\n').encode('utf-8'),
    }
    if version >= 2:
        payloads.update(render_queue_csv(queue, global_status=verified['review_status']))
    if version == 3:
        opts = {'global_status': verified['review_status'],
                'source_zip_sha256': verified['portable_transport_sha256']}
        payloads.update({
            'triage.md': render_human_triage_plan(queue, **opts).encode('utf-8'),
            'triage.html': render_human_triage_html(queue, **opts).encode('utf-8'),
            'triage.csv': render_human_triage_csv(queue, **opts).encode('utf-8'),
        })
    manifest = {
        'schema': f'lightup.lab-score-human-queue-workroom-manifest.v{version}',
        'source_zip_sha256': verified['portable_transport_sha256'],
        'unsigned_local_consistency_only': True,
        'file_sha256': {name: hashlib.sha256(value).hexdigest() for name, value in payloads.items()},
        'authorization_granted': False,
    }
    payloads['manifest.json'] = (json.dumps(manifest, sort_keys=True, indent=2)+'\n').encode('utf-8')
    if any(not 0 < len(value) <= _MAX for value in payloads.values()):
        raise ValueError('queue workroom too large')
    return verified, payloads


def _check_file(fd: int, name: str, expected: bytes) -> tuple[int, int, int, int, int]:
    reader = _artifact_fd(fd, name, _MAX)
    try:
        before = os.fstat(reader)
        data = os.pread(reader, len(expected)+1, 0)
        after = os.fstat(reader)
        linked = os.stat(name, dir_fd=fd, follow_symlinks=False)
        identity = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
        if (data != expected or (before.st_dev, before.st_ino, before.st_size,
             before.st_mtime_ns, before.st_ctime_ns) != identity
             or (linked.st_dev, linked.st_ino) != identity[:2]):
            raise ValueError('saved HUMAN queue changed')
        return identity
    finally:
        os.close(reader)


def verify_queue_workroom(archive: str | Path, directory: str | Path) -> dict[str, Any]:
    fd = _private_dir_fd(directory)
    try:
        inventory = set(os.listdir(fd))
        if inventory == set(_NAMES_V3):
            version, names = 3, _NAMES_V3
        elif inventory == set(_NAMES_V2):
            version, names = 2, _NAMES_V2
        elif inventory == set(_NAMES_V1):
            version, names = 1, _NAMES_V1
        else:
            raise ValueError('unexpected offline queue files')
        result, expected = _payloads(archive, version=version)
        first: dict[str, tuple[int, int, int, int, int]] = {}
        for pass_number in (0, 1):
            if set(os.listdir(fd)) != set(names):
                raise ValueError('unexpected offline queue files')
            for name in names:
                identity = _check_file(fd, name, expected[name])
                if pass_number == 1 and identity != first[name]:
                    raise ValueError('queue file changed between reads')
                first[name] = identity
        if set(os.listdir(fd)) != set(names):
            raise ValueError('offline queue inventory changed')
    finally:
        os.close(fd)
    # The pinned source ZIP was admitted before looking at output files.
    # An owner-local writer could replace the source while that inspection
    # runs. Re-admit it afterwards and refuse any changed source transport.
    final, final_expected = _payloads(archive, version=version)
    if (final['portable_transport_sha256'] != result['portable_transport_sha256']
            or final_expected != expected):
        raise ValueError('original ZIP changed during recipient inspection')
    result["workroom_version"] = version
    result["workroom_files_verified"] = len(expected)
    return result


def export_verified_queue_workroom(archive: str | Path, directory: str | Path,
                                   filename: str) -> tuple[dict[str, Any], bytes]:
    """Emit only original-derived bytes after full saved-workroom reinspection.

    Never open a mutable output path for presentation after validation; get
    canonical bytes from re-admitted original ZIP and compare transport again.
    """
    if filename not in _NAMES_V3 or filename == "manifest.json":
        raise ValueError("unsupported source-free reviewer export")
    verified = verify_queue_workroom(archive, directory)
    final, payloads = _payloads(archive, version=verified["workroom_version"])
    if final["portable_transport_sha256"] != verified["portable_transport_sha256"]:
        raise ValueError("original ZIP changed before recipient export")
    if filename in ("queue_pairs.csv", "queue_archives.csv"):
        # Old v1 workrooms lack stored CSVs; rederive only from admitted source.
        if filename not in payloads:
            payloads.update(render_queue_csv(final["review_queue"],
                                             global_status=final["review_status"]))
    if filename in ('triage.md', 'triage.html', 'triage.csv'):
        # Legacy v1/v2 room remains immutable. Re-derive from canonical source.
        if filename not in payloads:
            opts = {'global_status': final['review_status'],
                    'source_zip_sha256': final['portable_transport_sha256']}
            renderers = {'triage.md': render_human_triage_plan,
                         'triage.html': render_human_triage_html,
                         'triage.csv': render_human_triage_csv}
            payloads[filename] = renderers[filename](
                final['review_queue'], **opts).encode('utf-8')
    return verified, payloads[filename]


def publish_queue_workroom(archive: str | Path, destination: str | Path, *,
                           include_triage: bool = False) -> dict[str, Any]:
    """Publish three 0600 files to new 0700 dir, no overwrite or source auth."""
    source = Path(archive).expanduser().absolute()
    target = Path(destination).expanduser().absolute()
    if ('..' in Path(destination).parts or target == source.parent
            or target in source.parents or source in target.parents):
        raise ValueError('queue output overlaps original ZIP')
    version = 3 if include_triage else 2
    result, payloads = _payloads(archive, version=version)
    names = _NAMES_V3 if include_triage else _NAMES_V2
    root = _private_output_directory(target)
    fd = _private_dir_fd(root)
    created: list[tuple[str, tuple[int, int]]] = []
    try:
        try:
            for name in names:
                temporary = '.' + name + '.tmp'
                writer = os.open(temporary, os.O_WRONLY | os.O_CREAT |
                                 os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                try:
                    with os.fdopen(writer, 'wb') as output:
                        output.write(payloads[name]); output.flush()
                        os.fsync(output.fileno())
                    before = os.stat(temporary, dir_fd=fd, follow_symlinks=False)
                    identity = before.st_dev, before.st_ino
                    os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd,
                            follow_symlinks=False)
                    created.append((name, identity))
                    os.unlink(temporary, dir_fd=fd)
                    if _check_file(fd, name, payloads[name])[:2] != identity:
                        raise ValueError('published queue inode replaced')
                finally:
                    try: os.unlink(temporary, dir_fd=fd)
                    except FileNotFoundError: pass
            os.fsync(fd)
            if verify_queue_workroom(source, root)['portable_transport_sha256'] != result['portable_transport_sha256']:
                raise ValueError('original ZIP changed during publication')
        except Exception:
            for name, identity in reversed(created):
                try:
                    present = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if (present.st_dev, present.st_ino) == identity:
                        os.unlink(name, dir_fd=fd)
                except FileNotFoundError:
                    pass
            # On publication failure, do not strand a new empty 0700
            # directory that prevents a legitimate retry at the same path.
            # Never remove another writer's objects or a substituted path.
            try:
                original = os.fstat(fd)
                current = os.stat(root, follow_symlinks=False)
                if ((original.st_dev, original.st_ino) ==
                    (current.st_dev, current.st_ino) and not os.listdir(fd)):
                    os.rmdir(root)
            except OSError:
                pass  # best effort; never mask the original failure
            raise
    finally:
        os.close(fd)
    return result


def focus_verified_queue_workroom(archive: str | Path, directory: str | Path, *,
                                  archive_index: int | None = None,
                                  pair: tuple[int, int] | None = None) -> dict[str, Any]:
    """Read-only verified owner-private recipient drilldown, global HOLD intact."""
    if (archive_index is None) == (pair is None):
        raise ValueError('choose exactly one anonymous original selection')
    baseline = verify_queue_workroom(archive, directory)
    focused = verify_portable_review(
        archive, focus_archive_index=archive_index, focus_pair=pair)
    # The original ZIP may change during the independent second admission.
    if (focused['portable_transport_sha256'] != baseline['portable_transport_sha256']
            or focused['history_content_validated'] is not True
            or focused['review_status'] != baseline['review_status']):
        raise ValueError('original source changed during focused recipient review')
    if focused.get('selection_valid') is not True:
        raise ValueError('invalid original anonymous selection')
    return {
        'schema': 'lightup.lab-score-private-human-focus.v1',
        'original_source_authenticated': False,
        'authorization_granted': False,
        'external_targets_contacted': False,
        'deployment': False,
        'human_review_only': True,
        'global_review_status': baseline['review_status'],
        'portable_transport_sha256': baseline['portable_transport_sha256'],
        'workroom_files_verified': baseline['workroom_files_verified'],
        'focused_archive': focused.get('focused_archive'),
        'focused_pair': focused.get('focused_pair'),
    }
