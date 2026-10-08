"""Offline reference: binding remediation artifacts to immutable evidence manifests.

This is NOT a production authorization or provenance verifier.
No file, network, clock, or target access occurs.
"""
import hashlib
import re

_SHA = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MEDIA = frozenset({"application/json", "text/plain", "text/markdown"})


def verify_artifact_manifest(manifest, blobs):
    """Return True only when an exact, self-contained in-memory manifest matches.

    Each artifact must bind to a unique artifact ID and exact byte content.
    The caller is responsible for proving where those bytes originated.
    """
    if type(manifest) is not dict or type(blobs) is not dict:
        return False
    if set(manifest) != {"tenant_id", "finding_id", "remediation_id", "artifacts"}:
        return False
    if any(type(manifest[k]) is not str or not _ID.fullmatch(manifest[k])
           for k in ("tenant_id", "finding_id", "remediation_id")):
        return False
    artifacts = manifest["artifacts"]
    if type(artifacts) is not list or not 1 <= len(artifacts) <= 32:
        return False
    if len(blobs) != len(artifacts):
        return False
    seen = set()
    for artifact in artifacts:
        if type(artifact) is not dict or set(artifact) != {"artifact_id", "media_type", "size", "sha256"}:
            return False
        ident, media, size, digest = (artifact[k] for k in ("artifact_id", "media_type", "size", "sha256"))
        if type(ident) is not str or not _ID.fullmatch(ident) or ident in seen:
            return False
        seen.add(ident)
        if type(media) is not str or media not in _MEDIA:
            return False
        if type(size) is not int or not 0 <= size <= 1048576:
            return False
        if type(digest) is not str or not _SHA.fullmatch(digest):
            return False
        if ident not in blobs or type(blobs[ident]) is not bytes:
            return False
        data = blobs[ident]
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            return False
    return set(blobs) == seen
