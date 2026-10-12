"""#920: checksum provenance for the non-conflicting web transport acceptance pack.

Git blob SHA-1 is used ONLY to pin repository source snapshots; this is not a
cryptographic authorization grant or a production trust implementation.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent
# Exact blobs verified against pinned PR #202 and independent #918/#919 branches.
EXPECTED_GIT_BLOBS = {
    "src/lightup/webapp/security.py": "44b2e78c41832d87d64d4bf1f9081b04ad50d806",
    "tests/test_scope_authorization_trusted_proxy_identity.py":
        "bd4049f0d3d1f7d0726cdda103238c26300d3614",
    "docs/scope-authorization-trusted-proxy-identity.md":
        "bc9d17acaf4394c1eddc09992cab10d8740f098c",
    "tests/test_scope_authorization_public_origin_identity.py":
        "1896265dd80b0bdee2dbb61ab31c2e7ec285b257",
    "docs/scope-authorization-public-origin-identity.md":
        "751d7bb042a102589cd13512e96e21f5af478c65",
}


def _blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


class TransportCompositionProvenanceTests(unittest.TestCase):
    def test_all_five_original_owner_and_contract_snapshots_are_unchanged(self) -> None:
        for path, original_sha in EXPECTED_GIT_BLOBS.items():
            with self.subTest(path=path):
                self.assertEqual(
                    _blob_sha((ROOT / path).read_bytes()),
                    original_sha,
                    "original source/RED acceptance changed; re-review the complete pack",
                )

    def test_expected_inputs_have_separate_parent_domains(self) -> None:
        self.assertEqual(len(EXPECTED_GIT_BLOBS), 5)
        self.assertEqual(
            set(EXPECTED_GIT_BLOBS),
            {
                "src/lightup/webapp/security.py",
                "tests/test_scope_authorization_trusted_proxy_identity.py",
                "docs/scope-authorization-trusted-proxy-identity.md",
                "tests/test_scope_authorization_public_origin_identity.py",
                "docs/scope-authorization-public-origin-identity.md",
            },
        )

    def test_git_blob_pinning_preserves_binary_input_identity(self) -> None:
        # A content change or line-ending rewrite is a review-worthy change.
        self.assertNotEqual(_blob_sha(b"safe\n"), _blob_sha(b"safe\r\n"))
        self.assertNotEqual(_blob_sha(b"safe"), _blob_sha(b"safe "))


if __name__ == "__main__":
    unittest.main()
