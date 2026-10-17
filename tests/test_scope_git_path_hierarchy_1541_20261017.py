"""Additional offline hierarchy and display-identity acceptance for #1541.

Synthetic Git -z byte streams only. Never starts git, reads real paths,
imports production scope/authorization, or grants execution authority.
"""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from scope_git_path_identity_oracle_1541 import PathIdentityHold, parse_git_path_outputs


def manifests(*names: str) -> tuple[bytes, bytes]:
    status = b"".join(b"M\0" + name.encode("utf-8") + b"\0" for name in names)
    numstat = b"".join(b"1\t1\t" + name.encode("utf-8") + b"\0" for name in names)
    return status, numstat


class IndependentPathHierarchyAcceptance(unittest.TestCase):
    def hold(self, *names: str) -> None:
        status, numstat = manifests(*names)
        with self.assertRaises(PathIdentityHold) as raised:
            parse_git_path_outputs(status, numstat)
        self.assertEqual(str(raised.exception), "HOLD: ambiguous Git path identity")
        self.assertNotIn("secret", str(raised.exception))
        self.assertNotIn("token", str(raised.exception))

    def test_file_directory_prefix_collision_fails_closed(self):
        self.hold("root", "root/secret.py")
        self.hold("assets/logo", "assets/logo/icons.svg")

    def test_reverse_order_file_directory_prefix_collision_fails_closed(self):
        self.hold("nested/token.py", "nested")
        self.hold("one/two/secret", "one/two")

    def test_alias_directory_case_mismatch_fails_closed(self):
        self.hold("Folder/one.py", "folder/two.py")
        self.hold("LIB/deep/one.py", "lib/deep/two.py")

    def test_alias_directory_unicode_nfc_mismatch_fails_closed(self):
        self.hold("caf\u00e9/one.py", "cafe\u0301/two.py")

    def test_alias_directory_subpath_case_mismatch_fails_closed(self):
        self.hold("src/V1/file.py", "src/v1/other.py")

    def test_right_to_left_override_invisible_is_hold(self):
        self.hold("safe\u202e.py")
        self.hold("src/\u2066token.py")

    def test_zero_width_format_character_is_hold(self):
        self.hold("token\u200d.py")
        self.hold("name\u200b.py")

    def test_distinct_files_under_same_exact_directory_still_review(self):
        status, numstat = manifests("src/one.py", "src/two.py", "src/deep/three.py")
        checked = parse_git_path_outputs(status, numstat)
        self.assertEqual([item.path for item in checked],
                         ["src/one.py", "src/two.py", "src/deep/three.py"])

    def test_single_canonical_unicode_and_tab_remain_supported(self):
        status, numstat = manifests("caf\u00e9/name\tpart.py")
        checked = parse_git_path_outputs(status, numstat)
        self.assertEqual(len(checked), 1)
        self.assertEqual(checked[0].path, "caf\u00e9/name\tpart.py")

    def test_mixed_batch_invalid_is_atomic_and_privacy_minimal(self):
        self.hold("src/okay.py", "docs/hidden\u202e-secrets.txt")

    def test_case_sensitive_sibling_paths_still_supported(self):
        status, numstat = manifests("src/core.py", "tests/unit/test_core.py")
        checked = parse_git_path_outputs(status, numstat)
        self.assertEqual(len(checked), 2)


if __name__ == "__main__":
    unittest.main()
