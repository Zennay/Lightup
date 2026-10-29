from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

from lightup.lab_replay import (
    _prepare_store_dir,
    _require_private_artifact,
    _verify_existing_bundle,
)


class PrivateReplayStorageContract(unittest.TestCase):
    def test_owner_private_directory_is_admitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "private"
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o700)
            _require_private_artifact(directory, directory=True)

    def test_group_accessible_directory_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "shared"
            directory.mkdir(mode=0o700)
            os.chmod(directory, 0o750)
            with self.assertRaises(PermissionError):
                _require_private_artifact(directory, directory=True)

    def test_owner_private_regular_file_is_admitted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            path.write_bytes(b"{}")
            os.chmod(path, 0o600)
            _require_private_artifact(path, directory=False)

    def test_group_readable_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            path.write_bytes(b"{}")
            os.chmod(path, 0o640)
            with self.assertRaises(PermissionError):
                _require_private_artifact(path, directory=False)

    def test_hardlinked_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "receipt.json"
            alias = Path(temporary) / "alias.json"
            path.write_bytes(b"{}")
            os.chmod(path, 0o600)
            os.link(path, alias)
            with self.assertRaises(PermissionError):
                _require_private_artifact(path, directory=False)

    def test_symlinked_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "target.json"
            link = Path(temporary) / "receipt.json"
            target.write_bytes(b"{}")
            os.chmod(target, 0o600)
            link.symlink_to(target)
            with self.assertRaises(PermissionError):
                _require_private_artifact(link, directory=False)

    def test_store_path_rejects_symlinked_parent_component(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            real = Path(temporary) / "real"
            real.mkdir(mode=0o700)
            os.chmod(real, 0o700)
            alias = Path(temporary) / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with self.assertRaises(PermissionError):
                _prepare_store_dir(str(alias / "store"))

    def test_existing_bundle_rejects_public_receipt_before_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            bundle.mkdir(mode=0o700)
            os.chmod(bundle, 0o700)
            receipt = b"{}"
            digest = hashlib.sha256(receipt).hexdigest()
            receipt_path = bundle / "receipt.json"
            receipt_path.write_bytes(receipt)
            os.chmod(receipt_path, 0o644)
            checksum = bundle / "receipt.sha256"
            checksum.write_text(f"{digest}  receipt.json\n", encoding="ascii")
            os.chmod(checksum, 0o600)
            with self.assertRaises(PermissionError):
                _verify_existing_bundle(bundle, receipt, digest)


if __name__ == "__main__":
    unittest.main()
