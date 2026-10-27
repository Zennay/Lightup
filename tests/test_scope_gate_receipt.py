"""Pure offline regression tests for the scope release receipt shape."""
import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_scope_gate_receipt.py"
spec = importlib.util.spec_from_file_location("scope_gate_receipt", SCRIPT)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def valid():
    sha = "a" * 40
    return {
        "commit_sha": sha,
        "review_approved": True,
        "review_reference": "https://github.com/example/repo/pull/1#review",
        "runs": {
            "hosted": {"run_id": 101, "head_sha": sha, "status": "completed", "conclusion": "success", "tests_passed": 12},
            "permanent_vps": {"run_id": 102, "head_sha": sha, "status": "completed", "conclusion": "success", "tests_passed": 12},
        },
    }


class ScopeGateReceiptTests(unittest.TestCase):
    def test_complete_matching_receipt(self):
        self.assertEqual(module.verify_receipt(valid()), (True, ()))

    def test_refuses_missing_approval(self):
        document = valid()
        document["review_approved"] = 1
        self.assertFalse(module.verify_receipt(document)[0])

    def test_refuses_queued_hosted(self):
        document = valid()
        document["runs"]["hosted"]["status"] = "queued"
        self.assertFalse(module.verify_receipt(document)[0])

    def test_refuses_superseded_vps_sha(self):
        document = valid()
        document["runs"]["permanent_vps"]["head_sha"] = "b" * 40
        self.assertFalse(module.verify_receipt(document)[0])

    def test_refuses_duplicate_runs(self):
        document = valid()
        document["runs"]["permanent_vps"]["run_id"] = 101
        self.assertFalse(module.verify_receipt(document)[0])

    def test_refuses_empty_test_count(self):
        document = valid()
        document["runs"]["hosted"]["tests_passed"] = False
        self.assertFalse(module.verify_receipt(document)[0])

    def test_refuses_extra_lane(self):
        document = valid()
        document["runs"]["production"] = {}
        self.assertFalse(module.verify_receipt(document)[0])

    def test_refuses_noncanonical_sha(self):
        document = valid()
        document["commit_sha"] = "A" * 40
        self.assertFalse(module.verify_receipt(document)[0])

    def test_refuses_nonobject_input(self):
        self.assertFalse(module.verify_receipt([])[0])


if __name__ == "__main__":
    unittest.main()
