"""Ensure documentation-only authorization fixtures cannot become live target lists."""
import ipaddress
import json
import unittest
from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[1] / "docs/fixtures/scope-authorization-offline-review-v1.json"

def is_synthetic_asset(value: object) -> bool:
    """Accept only deterministic inert labels. Never resolve an address."""
    if type(value) is not str or not value or value != value.strip():
        return False
    if "://" in value or "/" in value or "@" in value or ":" in value:
        return False
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        return False
    return value.endswith(".example.invalid") and all(label.isascii() and label.replace("-", "").isalnum() and label and not label.startswith("-") and not label.endswith("-") for label in value.split("."))

class ReviewFixtureIsolationTests(unittest.TestCase):
    def test_no_routable_or_network_target_values(self):
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        for case in fixture["cases"]:
            with self.subTest(case=case["id"]):
                self.assertTrue(is_synthetic_asset(case["asset"]))
                self.assertEqual(set(case), {"id", "asset", "membership", "grant", "expected", "reason"})

    def test_network_and_authorization_payloads_rejected(self):
        for value in (
            "example.com", "8.8.8.8", "127.0.0.1", "2001:4860:4860::8888",
            "https://lab.example.invalid", "lab.example.invalid:443", "lab.example.invalid/path",
            "admin@lab.example.invalid", " lab.example.invalid ", "", None, 1,
        ):
            with self.subTest(value=value):
                self.assertFalse(is_synthetic_asset(value))

    def test_synthetic_names_accepted(self):
        for value in ("lab.example.invalid", "excluded.example.invalid", "unlisted.example.invalid"):
            self.assertTrue(is_synthetic_asset(value))

if __name__ == "__main__":
    unittest.main()
