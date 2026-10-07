import unittest
from datetime import datetime, timezone

from scripts.lightup_hosted_queue_sweep import (
    PaginationSafetyError,
    cancellation_candidate,
    paged,
    protected_shas,
)


class PaginationTests(unittest.TestCase):
    def test_reads_beyond_first_hundred_open_prs(self):
        pages = {
            1: [{"number": i, "head": {"sha": f"sha-{i}"}} for i in range(1, 101)],
            2: [{"number": i, "head": {"sha": f"sha-{i}"}} for i in range(101, 203)],
            3: [],
        }

        def request(path):
            page = int(path.rsplit("page=", 1)[1])
            return pages[page]

        items, used = paged(request, "/repos/x/y/pulls?state=open", max_pages=5)
        self.assertEqual(202, len(items))
        self.assertEqual(3, used)

    def test_refuses_partial_inventory_at_safety_cap(self):
        def request(_path):
            return [{"number": i, "head": {"sha": f"sha-{i}"}} for i in range(100)]

        with self.assertRaises(PaginationSafetyError):
            paged(request, "/repos/x/y/pulls?state=open", max_pages=2)


class ProtectionTests(unittest.TestCase):
    def test_every_open_pr_head_and_explicit_root_is_protected(self):
        protected, pr_by_sha = protected_shas(
            default_head="main-sha",
            current_sha="sweep-sha",
            explicit_evidence_sha="root-sha",
            open_prs=[
                {"number": 1, "head": {"sha": "pr-1"}},
                {"number": 202, "head": {"sha": "pr-202"}},
            ],
        )
        self.assertEqual(
            {"main-sha", "sweep-sha", "root-sha", "pr-1", "pr-202"},
            protected,
        )
        self.assertEqual({"pr-1": 1, "pr-202": 202}, pr_by_sha)

    def test_malformed_open_pr_identity_fails_closed(self):
        with self.assertRaises(ValueError):
            protected_shas(
                default_head="main",
                current_sha="sweep",
                explicit_evidence_sha="root",
                open_prs=[{"number": 7, "head": {}}],
            )


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 7, 11, 20, tzinfo=timezone.utc)
        self.run = {
            "name": "LightUp CI",
            "path": ".github/workflows/lightup-ci.yml",
            "head_sha": "obsolete",
            "created_at": "2026-10-07T08:00:00Z",
        }
        self.jobs = [
            {
                "status": "queued",
                "labels": ["self-hosted", "zcloud", "vps"],
            }
        ]

    def test_only_old_unprotected_canonical_self_hosted_run_is_candidate(self):
        decision = cancellation_candidate(
            self.run,
            protected={"main", "root"},
            now=self.now,
            minimum_age_seconds=7200,
            jobs=self.jobs,
        )
        self.assertEqual((True, "stale-superseded-queued-self-hosted"), decision)

    def test_open_pr_or_root_head_is_never_candidate(self):
        for protected in ({"obsolete"}, {"obsolete", "root"}):
            with self.subTest(protected=protected):
                decision = cancellation_candidate(
                    self.run,
                    protected=protected,
                    now=self.now,
                    minimum_age_seconds=7200,
                    jobs=self.jobs,
                )
                self.assertEqual((False, "protected-head"), decision)

    def test_recent_or_non_self_hosted_or_wrong_workflow_is_retained(self):
        recent = dict(self.run, created_at="2026-10-07T10:30:00Z")
        self.assertEqual(
            (False, "too-recent"),
            cancellation_candidate(
                recent,
                protected=set(),
                now=self.now,
                minimum_age_seconds=7200,
                jobs=self.jobs,
            ),
        )
        self.assertEqual(
            (False, "not-queued-self-hosted"),
            cancellation_candidate(
                self.run,
                protected=set(),
                now=self.now,
                minimum_age_seconds=7200,
                jobs=[{"status": "queued", "labels": ["ubuntu-latest"]}],
            ),
        )
        wrong = dict(self.run, path=".github/workflows/other.yml")
        self.assertEqual(
            (False, "not-canonical-lightup-ci"),
            cancellation_candidate(
                wrong,
                protected=set(),
                now=self.now,
                minimum_age_seconds=7200,
                jobs=self.jobs,
            ),
        )


if __name__ == "__main__":
    unittest.main()
