import importlib.util
import pathlib
import unittest
from datetime import datetime, timezone


ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "lightup_queue_hygiene.py"
SPEC = importlib.util.spec_from_file_location("lightup_queue_hygiene", SCRIPT)
queue_hygiene = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(queue_hygiene)


NOW = datetime(2026, 10, 6, 12, 0, tzinfo=timezone.utc)


def queued_run(run_id=1, sha="old", created_at="2026-10-06T08:00:00Z"):
    return {
        "id": run_id,
        "status": "queued",
        "head_sha": sha,
        "created_at": created_at,
        "name": "LightUp CI",
    }


def self_hosted_job(status="queued"):
    return {"status": status, "labels": ["self-hosted", "zcloud", "vps"]}


class QueueHygieneClassificationTests(unittest.TestCase):
    def classify(self, run, jobs=(), protected=(), current_run_id=None, min_age=7200):
        return queue_hygiene.classify_run(
            run,
            list(jobs),
            protected_shas=set(protected),
            now=NOW,
            minimum_age_seconds=min_age,
            current_run_id=current_run_id,
        )

    def test_current_run_is_never_candidate(self):
        self.assertEqual(
            (False, "current-run"),
            self.classify(
                queued_run(run_id=55),
                [self_hosted_job()],
                current_run_id=55,
            ),
        )

    def test_open_pr_or_main_head_is_never_candidate(self):
        self.assertEqual(
            (False, "protected-head"),
            self.classify(
                queued_run(sha="protected"),
                [self_hosted_job()],
                protected={"protected"},
            ),
        )

    def test_recent_run_is_retained(self):
        self.assertEqual(
            (False, "too-recent"),
            self.classify(
                queued_run(created_at="2026-10-06T11:00:01Z"),
                [self_hosted_job()],
            ),
        )

    def test_hosted_only_run_is_retained(self):
        jobs = [{"status": "queued", "labels": ["ubuntu-latest"]}]
        self.assertEqual(
            (False, "not-queued-self-hosted"),
            self.classify(queued_run(), jobs),
        )

    def test_finished_self_hosted_job_does_not_make_run_candidate(self):
        self.assertEqual(
            (False, "not-queued-self-hosted"),
            self.classify(queued_run(), [self_hosted_job(status="completed")]),
        )

    def test_only_old_superseded_queued_self_hosted_run_is_candidate(self):
        self.assertEqual(
            (True, "stale-superseded-self-hosted"),
            self.classify(queued_run(), [self_hosted_job()]),
        )

    def test_missing_head_sha_fails_closed(self):
        run = queued_run()
        run["head_sha"] = ""
        self.assertEqual(
            (False, "missing-head-sha"),
            self.classify(run, [self_hosted_job()]),
        )

    def test_timezone_naive_created_at_is_rejected(self):
        run = queued_run(created_at="2026-10-06T08:00:00")
        with self.assertRaises(ValueError):
            self.classify(run, [self_hosted_job()])


class QueueHygieneExecutionTests(unittest.TestCase):
    class FakeApi:
        def __init__(self):
            self.posted = []

        def request(self, path, *, method="GET"):
            if path == "/repos/Zennay/Lightup":
                return {"default_branch": "main"}
            if path == "/repos/Zennay/Lightup/commits/main":
                return {"sha": "main-head"}
            if method == "POST":
                self.posted.append(path)
                return {}
            raise AssertionError((path, method))

        def paged(self, path, *, key=None):
            if path == "/repos/Zennay/Lightup/pulls?state=open":
                return [{"number": 62, "head": {"sha": "open-pr-head"}}]
            if path == "/repos/Zennay/Lightup/actions/runs?status=queued":
                return [
                    queued_run(run_id=10, sha="open-pr-head"),
                    queued_run(run_id=11, sha="superseded"),
                ]
            if path == "/repos/Zennay/Lightup/actions/runs/11/jobs?filter=latest":
                return [self_hosted_job()]
            raise AssertionError(path)

    def test_dry_run_never_cancels(self):
        api = self.FakeApi()
        receipt = queue_hygiene.execute(
            api=api,
            repo="Zennay/Lightup",
            apply=False,
            minimum_age_seconds=7200,
            max_cancellations=25,
            current_run_id=None,
            current_sha="queue-guard-head",
            now=NOW,
        )
        self.assertEqual([], api.posted)
        self.assertEqual(1, receipt["candidate_count"])
        self.assertEqual(0, receipt["cancelled_count"])
        self.assertEqual("dry-run", receipt["mode"])

    def test_apply_cancels_only_candidate(self):
        api = self.FakeApi()
        receipt = queue_hygiene.execute(
            api=api,
            repo="Zennay/Lightup",
            apply=True,
            minimum_age_seconds=7200,
            max_cancellations=25,
            current_run_id=None,
            current_sha="queue-guard-head",
            now=NOW,
        )
        self.assertEqual(
            ["/repos/Zennay/Lightup/actions/runs/11/cancel"],
            api.posted,
        )
        self.assertEqual(1, receipt["cancelled_count"])
        self.assertEqual("apply", receipt["mode"])

    def test_apply_aborts_before_mutation_when_candidate_cap_is_exceeded(self):
        class TwoCandidateApi(self.FakeApi):
            def paged(self, path, *, key=None):
                if path == "/repos/Zennay/Lightup/pulls?state=open":
                    return []
                if path == "/repos/Zennay/Lightup/actions/runs?status=queued":
                    return [
                        queued_run(run_id=21, sha="superseded-a"),
                        queued_run(run_id=22, sha="superseded-b"),
                    ]
                if path in {
                    "/repos/Zennay/Lightup/actions/runs/21/jobs?filter=latest",
                    "/repos/Zennay/Lightup/actions/runs/22/jobs?filter=latest",
                }:
                    return [self_hosted_job()]
                raise AssertionError(path)

        api = TwoCandidateApi()
        with self.assertRaisesRegex(RuntimeError, "cap is 1"):
            queue_hygiene.execute(
                api=api,
                repo="Zennay/Lightup",
                apply=True,
                minimum_age_seconds=7200,
                max_cancellations=1,
                current_run_id=None,
                current_sha="queue-guard-head",
                now=NOW,
            )
        self.assertEqual([], api.posted)


if __name__ == "__main__":
    unittest.main()
