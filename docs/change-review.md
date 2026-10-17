# Change review (Future Security, inferred lane)

`lightup review-change` is the first Future Security path that runs on any
repository without lab infrastructure. It answers, before merge:

> Does this diff *appear* to introduce security exposure, and how sure are we?

```text
git range / GitHub compare JSON
  -> ChangeSet (+ OpenAPI / Terraform structured deltas)
  -> deterministic change rules        (lightup.change_rules)
  -> future Security Twin branch       (derive_future_twin + candidate binding)
  -> policy verdict                    (lightup.change_review)
  -> Markdown job summary, JSON, SARIF
```

## Usage

```bash
PYTHONPATH=src python -m lightup.cli review-change --repo . --base origin/main --head HEAD
PYTHONPATH=src python -m lightup.cli review-change --format sarif --output review.sarif
PYTHONPATH=src python -m lightup.cli review-change --compare-json compare.json --repository acme/app
```

Exit code is `1` when the verdict reaches `--fail-on` (default `block`), `2` on
input errors. Inside GitHub Actions the Markdown report is appended to the job
summary automatically. A composite action lives in `action.yml`; see
`docs/examples/lightup-change-review.yml`.

## Rules

About 35 rules across secrets (private keys, AWS/GitHub/Slack/provider keys,
hard-coded credentials), injection (shell, eval, SQL string building, unsafe
deserialization, XSS sinks), transport/crypto (TLS verification off, weak
hashes, insecure randomness), app config (debug, wildcard CORS, insecure
cookies, bind-all), access control (removed auth guards, CSRF off, unverified
JWT), IaC/IAM (open ingress, public storage, encryption off, wildcard
actions/principals, privileged containers) and CI/supply chain
(`pull_request_target`, broad token permissions, script injection, unpinned
actions, `curl | sh`).

Secret rules skip tests and docs; placeholders and environment lookups are
ignored. A line containing `lightup: ignore` is skipped.

## Verdict policy

Default mapping, overridable in `.lightup-review.json`:

| Signal | Verdict |
| --- | --- |
| critical hypothesis | `BLOCK` |
| high hypothesis | `REVIEW_REQUIRED` |
| medium / low hypothesis | `PASS_WITH_WARNING` |
| IAM / network-boundary surface change | `PASS_WITH_WARNING` |
| file that could not be analyzed | `PASS_WITH_WARNING` |
| compare too large | `REVIEW_REQUIRED` |

```json
{
  "severity_verdicts": {"critical": "BLOCK", "high": "BLOCK"},
  "surface_change_verdict": "REVIEW_REQUIRED",
  "incomplete_coverage_verdict": "PASS_WITH_WARNING",
  "ignore_rules": ["config.bind-all-interfaces"],
  "ignore_paths": ["tests/*", "examples/*"],
  "min_confidence": 0.5
}
```

Unknown keys are rejected so a typo cannot silently weaken the policy.

## Safety and provenance

- Every hypothesis is `provenance=inferred`; the report carries
  `basis=inferred` and `not_authorization=true`. It is deliberately distinct
  from the evidence-verified ST5 verdict in `lightup.future_security_ci_verdict`.
- Raw patches and matched secrets are never stored: hypotheses keep the path,
  head-side line number, a `patch-sha256:` and a `line-sha256:` reference.
- A `PASS` with no matches says so explicitly: it is an absence of inferred
  signals, not a clean bill of health.
- Git access is read-only (`diff`, `show`, `cat-file`, `rev-parse`,
  `merge-base`) and revisions are validated before use.
