# LightUp

LightUp is an AI-assisted security validation platform for **owned or explicitly authorized systems**.

Its long-term product promise is:

> **Find what is vulnerable today, and prove whether the change you are about to ship makes you vulnerable tomorrow.**

That means LightUp is being built around two complementary lanes:

- **Current Security** — evidence-backed assessment of today's vulnerabilities, misconfigurations and attack paths.
- **Future Security** — Security Twin-based adversarial simulation of proposed code, API, IaC, IAM, cloud and configuration changes before production.

See `docs/product-architecture.md` and `docs/security-twin.md`.

## Current phase: M1 — platform skeleton

Current real-target activation remains disabled. The repository already has
lab-only network-capable workers, but real-target adapters are a later phase
and require an explicit project-level activation decision plus valid
authorization.

The platform can already:

- define and validate target scope;
- model authorization, clients, engagements and risk approvals;
- build typed AI assessment plans from a capability registry;
- execute HTTP-header, service-inventory and TLS baselines against lab targets;
- normalize findings, evidence, remediation and retest state;
- run provider-neutral AI review/orchestration;
- expose a multi-client authenticated web shell;
- exercise planted-weakness lab scenarios and score results;
- prove fail-closed behavior with tests.

It cannot yet actively assess arbitrary real targets or execute exploit logic.

## Safety invariants

1. Unknown public targets fail closed.
2. Public targets require exact host or CIDR authorization.
3. Private/loopback lab targets can be permitted by policy.
4. Authorization has an owner/reference and optional validity window.
5. Every future active adapter must pass through the same scope gate.
6. No adapter may silently widen target scope.
7. Findings must include evidence, remediation, and retest state.
8. Parallel workers claim non-overlapping capabilities/write scopes before changes.
9. Future-state simulation never grants authorization to interact with a real target.
10. AI/model output is not itself ground truth; important findings require evidence/verifier semantics.

## Architecture

```text
                    Current state
                         |
AuthorizedTarget -> Scope/Policy -> AI Orchestrator -> Capability Workers
                         |                                |
                         v                                v
                    Security Twin <- Evidence <- Findings/Attack Paths
                         |
                  Proposed future change
                         |
                  Future-state Twin
                         |
                 Isolated simulation
                         |
             Current vs Future attack graph
                         |
                Verdict + Fix + Retest
```

## Quick start

```bash
cd lightup
python -m unittest discover -s tests -v
PYTHONPATH=src python -m lightup.cli scope-check 127.0.0.1
PYTHONPATH=src python -m lightup.cli plan 127.0.0.1
PYTHONPATH=src python -m lightup.cli create-operator --db lightup.db \
  --email you@example.com --name "You"
PYTHONPATH=src python -m lightup.cli serve --db lightup.db

# End-to-end lab demo
python lab/http_fixture.py &
PYTHONPATH=src python -m lightup.cli lab-baseline --expect-fixture

# Planner-driven multi-lane assessment against planted ground truth
python lab/vuln_fixture.py --profile exposed --port 18081 &
PYTHONPATH=src python -m lightup.cli lab-assess http://127.0.0.1:18081/ \
  --profile exposed
```

The `plan` command is intentionally non-invasive: it only emits a structured plan.

The web shell (`docs/webapp.md`) serves the operator dashboard on `/` and the
client portal on `/portal/<client_id>`, behind session authentication with
CSRF protection.

### Export finding summaries

Signed-in portal users can choose **Download CSV** beside Findings. The download
contains finding ID, title, severity, retest status and remediation for the
selected client. Operators explicitly select one client; client users can
download only their own client.

For an existing database, terminal users can sign in interactively and export:

```bash
PYTHONPATH=src python -m lightup.finding_export_cli --db lightup.db \
  --email you@example.com --client-id CLIENT_ID > findings.csv
```

Add `--engagement-id ENGAGEMENT_ID` to limit the export to one engagement.
The command prompts for the password and refuses unsafe fallback input.
Keep the destination private and review free text before sharing. Exports omit
targets, raw evidence and arbitrary metadata, redact known credential patterns
and guard spreadsheet formula-like values.

See [terminal export](docs/authenticated-finding-csv-cli.md),
[portal downloads](docs/session-finding-csv-download.md) and
[web entry points](docs/finding-export-entrypoints.md).

## Platform layers

- `lightup.domain` — multi-client persistence with in-code tenant isolation.
- `lightup.ai.gateway` — provider-neutral model gateway.
- `lightup.ai.orchestration` — typed tool calls, immutable run context, policy gate and evidence ledger.
- `lightup.labeval` — lab-only evaluation run path and benchmark schema.
- `lightup.webapp` — minimal progressive-disclosure web shell.
- **Security Twin (planned)** — durable current-state model, attack graph and future-state change simulation.

See `docs/ai-orchestration.md` for the AI-layer contracts.
