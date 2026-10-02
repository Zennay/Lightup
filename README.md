# LightUp

LightUp is an AI-assisted defensive security lab for **owned or explicitly authorized systems**.

## Current phase: M0 — infrastructure only

This scaffold deliberately has **no network execution path**. It can:

- define and validate target scope;
- model authorization metadata;
- build assessment plans from a capability registry;
- normalize findings and remediation state;
- render reports;
- prove fail-closed behavior with tests.

It cannot yet send requests, scan ports, authenticate to targets, or execute exploit logic. Network-capable adapters are a later phase and require an explicit project-level activation decision.

## Safety invariants

1. Unknown public targets fail closed.
2. Public targets require exact host or CIDR authorization.
3. Private/loopback lab targets can be permitted by policy.
4. Authorization has an owner/reference and optional validity window.
5. Every future active adapter must pass through the same scope gate.
6. No adapter may silently widen target scope.
7. Findings must include evidence, remediation, and retest state.
8. Parallel workers claim non-overlapping capabilities/write scopes before changes.

## Architecture

```text
AuthorizedTarget -> ScopeGate -> AssessmentPlanner -> CapabilityAdapters (future)
                                      |
                                      v
                              Finding + Evidence
                                      |
                                      v
                              Remediation/Retest
```

## Quick start

```bash
cd lightup
python -m unittest discover -s tests -v
PYTHONPATH=src python -m lightup.cli scope-check 127.0.0.1
PYTHONPATH=src python -m lightup.cli plan 127.0.0.1
PYTHONPATH=src python -m lightup.cli create-operator --db lightup.db \
  --email you@example.com --name "You"                        # bootstrap account
PYTHONPATH=src python -m lightup.cli serve --db lightup.db   # loopback-only web shell
PYTHONPATH=src python -m lightup.cli gateway-check           # show model role->provider bindings (offline)

# End-to-end lab demo: fixture + baseline worker + evaluation
python lab/http_fixture.py &  # loopback only
PYTHONPATH=src python -m lightup.cli lab-baseline --expect-fixture
```

The `plan` command is intentionally non-invasive: it only emits a structured plan.

The web shell (`docs/webapp.md`) serves the operator dashboard on `/` and the
client portal on `/portal/<client_id>`. It has no authentication yet and
therefore refuses to bind to non-loopback addresses; it cannot trigger any
target interaction.

## Platform layers (M1)

- `lightup.domain` — multi-client persistence with in-code tenant isolation.
- `lightup.ai.gateway` — provider-neutral model gateway (role → provider/model
  is configuration, never business logic).
- `lightup.ai.orchestration` — typed tool calls, immutable run context, policy
  gate before execution, mandatory evidence ledger.
- `lightup.labeval` — lab-only evaluation run path and benchmark schema.
- `lightup.webapp` — minimal progressive-disclosure web shell.

See `docs/ai-orchestration.md` for the AI-layer contracts.
