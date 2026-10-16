# LightUp #1511 — LAB_ONLY capability identity (offline, non-authorizing)

**Project:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This is a synthetic
review experiment, not production authorization or a completed source fix.

## Verified current-source gap

On the current unmodified `main` `src/lightup/activation.py`,
`ActivationGate.issue()` passes through the caller's `capability_id`
without a runtime type, canonical-identity or emptiness check before putting
it into an `ExecutionPermit`. In LAB_ONLY this also applies to the permitted
loopback/private-lab path. No target/network activity is needed to reproduce.

The issue #1511 acceptance file retains two deliberately **expected RED**
source tests: one whitespace capability ID and one arbitrary non-string
equality-spoof object. Those are *unfixed installed-source failures*, not PASS.

## Implemented independent no-I/O advisory

`lightup.fictional_lab_capability_review_1511` is an **unwired** pure helper.
It accepts an exact builtin `str` and caller-provided exact builtin
`tuple[str, ...]` with 1–64 distinct exact-builtin canonical IDs. Canonical
IDs are lowercase ASCII `[a-z][a-z0-9]*(?:-[a-z0-9]+)*`, length 1–64.
All other inputs, subclass spoofing, duplicates, absent IDs and ambiguities
return generic `HOLD`. Locally coherent purely fictional records return only
`REVIEW_ONLY`. Neither output ever grants anything: frozen
`authorized=False`, `consent_verified=False`,
`dispatch_allowed=False`, `release_allowed=False`.

This reference check is **not** an attested or complete registry, not a
signature, not authenticated client/operator consent and not live revocation.
It is never called by the installed `ActivationGate`, ToolExecutor or
any handler. Nothing here changes the original runtime's permit behavior.

## Replay / acceptance

```bash
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 \
  python -m unittest discover -s tests \
  -p 'test_fictional_lab_capability_review_1511.py' -v
```

Ordinary acceptance covers valid synthetic input, non-authorizing decisions,
missing/blank/Unicode/path/overlong requests, tuple/str subclasses,
polymorphic objects, duplicate/unknown/malformed allowlists, data immutability,
no socket calls, and bound limits. Two original source tests intentionally
remain `expectedFailure`. Read the **exact HEAD** CI logs before claiming
hosted validation. Original full-suite hosted and permanent named registered
`vps-bb300bba` validation must also be independently proven; isolated
green cannot substitute for these gates.

## Ownership and release constraints

- Own only the new #1511 module, tests, document and isolated workflow.
- Do not edit `activation.py`, `models.py`, `scope.py`, any other worker's
  tests/PR/branch, default CI, grants, existing workflow or runner.
- #726 owns AUTHORIZED capability identity on #122's source-owner branch;
  #1094 owns ToolCall identifier admission; #1491 owns permit audit.
- Original runtime source owners must design and review the **actual** LAB_ONLY
  source fix, then convert RED into ordinary PASS after integration.
- Absolutely no merge, deploy, release, grants, real-target scans or handler
  dispatch until separate genuine client AND operator consent, at-use
  revocation, full source owner/security/privacy review, original full hosted
  suite and registered permanent VPS GREEN, and explicit human GO.


## W2 — optional fictional CLI (not a production interface)

New `scripts/fictional_lab_capability_cli_1511.py` reads up to 4096 bytes
from stdin and accepts only canonical ASCII JSON shaped exactly as
`{"schema":"fictional_lab_capability_v1","requested":"web-baseline","allowlist":["web-baseline"]}`.
It rejects duplicate keys, aliases, Unicode escapes, other encoding choices,
unknown fields, trailing data, poisoned types, ambiguous or duplicate
fictional IDs, and missing/overlong input. It never prints input and
never exits with code 0: **2 = REVIEW_ONLY**, **3 = HOLD**, both non-authorizing.
No target/network interaction or runtime wiring is introduced.

```bash
printf '%s' '{"schema":"fictional_lab_capability_v1","requested":"web-baseline","allowlist":["web-baseline"]}' \
  | PYTHONDONTWRITEBYTECODE=1 python scripts/fictional_lab_capability_cli_1511.py
# REVIEW_ONLY and exit 2. Never use this as permission to do anything.
PYTHONPATH=src PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -s tests \
  -p 'test_fictional_lab_capability*_1511.py' -v
```

New separate tests cover genuine CLI subprocess return codes, no input echo,
corrupt/duplicate-key/binary/oversize/Unicode and canonical fixture admission,
as well as every single-byte NUL corruption of the positive fixture. The
isolated pinned workflow now runs **both** #1511 test files. Exact W2 head
and hosted logs must be checked anew: a prior SHA's green CI cannot be
substituted for the new SHA.
