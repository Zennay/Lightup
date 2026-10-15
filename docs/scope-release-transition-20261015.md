# LightUp — two-snapshot offline scope-release claim review

**Stage:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This is a standalone
review *of fictional, untrusted declarations*, not a consent, authorization,
deployment or CI attestation system. No customer identities, URLs, IP addresses,
real grants, production state or remote endpoints are read or changed.

## Why this exists

A single HOLD-only readiness checklist cannot show whether a previously
self-reported approval was subsequently withdrawn, a new blocker was
self-reported, or an unresolved condition was merely renamed from
"blocked" to "missing". These are differences between **claims**, never
trusted security findings. This is separate from runtime grant revocation
in [#107](https://github.com/Zennay/Lightup/pull/107), independent risk-5
operator checks [#1172](https://github.com/Zennay/Lightup/pull/1172)
and pre-handler durable evidence
[#1454](https://github.com/Zennay/Lightup/issues/1454).

## Use — no real data

Run only against the checked-in synthetic fixture:

    python scripts/scope_release_gate_transition_20261015.py < docs/fixtures/scope-release-fictional-transition-20261015.json
    python scripts/scope_release_gate_transition_nl_20261015.py < docs/fixtures/scope-release-fictional-transition-20261015.json

Both always return exit status **2 / HOLD**, even if every condition is
SELF_REPORTED or all nine are unchanged. The machine-readable result
includes only fixed gate IDs, fixed statuses, canonical transition labels,
counts, and **six literal false** flags for scan, grant, dispatch, merge,
deploy and release. The Netherlands-oriented report describes every gate
in ordinary Dutch and always says **GEEN VRIJGAVE / Vrijgave: NEE**.

The fictional example exhibits three distinguishable transitions:
previously self-reported consent -> MISSING (withdrawal of a *claim*);
operator step-up BLOCKED -> SELF_REPORTED (a *new unverified claim*);
permanent VPS CI MISSING -> BLOCKED (a *new blocker*).
These changes are **NOT evidence of real consent, remediation or VPS status**.

## Strict input contract

One complete JSON object, keys **exactly** `schema`, `previous`,
`current`; `schema` must be the built-in integer 1, not bool.
Previous and current must each be complete shape-identical nine-gate
packets accepted by the existing release inventory (schema 1; exact
gate names; statuses only MISSING/BLOCKED/SELF_REPORTED).
Duplicate keys anywhere, unusual types, arbitrary fields, nonfinite
JSON constants, invalid UTF-8/BOM, trailing documents, missing snapshots
and >8192 bytes fail **atomically** to a single generic HOLD response,
no partial previous/current progress counts and no echo of attacker text.

Shared stdin reader requires local pipe or regular-file stdin, an actual
EOF within two seconds of a single monotonic deadline, and at most 8192
bytes. Incomplete or unclosed transport also fails closed; socket and
character devices are not trusted packet sources.

## Tests / acceptance

Run:

    python -m unittest discover -s tests -p 'test_scope_release_gate_transition_20261015.py' -v
    python -m unittest discover -s tests -p 'test_scope_release_gate_transition_nl_20261015.py' -v

The full nine-by-nine category matrix is characterized, along with
ordering/permutation stability, withdrawals/new blockers/claim-only
increases, valid-but-never-authorizing controls, duplicate JSON keys at
any nested depth, oversized or incomplete packets, secrets, malformed
Unicode, real subprocesses, and the exact committed fictional example.
No test grants authority, sends network packets or calls target-capable
handlers. This tests the non-installed review tool, **not** runtime
safety or the real authorization store.

## Promotion gate remains separate

Real client consent, same-tenant and same-asset durable grants,
pre-dispatch revocation, operator step-up, immutable evidence provenance,
registered exact-head permanent VPS CI, installed network fences,
independent security/privacy assessment and explicit human GO are still
required. Existing [#301](https://github.com/Zennay/Lightup/issues/301)
expired test fixture is owner-gated under
[PR #1452](https://github.com/Zennay/Lightup/pull/1452);
this review does not modify it. Do not merge, deploy, issue real
grants or scan targets based on this output.

## W7 — de verschilrapportage noemt ook de juiste reparatieroute

Elk van de negen veranderde **of** onveranderde controlepunten toont nu
de vastgelegde bron-/menselijke eigenaar, de concrete benodigde
vervolgstap, wat onafhankelijk aangetoond moet worden en waarom een
zelfgerapporteerde status zelfs bij verbetering nog geen vrijgave
oplevert. Ook bij atomair ongeldige twee-snapshot input blijven alle
negen herstelvragen staan; er worden **geen** fictieve voortgang of
gevoelige brongegevens overgenomen. Zowel gewone inventarisatie als
twee-snapshot-verschillenrapport gebruiken exact dezelfde onveranderbare
catalogus. Meer details staan in
[scope-release-remediation-owner-map](scope-release-remediation-owner-map-20261015.md).

**Belangrijk:** issue-/PR-nummers in de catalogus zijn
eigenaarschapshints, geen geverifieerde actuele GitHub-status.
Veranderingen aan deze read-only rapportage hebben geen effect op echte
`ToolExecutor`-/grant-/SQLite-/runner- of deploymentpaden.
