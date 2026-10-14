# LightUp atomic incubation review dossier (#1364)

LightUp remains **INCUBATE M3/M7, PLAN/LAB ONLY**. An operator should not
have to infer a combined review verdict from three separate opt-in metadata
CLI outputs, and one favorable result must never hide another gate's HOLD.

This new **developer-only source-local** dossier reviews a single canonical
bounded manifest with three independently existing checks: closed-world
catalog (31 capability IDs, fixed incubation states), independent
incubation posture (sensitive labs and explicit activation), and
field-level human-readable metadata drift (approved names/descriptions).

Run:

```bash
python3 scripts/review_scope_incubation_dossier_offline.py
python3 -m unittest discover -s tests -p 'test_scope_incubation_dossier_offline_20261014.py' -v
```

All three checkers evaluate the same manifest bytes. Any invalid shape,
unrecognized component status, inconsistent fingerprint, malformed
identifier/code/field, or contradictory component returns one **atomic
HOLD** without partial positive claims. On well-shaped changes, the
dossier includes three component states, a canonical unkeyed SHA-256
metadata fingerprint, sanitized fixed violation codes and sorted canonical
ID + `name`/`description` field labels. It never echoes source
name/description text, target addresses, customer or tenant data.

Unchanged current source metadata gives **REVIEW_ONLY (exit 3)**,
not permission; any security-relevant mutation gives **HOLD (exit 2)**.
Both exit nonzero. Five flags remain literally **false**, regardless
of all other statuses: `authorization_verified`, `permit_issued`,
`execution_enabled`, `merge_approved`, `release_approved`.
The dossier never issues grants, scans, starts engines, registers
callbacks, reads/writes a customer DB or invokes targets/network/SSH.

These are *code-local developer-selected reference manifests*, not
trusted immutable release provenance or signed customer consent. The
same repo owner could change all three implementations together. Real
authorization requires independently authenticated tenant/asset ownership,
scope, risk/time window, live revocation and explicit operator approval.
Actual permanent VPS release/CI and production deployment remain
separate decisions. This is not an OS-enforced network/filesystem sandbox.

The 14 regression methods exercise all three real checkers and the actual
CLI, valid source, name/description-only changes, missing/extra
capabilities, activation changes, invalid/legacy records, synthetic
contradictory component responses, privacy and no-success exit behavior.
Only four NEW script/src/test/docs paths are introduced; other workers'
runtime/orchestration/StateStore/CI/runner/production paths are untouched.
