# Offline historical capability metadata review

The [pairwise registry drift review](scope-capability-registry-drift-offline-20261014.md) only compares two snapshots. If a capability is silently introduced, reclassified or made easier to activate in one revision and subsequently reverted, comparing only original and latest would be `REVIEW_ONLY`. The optional historical reviewer checks **every adjacent transition** and returns **HOLD on any intermediate change** even when endpoints match.

Run (each argument must be a distinct physical local regular file, **oldest to newest**):

```bash
python3 scripts/review_scope_registry_history_offline.py baseline.json middle.json candidate.json
```

The history reviewer accepts between 2 and 16 caller-supplied snapshots. It uses the exact existing duplicate-key-safe and bounded registry parser; output reports canonical SHA-256 metadata fingerprints and per-transition canonical capability IDs plus approved changed-field labels, never name/description free text. It refuses aliases/hardlinks, symlinks, directories and pipes. Invalid input returns `HOLD` with no partial transition or potentially misleading fingerprints. **REVIEW_ONLY exits 3 and HOLD exits 2; exit 0 is never returned.**

### Safety and trust limits

All receipts have `authorization_verified=false`, `permit_issued=false`, `execution_enabled=false`, `merge_approved=false`, `release_approved=false`. Declared snapshot order is **not trusted chronological attestation**. File identity is not Git object provenance; metadata hash is not a signature. You must independently authenticate historical sources, decide whether missing releases exist, validate deployment/change lineage, and review actual customer grants, tenant boundaries, revocation and per-asset consent separately. This tool cannot assert that no intermediate security change took place **outside the supplied manifest sequence**. It never imports the execution engine or touches target addresses. Project posture remains INCUBATE M3/M7, PLAN/LAB ONLY.

Targeted tests: `python3 -m unittest discover -s tests -p test_scope_registry_history_review.py -v`; hosted and canonical permanent VPS evidence remain separate.
