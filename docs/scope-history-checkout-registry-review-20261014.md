# Offline history-to-checkout registry consistency (no authority)

## Why this exists

The separate [historical review](scope-capability-registry-history-review-20261014.md) checks every adjacent release-like snapshot. An untrusted operator could supply two byte-identical *stale* snapshots and receive a `REVIEW_ONLY` metadata result, even when the actual capability registry in the current LightUp checkout has changed. This optional cross-check ensures the **last declared snapshot** also matches metadata exported from the **current local `get_capabilities()`**.

```bash
python3 scripts/review_scope_history_against_checkout_offline.py baseline.json candidate.json
```

The script takes **two to sixteen** distinct local regular JSON files in caller-declared order; it reuses bounded local file open/physical identity enforcement (reject symlinks, hardlinks/aliases, named pipes, directories and malformed inputs). The last supplied file is independently compared to actual local registry metadata with canonical exact-model/enum/boolean identity, validated names and descriptions. The CLI is strictly offline and **never returns exit 0**: `REVIEW_ONLY=3`, `HOLD=2`.

## The fail-closed decisions

- If snapshots match each other **but not the actual local registry**, it returns `HOLD` with reason `latest_snapshot_differs_from_local_registry`. The receipt lists only the changed *canonical capability IDs* and the fixed field names; it never emits the capability name or description text.
- If a historical intermediate change occurred and the latest snapshot matches the actual registry, it **still returns HOLD**: prior history cannot be washed away by a reversion.
- If historical metadata, actual local registry metadata, or file structure is invalid, the result is `HOLD` with **no partial fingerprint or change details**.
- Only if the **entire declared history has no drift** and the **last declared snapshot matches the current checkout metadata** can it return `REVIEW_ONLY`. That is *never* a security approval.

All outputs explicitly hardcode `authorization_verified=false`, `permit_issued=false`, `execution_enabled=false`, `merge_approved=false`, `release_approved=false`.

## Trust boundaries

**The local source checkout is not independently authenticated.** The review does not verify Git commit provenance, checkout ownership, signatures, exhaustive release chronology, a real deployment version, customer consent, revocation, grant lineage, or actual runtime allowlisting. An attacker controlling both history and local source can make metadata match; this must not be treated as release/security attestation. No network, target interaction, automatic permit, grant, policy update, deployment, scan or production-VPS operation is performed.

The 20 synthetic and real-checkout regressions include stale equal histories, temporary security changes, legacy format downgrade, type confusion, symlink/hardlink/FIFO rejection and latest real registry fingerprint consistency. Hosted exact-head CI and separately registered permanent VPS evidence remain distinct. LightUp continues **INCUBATE M3/M7 · PLAN/LAB ONLY**.
