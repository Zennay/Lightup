# Scope authorization — negative-evidence monotonicity (offline reference)

Status: **proposal / reference-only**, 2026-10-09. Not production enforcement, not a successful LightUp CI/VPS result, and not approval for real-target interaction.

## Security invariant

Within one immutable authorization evaluation, any authoritative negative evidence (revocation, expiry, tenant/scope mismatch, missing approval, lease conflict) must prevent permission. Adding more evidence cannot turn an already denied result into permission, even if the additional evidence contains a new approval or reassuring label. A new evaluation may only be started after trusted, independently verified issuance/reapproval; this reference does not define that authority.

The test module intentionally uses a tiny pure reference function independent of production source. Its positive path indicates **reference eligibility only**, never dispatch authorization. Callers must not treat a new positive statement as cancelling a recorded denial inside the same evaluation.

## Owner integration handoff

The owner of the canonical scope/execution boundary must enforce immutable issuer-owned snapshots, trusted evidence provenance, per-tenant isolation, revision binding, and live revocation checks before and during execution. Denial records need distinct reason codes and evidence lineage; log text and AI model output cannot grant authority. This branch does not edit those source-owned boundaries.

## Coverage

Twelve stdlib unittest methods exercise canonical and absent capability, new and accumulated denial evidence, persistent snapshot denial, noncanonical evidence/revisions, malformed snapshot authority/denial containers, tenant isolation, exact dataclass identity and immutable inputs. Strict value typing and immutability here are reference choices rather than proof of actual production canonicalization.

No DNS, sockets, public targets, scanning, capabilities, deployment, database writes, or authorization widening. Keep isolated pending source-owner review and exact-head runner proof.
