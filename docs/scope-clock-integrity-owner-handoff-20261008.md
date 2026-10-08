# Scope clock-integrity — production-owner handoff

Status: **reference only; not production authority**. Applies to the clock-integrity acceptance work in draft PR #1038. Production policy/executor files remain owned by their existing maintainers.

## Admission invariant

At each authority-bearing decision and immediately before any target-capable dispatch, obtain a trusted timezone-aware clock reading. Reject missing, invalid, naive or non-datetime clock output, exceptions from the clock provider, and backward clock movement relative to the prior trusted decision on the same run. A failed clock check denies execution; it must never substitute a caller timestamp or wall-clock fallback.

Do not convert ambiguous local times or daylight-saving offsets into an expanded validity window. Evaluate grant `not_before` and `expires_at` using canonical UTC instants and the existing specified boundary inclusivity. A valid timestamp does not itself grant permission: issuer, tenant, exact asset, capability, revocation and risk checks all remain required.

## Owner-owned integration checklist

1. Inventory each production authorization and executor admission boundary; attach clock validation to the shared path instead of only UI or offline helpers.
2. Preserve a per-run monotonic prior trusted UTC instant where repeat admission occurs. If the clock is earlier than that instant, fail closed rather than moving the watermark backwards.
3. Evaluate grant expiry/revocation afresh at dispatch. A successful earlier check must not cache permission to execute after expiry.
4. Ensure rejection is side-effect free: no target I/O, handler invocation, grant mutation, queue enqueue or evidence success record.
5. Regression matrix: aware UTC; non-UTC aware equivalent; naive datetime; `None`; strings/numbers/bool; provider exception; backward movement; equal successive instant; expired boundary; forward jump past expiry; independent runs. A positive canonical control must still allow only already-approved authority.
6. Run offline focused regressions, hosted exact-head preflight and canonical permanent VPS CI, recording immutable run IDs and the tested commit SHA. Expected-RED reference tests are not a release green signal.

## Ownership and stop line

No production patch, real-target testing, DNS/network scanning, active capability execution, runner re-trigger or deploy is authorized by this document. Production-owner review and all exact-head proof gates are necessary before promoting PR #1038 or integrating this acceptance surface.
