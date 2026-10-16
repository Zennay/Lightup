# #896 — Fail-closed programmatic CLI opt-in for a synthetic grant-ID reviewer

**LightUp remains INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This code lives only in a private standalone test helper and is *not* authorization logic.

## Precise change and independent ancestry

A caller may invoke the opt-in `main(argv)` function directly, passing an object that implements `__eq__` to pretend to equal `["--offline-synthetic-only"]`. The previous guard evaluated that comparison before verifying the `argv` container and inner token types. Such a caller could therefore cause untrusted equality behavior and an unintended stdin read, though the helper would still have returned only a non-authorizing receipt.

On this new standalone branch (pinned above unchanged own #896 child `2d8ac90a31acf8174f10f7cda97737fec1ceceae`) we require **exact built-in `list`**, **exact one element**, **exact built-in `str` token** before comparing with the literal flag and before touching `sys.stdin.buffer`. Type admission relies on `type`, not spoofable `isinstance` or caller equality.

Two additional synthetic unittest methods model (a) a fake list object with `__class__` impersonation and `__eq__` returning true; (b) a matching-string subclass with forged `__eq__`. Both require:
- CLI exit **2/HOLD**, never REVIEW_ONLY;
- zero attacker comparator calls;
- a stub stdin object never accessed;
- exactly six false authority flags and no user input echo.

Existing canonical CLI behavior and all previous synthetic grant-ID review/no-authority controls are retained.

## What is / is not proven

New helper and test changes were **committed to GitHub** on a child owned entirely by this lane. **These two newly authored methods have not yet been executed on the exact new HEAD** (neither Python local run nor trusted hosted/VPS CI); do not count them as PASS. GitHub ancestry/diff proves branch isolation, not functional verification. Actual #873/#896 resolver/source-owner defects remain open and must be repaired within PR #107/#146 with genuine owner-reviewed source RED-to-PASS and consent/revocation/asset/risk controls, trusted registered `[self-hosted,zcloud,vps]` CI and human GO.

No real grant, handler, target, scan, deployment, prod source, PR, runner/workflow dispatch or other-worker branch modification is permitted by this isolated enhancement.
