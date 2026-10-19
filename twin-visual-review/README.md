# LightUp · Future Security topology review desk

**INCUBATE / M3–M7 PLAN-LAB ONLY / DRAFT-HOLD.** This is an **offline, human-authored model** for reviewing *hypothetical* current versus proposed system relationships. It is **not** the original authenticated SecurityTwin, a verified attack graph, an authorization record, a real security assessment or a release verdict. No scan, model/provider, real target, grant, browser persistence, telemetry, or network request is implemented.

## Why this separate product?

The existing `docs/security-twin.md` specifies immutable future-state representation, change deltas, provenance distinctions and explicit unknown-coverage semantics. There is no small operator-facing workspace in `main` for a human to explain **which explicitly declared nodes and relationships would differ** and what questions an actual owner must answer. This desk makes that review legible without touching any Security Twin/ST4/ST5 source owner or promoting modelled edges into verified security.

## Open locally

**Easiest:** save [standalone.html](standalone.html) locally and double-click it. It is one complete self-contained review desk with inline JavaScript and CSS individually SHA-256 pinned in Content Security Policy; no server, connection or extra dependency. CSP hash pinning alone is **not** an independent browser or security audit.\n\nAlternatively download `index.html`, `app.js` and `style.css` from this *same branch* into one directory, and open `index.html` without a server. The multi-file policy allows only sibling local scripts/styles, no remote URLs, requests or frames. Do not use a live server for sensitive work. To regenerate a new portable file, run `python3 build_standalone.py` into a **new** filename; the generator rejects overwrite and unexpected source template drift.

1. Start with fictional example or add a small graph manually (up to 32 nodes and 96 relationships per snapshot).
2. Edit **current declaration** and **proposed declaration** separately. “Copy current → proposed” asks before replacing the future draft.
3. Compare displayed nodes and relationships. The diff is exact by ID, edge endpoints, kind and editable human-readable labels; it cannot infer security consequences, actual reachability or verified mitigations.
4. Select questions for human owners and export a **PRIVATE** entire declared snapshot JSON (which may contain sensitive asset descriptions) or **source-free counts-only** CSV/JSON. A separate PRIVATE human brief can be exported with changed component labels; it is not encrypted or safe to share broadly.
5. Resume only with an explicitly selected strict same-format `lightup.twin_declared_review` v1 local JSON file. Any malformed/oversize/duplicate-key/unrecognized/authority-bearing file is a whole-input HOLD, preserving current work.

All graph entries are `declared` and `unverified`. No evidence IDs, claims about authenticated client/tenant identity, grant, scanner, deployment or permission are accepted. Even a 0-delta display is **not PASS**.

**Dependencies/gates:** Actual Security Twin ST2/ST3/ST4 evidence provenance, CI approval, source-owner acceptance, independent security/privacy review, scope issues #177/#182/#829, current separately authenticated client/operator permission including action-time revocation, and explicit HUMAN GO all remain separate before any actual execution, main merge or deployment. Do not treat a browser-edited draft or its digest as any of these gates.

**Ownership:** Only new `twin-visual-review/` files; leave `src/lightup/`, source-owner PRs, scope, webapp, tests, QA and CI untouched. No test suite is added or run.

## Bounded identity-to-data declaration chain exploration

The human-only browser also enumerates *only explicitly entered* directed chains from nodes labelled `identity` to `data`, up to four relationships per chain. It labels future-only and current-only declared chains as discussion prompts, **not** verified attack paths. Enumeration is bounded to 200 chains and 5000 local graph traversals: a limit triggers visible **INCOMPLETE/HOLD**, never an all-clear. Purely non-technical trust assumptions such as `may-access` are treated as authored relationship text, not a permission, access check, or proof of real reachability. No algorithms infer edges or interact with any network.
