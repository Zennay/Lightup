# Passive-discovery admission integrity pack

Issue: #917

Pinned production source owner: draft PR #175 exact head
`df9eac879bbe232cd1e50fd6e9dfe12ff38f8469`.

## Included contracts

- #915 — confidence metadata must be an exact built-in float before range
  validation. Bools, integers and float subclasses cannot become canonical
  passive-discovery confidence.
- #916 — prospect admission accepts only an exact `ProspectSignal` outer
  object before its authorization validator runs. Subclasses and duck objects
  cannot replace the passive/public gate.

## Composition boundary

This branch carries the two dedicated regressions, two contract documents and
this manifest only. It changes no production source.

PR #175 retains sole `src/lightup/discovery.py` ownership and its existing
exact-boolean `public_source` / `requires_target_interaction` implementation.

## Stop line

This pack only narrows offline passive-discovery metadata/admission. It adds no
active discovery, DNS/network I/O, target interaction, scanning, capability
execution, remediation/retest execution, deployment, verdict or attack-path
authority.
