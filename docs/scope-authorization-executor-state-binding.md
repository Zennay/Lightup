# ToolExecutor evidence-ledger binding integrity

Issue: #948  
Production owner: draft PR #107  
Pinned owner head: `c37ee27d922a7dd400eee1db39268f4a6269e431`

## Boundary

`ToolExecutor` treats evidence persistence as mandatory, but the current constructor only rejects `state is None`. Any duck object or `StateStore` subclass can therefore replace canonical evidence behavior at construction, and the retained public `state` attribute can be replaced later.

That creates an execution/evidence split: policy-gated tool execution can succeed while the evidence record is suppressed, redirected or fabricated by caller-controlled state behavior.

## Acceptance contract

The executor boundary must:

1. accept only an exact `StateStore` at construction;
2. reject duck ledgers and `StateStore` subclasses before any handler can run;
3. retain the exact accepted ledger for the executor lifetime;
4. reject post-construction ledger replacement;
5. preserve canonical execution through the original ledger, including a retrievable evidence record;
6. keep rejected constructor/rebinding attempts state-atomic with zero handler calls and zero forged evidence writes.

This contract is intentionally tests/docs only. Production changes remain with PR #107 so this slice does not take over `src/lightup/ai/orchestration.py`. It is distinct from #170, which concerns SQLite foreign-key enforcement inside the canonical `StateStore` itself.

## Safety

All proof is local and passive. It uses a passive-public in-memory handler plus temporary SQLite state. It performs no DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
