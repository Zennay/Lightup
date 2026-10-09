# Offline approval-context replay contract

**Status:** isolated reference test only; no active-target capability and no production authorization integration.

Run with `python -m unittest discover -s tests -p test_scope_approval_context_replay_offline.py -v`.

The fixture in `tests/test_scope_approval_context_replay_offline.py` locks down these expectations:

- Both stored and requested receipts must be canonical `ApprovalReceipt` instances, not subclasses; all six identity fields must be exact, nonempty built-in strings. Even an identically corrupted receipt/request pair must deny.\n- Request-side lookalikes (case changes, surrounding whitespace, U+200B zero-width space, and U+0301 combining mark) are never silently normalized into stored authorization across all six binding fields.\n- An explicit approval must match the **tenant, engagement, asset, capability, run ID and operator ID** exactly. A receipt from another context cannot be replayed.
- Request-side type-confusion matrix covers seven non-string values in each of the six bound identity fields; all deny. A separate 6×4 risk/revision matrix confirms revocation overrides every otherwise valid receipt.\n- Revocation and requested approval reject truthiness-coercible non-booleans, including hostile objects implementing `__bool__`, numerics, strings and containers. Only literal `False` revocation and literal `True` approval are valid.\n- Revocation is fail-closed: only the literal boolean `False` constitutes a non-revoked receipt. Unknown, missing or coercible values deny.
- Both revisions must be positive exact integers and equal. Boolean/int coercion cannot authorize.
- Corrupted *stored* revision/risk/approval values deny even when a request duplicates them exactly. All 15 pairwise swaps among the six authorization roles deny against the original trusted binding in both directions.\n- Exhaustive reference matrices cover all 36 combinations of approved/requested risk 0–5 (and revoked variants) and 16 combinations of positive stored/requested revisions 1–4.\n- Requested risk cannot exceed approved risk, and the risk fields must be exact integers within the 0–5 policy range.
- This pure reference has no datastore, signatures, clock, network calls, real tool handlers, or durable revocation ledger. It is **not** proof that production enforces these properties.

## Required production gates (not satisfied by this PR)

The responsible source owners must bind the trusted approval and revocation records to the actual pre-I/O ToolExecutor entrypoint. Negative paths must prove **zero handler invocations**, including evidence-producing and network-capable handlers. Independently obtain green hosted and canonical permanent-VPS CI for the exact PR SHA, and obtain owner review before merge. Never activate real targets from this fixture.
