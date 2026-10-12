# Evidence-remediation W43/W44: integration acceptance (12 Oct 2026)

Status: **DRAFT / HOLD / NO MERGE / NO DEPLOY**. This is a documentation-only child of `5a30c66a0b4c1193d54b68b8e72139d6adb98af2`. The canonical `main` observed during this run is `05b80319cd0581fed21fe9d8f565bcb0a56cd2df`, not the earlier `dd4072c`. Do not infer current-main compatibility from older tests.

## Open owner issues

- #856: fail-closed decoding of persisted finding evidence on reads.
- #886: normalize malformed JSON decoder failures to a deterministic evidence-integrity ValueError.
- #851: separate canonical write-side evidence reference contract.

## W43/W44 optional preflight proof and limitations

Local W43/W44 prototype artifacts exist outside GitHub. W43 checks a complete selected SQLite batch before invoking an opt-in mapper: exact row/column shape, tenant and engagement equality, unique finding identifiers, enum strings and evidence JSON. W44 adds exact built-in, nonblank title/remediation checks before invoking W43. Earlier local reports show W43 18/18 and W44 17/17 tests passed with a reconstructed mapper. Those are **not** repository integration, exact-head CI, or proof of authorization.

Source upload was refused by connector safety checks in this run; no source implementation has been committed in this child branch.

## Required next acceptance

1. Reconcile the immutable W30 ancestor with current main and active read owner #828 without editing owner-controlled `src/lightup/domain.py`.
2. Run tests against the **real** `DomainStore._finding_from_row` and all read selectors, not a surrogate mapper. Include a later corrupt row and assert zero earlier mapper calls where preflight promises atomicity.
3. Test corrupt JSON, `null`, numbers, duplicates, blank refs, ambiguous SQL aliases, duplicate finding IDs, mismatched client/engagement, blank title/remediation, and canonical empty evidence.
4. Confirm byte-for-byte durable-row preservation on every rejection and deterministic generic errors with no evidence leakage.
5. Treat row caps and historical blank-text policy as provisional pending source-owner compatibility review.
6. Require independently inspected hosted diagnostics **and** exact-head green registered permanent VPS CI, original owner and privacy/security approval, and explicit release permission.

No external target, active scan, real customer data, remediation execution, verified retest, merge or deployment is authorized by this note.
