# PRIVATE HUMAN role-return reconciliation

**DRAFT/HOLD · INCUBATE M3/M7 · PLAN/LAB ONLY · REVIEW_ONLY.**
This is an offline operator-only read of fictional or already existing authorized
lab review *records*, not an assessment or permission to contact a target.

## Product workflow

A recipient's voluntarily assigned HUMAN role is not identity authentication.
Previously, separate selected-role packets could be consolidated into the next
workroom, but the operator did not receive a readable review of **which
original local slots were selected, what changed, and which suggested roles
still report pending work**.

The native `role_return_reconcile.py` now admits one to five *complete original
two-file source-bound return packets*, against the same original five-file
Launchpad and two to eight unchanged operator-ordered HUMAN rounds. It
rejects duplicate packet directories and all overlapping source ordinals:
there is no automatic precedence and no risk of merging another role's notes.
Every original packet, receipt, owner-private worksheet, and original lab
source must re-admit, including a second source read immediately before
publication. An unsigned local packet does not authenticate an actual person.

Create the output directory as a new mode-0700 directory owned by the current
user. The source folders and result must all be separate.

```sh
mkdir -m 700 ~/private-human-reconciliation

python3 assessment-launchpad/role_return_reconcile.py \
  --bundle-dir ~/private-lab-launchpad \
  --round-dir ~/private-human-round-01 \
  --round-dir ~/private-human-round-02 \
  --role-return-dir ~/private-owner-return-security \
  --role-return-dir ~/private-owner-return-privacy \
  --output-dir ~/private-human-reconciliation
```

The result consists of exactly four exclusive mode-0600 files:

* `lightup-lab-human-return-reconciliation-private.html`: offline,
  scriptless, SHA-256 CSP-pinned table of suggested role, original **local
  ordinal**, prior vs proposed HUMAN stage, and whether a private note changed.
  It does **not** include endpoint URLs, note text, filesystem paths, hashes
  or authenticated reviewer identities. It must still be kept PRIVATE.
* `lightup-lab-human-return-reconciliation-private.csv`: the same
  fixed-vocabulary ordinal/role/stage change matrix, no note text.
* `lightup-lab-human-return-reconciliation-counts.json`: source-free
  overall change counts, suggested-role workload and explicitly negative
  identity/authorization/HUMAN-GO flags. Small cohorts may be identifiable.
* `START-HERE-RECONCILIATION-PRIVATE.txt`: use and safety restrictions.

Read-only replay verifies **exact canonical file inventory and content** from
the original source and the same HUMAN returns, without changing either:

```sh
python3 assessment-launchpad/role_return_reconcile.py \
  --bundle-dir ~/private-lab-launchpad \
  --round-dir ~/private-human-round-01 \
  --round-dir ~/private-human-round-02 \
  --role-return-dir ~/private-owner-return-security \
  --role-return-dir ~/private-owner-return-privacy \
  --verify-output-dir ~/private-human-reconciliation
```

To actually create the **next** HUMAN round, the original source-bound returns
must still be passed to `advance.py` with matching earlier-round/previous-round
arguments. This reconciliation output never grants access, replaces a reviewer,
approves a remediation or permits a scan.

No network, model, target, grant, consent or active assessment is involved.
Permanent CI, independent privacy/security, authentic client/operator consent
with action-time revocation, original source owner, and explicit HUMAN GO remain
mandatory for release.
