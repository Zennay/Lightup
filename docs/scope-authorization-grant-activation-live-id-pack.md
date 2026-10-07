# Grant activation pack — live grant ID extension

Issue: #896

## Parent

Pinned above active #887 grant-activation head:

`4153ff1422d2fe3e9221b92edac3b39935d2f8d9`

That parent is based on exact PR #146 head `33c67f8e8b17bd9214c29d02fc52954cc42655da`, which already contains the #107 authorization-resolver ancestry required by #873.

## Added contract

This child carries #873 into the active grant-activation acceptance lineage:

- live authorization resolution accepts only an exact built-in non-blank `grant_id`;
- SQLite-adaptable or polymorphic grant identifiers fail before they can participate in authority resolution;
- canonical grant snapshots preserve the existing green path;
- rejected identities cannot cause target-handler calls or evidence mutation.

## Combined unresolved activation-side gaps

The composed acceptance lineage now keeps these independent boundaries adjacent:

- #873 live grant identifier identity;
- #881 ELEVATED grant step-up binding;
- #884 RUNNING requires a current grant;
- #890 explicit current-grant evaluation instant validation.

#888 remains an inherited source-green durable recurring-retest control.

## Collision and safety boundary

Tests/docs only. No edits to resolver/executor source, `src/lightup/domain.py`, PR #107, PR #146, target handlers, evidence-remediation, deployment, verdicts or attack-path state. No target interaction, scanning, model/tool execution, remediation/retest execution or deployment is introduced.

## Runner posture

Keep branch-only while the permanent LightUp self-hosted queue remains occupied. Do not dispatch duplicate canonical proof for known expected-RED acceptance.
