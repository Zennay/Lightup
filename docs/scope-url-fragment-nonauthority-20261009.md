# URL fragment non-authority: offline scope contract

The URL fragment is client-side display/navigation metadata, never an approved asset,
authorization proof, target override, or capability grant. A fragment containing an
allowlisted hostname cannot authorize a different URL hostname. A fragment containing
an approval reference cannot replace `Target.authorization`.

This isolated acceptance test exercises the existing `ScopePolicy.decide` boundary
with synthetic `.test` names and in-memory approval objects. It performs no DNS,
network, scanning, dispatch, deployment, or real-target interaction. It does not
establish authorization safety for every HTTP client or redirect handler; each
target-capable executor must separately enforce the approved origin at dispatch.

Run: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_url_fragment_nonauthority_20261009.py' -v`

Ownership: only this document and its dedicated test file. Production enforcement
belongs to the production scope/activation owners; do not merge on hosted checks
alone without exact-head canonical self-hosted CI proof.
