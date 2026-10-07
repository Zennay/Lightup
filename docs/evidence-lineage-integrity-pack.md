# Evidence-lineage integrity pack

Issue #863 composes six independent evidence-lineage integrity slices into one candidate.

## Exact ancestry

The pack starts from draft PR #859 exact head:

- #858 / #859 Security Twin primitive evidence references:
  `50d0028e6b6034033416f147b7fe31bb97fad44d`

It then carries the exact source, regression and contract content from:

- #860 FutureSecurityEffect evidence IDs:
  `ac43c0c305d497437439cc0e8f1ef881fe3ac3fa`
- #861 FutureMaterializationResolution evidence IDs:
  `7a1f4cfd9555b630dc3c4ef2b65bb8787ff4b813`
- #862 SemanticChangeSignal evidence refs:
  `2f6eb3c7a60b46db81f451649e4cd94014c15e3a`
- #864 FutureSubjectResolution evidence IDs:
  `383b6b472101a92fbea45f9b0b26ad8e446535c6`
- #866 ST4 transition-verification evidence input:
  `caf741f28c1e942bbe32e85d9bab707427ae94fd`

## Integrated boundary

Across ST2, ST3 subject/materialization/effect resolution, ST4 transition verification and the Security Twin primitives, evidence lineage now fails closed on producer-impossible typed states:

- exact built-in tuple containers;
- exact built-in non-blank string members;
- duplicate references rejected;
- required evidence remains required;
- optional evidence remains optional where the existing model permits it;
- no trimming, sorting, stringification, deduplication or repair.

## File ownership

The four production files are disjoint:

- `src/lightup/changes.py`
- `src/lightup/future_materialization.py`
- `src/lightup/future_effects.py`
- `src/lightup/future_subject_resolution.py`
- `src/lightup/future_attack_path_transition_resolution.py`
- `src/lightup/twin.py`

The pack does not touch domain/labsync persistence, review/remediation stacks, scope authorization, target-capable paths, deployment, verdict creation or attack-path mutation.

## Validation posture

Draft PR #859 already has a green hosted/offline preflight on its exact parent head. Its canonical self-hosted run remains queued. This composition branch intentionally has no PR/workflow yet; once canonical capacity clears, it is the preferred integrated exact-head validation candidate for #858/#860/#861/#862/#864/#866 together.

## Safety

Validation/integrity only. No target interaction, evidence collection, capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
