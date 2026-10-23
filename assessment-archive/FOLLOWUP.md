# LightUp Archive · Human Follow-up Desk

This is the **second integrated product workflow** in the isolated Assessment Archive source branch, designed to follow up on source claims from multiple private lab sessions. Original comparator/review/authorization paths are unchanged.

## Use with the existing private archive

First create the owner-private manifest with the archive tool. Then generate a source-bound human planning form:

    python3 assessment-archive/followup.py draft --manifest /private/ARCHIVE.json --output /private/NEW-followup-draft.json

Open the new JSON **locally in an editor** (do not share its original SHA-256 metadata). For each slot, edit only the stage, next_role and review_date fields, keeping original slot/source fingerprint unchanged.

Allowed stage selections:

- PENDING_ORIGINAL: original source-owner review still outstanding.
- NEEDS_ORIGINAL_EVIDENCE: original evidence/metrics require independent inspection.
- NEEDS_SOURCE_OWNER: ask the original source author.
- NEEDS_PRIVACY_REVIEW: privacy review required before transmission.
- AWAITING_INPUT: external original source/client reply is necessary.
- HUMAN_DISCUSSION: schedule a human review conversation.

Allowed non-identifying role selectors: unassigned, source_owner, reviewer, privacy, operator. Leave review_date null or use ISO YYYY-MM-DD (a planning date, never an authorization window).

## Render the human worklist

    python3 assessment-archive/followup.py render --manifest /private/ARCHIVE.json --choices /private/NEW-followup-draft.json --output /private/NEW-human-worklist.html

This **offline accessible, printable, responsive dashboard** shows 2–64 per-slot stage/role/date choices and a source-class-specific human question. It never imports raw target names, original source notes or records. It validates the exact original private manifest-byte SHA-256, each source file's original fingerprint and every slot/stage/date **before** publishing. Changed source selection or file content requires a new separate planning form; no stale planning is silently carried forward.

To export only aggregate stage counts, use:

    python3 assessment-archive/followup.py render --manifest /private/ARCHIVE.json --choices /private/NEW-followup-draft.json --aggregate-only --format json --output /private/NEW-aggregates.json

Or use --format html for an anonymous human-facing document. Aggregate exports contain no source hashes, slots, role assignments, schedule dates, original identifiers or source text. Original private manifests and draft forms stay private.

Files are always NEW, atomically fsynced and mode 0600 (no overwrite). Browser HTML has no scripts/network/storage and a static restrictive CSP. Operator input is never treated as trusted target or consent evidence. The CLI exits 2 on source-available REVIEW_ONLY, 3 on HOLD, never 0 as successful authorization.

**DRAFT/HOLD, INCUBATE M3/M7 PLAN/LAB ONLY:** This is a human coordination form, not a grant, approval, scope resolver, scan, benchmark, automated remediation or completed security finding. The original hosted and permanently registered VPS CI, source-owner reviews, independent privacy/security, actual separate client/operator permissions, revocation and HUMAN GO remain mandatory. No active code, original webapp or other workers' source was modified. No QA suites were added or executed.

## Turn original human follow-up into an actionable agenda

After the strict original source-bound followup form has been saved, build
an owner-private chronological, source-neutral human agenda:

    python3 assessment-archive/agenda.py --manifest /private/ARCHIVE.json --choices /private/EDITED-followup.json --as-of 2026-10-18 --format html --output /private/NEW-private-agenda.html

The agenda has a source-slot human review question and shows planning dates
before/on/after the **explicit** chosen as-of date; these are private
coordination notes, not actual security incidents, deadlines or execution
permissions. --format md or --format json provides source-neutral textual
handoff, while --aggregate-only drops all individual source slots, neutral
role assignments and review dates (only group counts remain). The source
checksum and original human stage validation are still mandatory.

Console option 10 exposes the same locally bounded workflow.

### One offline review ZIP

    python3 assessment-archive/packet.py --manifest /private/ARCHIVE.json --choices /private/FOLLOWUP.json --agenda-date 2026-10-18 --output /private/NEW-human-review.zip

The packet's local index.html links to the static printable human agenda
together with the original archive and source-bound worklist. This adds
no customer consent, verification or target interactions. With
--aggregate-only, the agenda includes ONLY anonymous human counts.
