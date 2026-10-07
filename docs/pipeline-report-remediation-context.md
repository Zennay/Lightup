# Review report remediation context

Issue: #842  
Parent: #841 evidence-summary binding

## Problem

The report synthesizer was asked to explain what was found and what to do first,
but received only finding titles and a JSON-encoded coverage string. It could
not see the verifier's decision, finding severity, or the remediation advice
produced immediately beforehand.

## Contract

The report request now contains, in original finding order:

- finding title;
- severity;
- exact verifier verdict;
- exact remediation advice.

Target context remains present. Coverage counts are passed as a structured JSON
object rather than JSON text nested inside JSON.

The report stage receives no raw evidence payload, evidence summary, or evidence
references; those stay at the verifier boundary. Empty-finding reports remain
supported and still receive structured coverage context.

## Safety

This only reshapes in-memory report input after the finding-level review has
completed. It does not widen scope or authorization and does not add target
interaction, evidence collection, tool execution, remediation/retest execution,
deployment, security-verdict authority, or attack-path mutation.
