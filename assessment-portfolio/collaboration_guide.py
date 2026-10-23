#!/usr/bin/env python3
"""Scriptless original-source-neutral human collaboration instructions in ZIP."""
from __future__ import annotations
from base64 import b64encode
from hashlib import sha256
from html import escape
from portfolio import Hold

STYLE="""
:root{font:16px/1.5 system-ui,sans-serif;background:#0a1829;color:#eaf8fd;color-scheme:dark}
*{box-sizing:border-box}body{max-width:1200px;margin:auto;padding:25px}
header{padding:36px;background:linear-gradient(130deg,#164e5e,#1a2941);border:1px solid #447386;border-radius:22px}
small{letter-spacing:.14em;font-weight:800;color:#a1efd4}h1{font-size:clamp(2.1rem,5vw,3.9rem)}
p{color:#bbd3e0}strong{color:#f3dca4}.steps{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:22px 0}
section{padding:23px;background:#152e44;border:1px solid #3c6478;border-radius:14px}
pre{padding:14px;background:#081521;border-radius:9px;overflow:auto;color:#c4e8db;white-space:pre-wrap;overflow-wrap:anywhere}
code{color:#afecd5}a{color:#b3e8d9;font-weight:800}
.note{border-left:4px solid #ebce90;background:#302d3b;padding:21px;border-radius:10px}
footer{color:#aec6d5;font-size:.84rem;margin:24px 0}
@media(max-width:800px){body{padding:12px}.steps{display:block}section{margin:14px 0}}
@media print{body,header,section,pre{background:white;color:#222}p{color:#222}}
"""

def build(summary):
    if (type(summary) is not dict or type(summary.get("agenda_count")) is not int
            or not 1<=summary["agenda_count"]<=12
            or summary.get("claimed_status") not in ("HOLD","REVIEW_ONLY")):
        raise Hold("unknown original private human collaboration scope")
    digest=b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'sha256-"""+
        digest+"""'; script-src 'none'; img-src 'none'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp · Offline human collaboration</title><style>"""+STYLE+"""</style></head>
<body><header><small>LIGHTUP / ORIGINAL HUMAN REVIEW / PRIVATE OFFLINE</small>
<h1>Collaborate without changing the originals.</h1>
<p>This workspace has <strong>"""+str(summary["agenda_count"])+""" original source agendas</strong>.
All contributors work with the same unmodified original workspace and separately retained original manifests and choices. Changes concern only a human planning stage, next neutral role, and proposed discussion date.</p>
<strong>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · """+
        escape(summary["claimed_status"])+""" · NO GO</strong></header>
<div class="steps">
<section><small>STEP 1</small><h2>Independently review</h2>
<p>Give reviewers separate copies of the exact same private original workspace only where its owner and privacy policy permit. Each person opens <a href="original-human-review-studio.html">Original human Review Studio</a>, edits human-only notes and chooses <strong>Export ALL original human proposals</strong>. Keep every original input untouched.</p>
</section>
<section><small>STEP 2A</small><h2>Combine without conflicts</h2>
<p>Use <code>assessment-portfolio/portfolio_merge.py</code> with one original workspace, matching original manifests and choices, and repeat <code>--proposal-bundle</code> for each contributor. It rejects ANY two human drafts changing the same agenda/slot. Output is a NEW owner-private merged bundle, never authority.</p>
</section>
<section><small>STEP 2B</small><h2>Handle conflicting edits</h2>
<p>Run <code>portfolio_mediation.py</code> on those same unchanged original files and complete contributor bundles. Open its NEW standalone private HTML. Resolve every contested original source slot by explicitly selecting a proposal or keeping old human notes. The browser never picks a winner.</p>
</section>
<section><small>STEP 3</small><h2>Generate the next human review</h2>
<p>No overlaps? Use <code>collaboration_cycle.py --next-as-of YYYY-MM-DD</code> to merge and create the next offline private human workspace in one command. Human-mediated conflicts? Use <code>mediation_return.py --resolved-bundle FILE --next-as-of YYYY-MM-DD</code>; all chosen values must still match exact original or contributed human values.</p>
</section>
</div>
<section><h2>Operator command outline</h2>
<p>Run from the LightUp project checkout, against exact ORIGINAL source files retained separately outside this private ZIP. The names below are placeholders, not actual files in this ZIP. Repeat each source argument once per original source and each independent contributor bundle once per reviewer.</p>
<pre>python3 assessment-portfolio/collaboration_cycle.py \
  --workspace ORIGINAL-human-workspace.zip \
  --original-manifest ORIGINAL-manifest-A.json \
  --original-choices ORIGINAL-choices-A.json \
  --proposal-bundle REVIEWER-A-all-proposals.json \
  --proposal-bundle REVIEWER-B-all-proposals.json \
  --next-as-of YYYY-MM-DD \
  --output NEW-private-collaborative-cycle.zip</pre>
<p><strong>Conflict on any original agenda/slot?</strong> Do not retry with dropped contributors, last-write-wins or unsigned approvals. Choose the separate mediation and authenticated original source-owner follow-up path.</p>
</section>
<aside class="note"><strong>Do not confuse human coordination with verified outcomes.</strong>
<p>Source SHA-256 values are unsigned byte correlations. Contributor numbers are not authenticated identities. No original source finding, target, client record, evidence, scanner, model, role assignment, scope approval, grant, permission or actual engagement is changed or executed here. Original exact-head hosted/permanent named VPS CI, source-owner and independent security/privacy reviews, genuine separate authenticated client/operator consent with action-time revocation, #177/#182/#829 and explicit HUMAN GO remain mandatory for any real activity or release.</p></aside>
<footer>Scriptless private owner workflow · no network, scripts, browser persistence, targets, scans or credentials</footer>
</body></html>""").encode("utf-8")
