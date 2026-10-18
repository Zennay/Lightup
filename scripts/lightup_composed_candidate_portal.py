"""Static no-script local index for unchanged original candidate and trends apps."""

def render(include_trends: bool) -> bytes:
    links = (
        '<a href="standalone.html"><strong>Original Candidate Matrix</strong>'
        '<span>2–12 existing canonical baseline/candidate lab reports.</span></a>'
    )
    if include_trends:
        links += (
            '<a href="trends.html"><strong>Original Longitudinal Trends</strong>'
            '<span>3–12 existing canonical cohort revisions, human drift review.</span></a>'
        )
    html = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer">
<meta http-equiv="Content-Security-Policy"
content="default-src 'none'; script-src 'none'; connect-src 'none'; img-src 'none'; font-src 'none'; base-uri 'none'; form-action 'none'; style-src 'unsafe-inline'">
<title>LightUp · Offline Candidate & Longitudinal Room</title>
<style>
:root{font-family:system-ui,-apple-system,sans-serif;background:#0a1724;color:#e7f4ff}
*{box-sizing:border-box}body{max-width:1000px;margin:0 auto;padding:clamp(20px,5vw,68px);line-height:1.55}
header{border-radius:26px;border:1px solid #42687e;padding:clamp(24px,5vw,48px);background:linear-gradient(130deg,#143d51,#101f30)}
.flag{font-size:.79rem;font-weight:850;letter-spacing:.14em;color:#daca8d}
h1{font-size:clamp(2rem,5vw,3.4rem);letter-spacing:-.05em;line-height:1.1}
p{color:#adc5d6}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px;margin:22px 0}
a{display:block;text-decoration:none;padding:24px;border:1px solid #33566f;background:#143448;border-radius:16px;color:#a8f3de}
a:hover,a:focus-visible{border-color:#90f0d7}a strong{display:block;font-size:1.12rem}
a span{display:block;color:#bbd5e3;font-size:.87rem;margin-top:10px}
.alert{border-left:4px solid #dbc28a;background:#243849;border-radius:9px;padding:18px}
code{color:#b6ebdb}li{margin:7px 0}
</style></head><body><header><div class="flag">LIGHTUP / ISOLATED LAB / OFFLINE HUMAN REVIEW</div>
<h1>Compare completed candidates. Review original drift.</h1>
<p>These are the original, unchanged LightUp browser tools with existing source-owner canonical metric output.
No model, scanner, asset access, client authorization, approval or release GO is provided.</p>
<div class="flag">INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD</div>
</header><main><h2>Original browser workspaces</h2><div class="cards">__CARDS__</div>
<section><h2>Open original comparison documents</h2>
<ol><li>Extract this sensitive ZIP into an owner-private directory.</li>
<li>Open the original Candidate Matrix or longitudinal app locally.</li>
<li>Use the browser's existing file picker. Select 2–12 or 3–12 files respectively from the
<code>reports/</code> directory, in the intended original chronological order.</li>
<li>Review source-derived metrics and discuss regressions; make no permission or GO inference.</li></ol>
<p>The original reports may contain private lab scenario identities. They are untrusted,
unsigned observations. The index.json is a PRIVATE byte-integrity inventory, not provenance proof.</p></section>
<div class="alert"><strong>Mandatory original review and release gates remain intact.</strong>
<p>Any measured HOLD stays HOLD and requires human consideration. Identical baseline metrics,
lack of reported regressions or source SHA matching are not evidence of consent, target ownership,
a verified remediation or a secure model. Original scope/security/privacy, separately authenticated
client/operator consent, at-use revocation, exact-head CI, source-owner review and explicit HUMAN GO
are all mandatory for any production authorization or deployment.</p></div>
</main><footer><p>No network, scripts, storage, telemetry, credentials or target probes from this local launcher.</p></footer>
</body></html>"""
    return html.replace("__CARDS__", links).encode("utf-8")
