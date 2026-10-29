# LightUp assessment UX benchmark — discovery pass

**Date:** 2026-10-29  
**Status:** Discovery artifact only; review required before low-fi/hi-fi redesign or implementation.  
**Scope:** Scope intake, written authorization/consent boundaries, risk choice, operator review, assessment status, findings and evidence handoff.

## What was inspected

The current default-branch UI was inspected in source at commit 7db8568f85845eb0daa2b660d86eab8ab1f7ce7c, file src/lightup/webapp/app.py (blob da46cd62b645b00e5a0f70abb5b278c625e9b544). This is **source inspection**, not an observation session with real users and not a browser/device usability test.

The current client portal renderer puts the KPI cards first, followed by findings, coverage, assessment-request history and then the request form. The request POST redirects back to the same portal route; the visible status is then found in the request list. The operator Assessments route presents assessment requests and pending risk elevations with inline decision controls. Client navigation currently exposes only Overview. The portal copy says that submitting a request starts a review and that active testing requires written authorization plus operator approval.

These are the source-defined baseline facts. We have not measured real task success, time, errors, screen-reader behavior, or actual click counts. The top user goals below are hypotheses to validate with users, not interview findings.

## Hypotheses for the three highest-value user goals

1. **Know the next safe action:** understand whether the client or operator must act next, what is waiting, and whether testing is still off.
2. **Understand recorded findings and evidence:** see what was actually observed, what is unknown, what is only marked fixed, and how to reach the underlying evidence.
3. **Request an assessment without accidentally authorizing it:** describe the intended assets and requested risk, understand the review path, and distinguish a request from written authorization, operator approval and permission to test.

Operator-side hypothesis: prioritize the oldest/pending human decision, inspect exact scope and risk context, and reach the original evidence without interpreting missing data as a clean result.

## Screenshot benchmark — 12 references

The screenshots below were visually inspected during this discovery pass. Some are product screenshots reproduced by third-party publications; they may be dated. Dribbble entries are concept work, not proof of production behavior. Treat these as visual/interaction references, not as a claim that the pictured UI is the latest release.

### 1. GitHub Code Scanning — alert triage and provenance

Source: [GitHub Code Scanning alerts documentation](https://docs.github.com/en/code-security/concepts/code-scanning/code-scanning-alerts); screenshot source: [GitHub Advanced Security walkthrough](https://medium.com/%40susovanpanja/github-advanced-security-ghas-part-1-d9754742b403).

![GitHub Code Scanning alerts list](https://miro.medium.com/v2/resize%3Afit%3A1400/1%2AYYYrxHd54ERUTgCQqN5wzg.png)

**Observed pattern:** a dense but scannable list, severity labels, status counts, branch/tool filters and a route from alert to source context. **Apply:** keep severity and source context visible; make filters and evidence drill-down useful. **Do not copy:** repository-centric terminology into the client-facing flow.

### 2. Snyk — project vulnerability dashboard

Source: [Snyk: lessons from OpenSSL vulnerabilities](https://snyk.io/es/blog/lessons-from-openssl-vulnerabilities-part-2/).

![Snyk project vulnerability dashboard](https://res.cloudinary.com/snyk/image/upload/f_auto%2Cw_2560%2Cq_auto/v1682538473/blog-lessons-openssl-add-project-github.jpg)

**Observed pattern:** severity totals sit beside a project list with timestamps and a direct remediation affordance. **Apply:** counts must lead to a specific actionable list and carry recency. **Do not copy:** raw vulnerability-volume KPIs as the first thing every client sees.

### 3. Snyk — reporting and issue detail

Source: [Snyk revamped security reporting beta](https://snyk.io/blog/snyk-new-reporting-beta/).

![Snyk reporting dashboard](https://snyk.io/_next/image/?q=75&url=https%3A%2F%2Fres.cloudinary.com%2Fsnyk%2Fimage%2Fupload%2Fv1671633598%2Fwordpress-sync%2Fblog-reporting-open-beta-issues-detail-1.jpg&w=2560)

**Observed pattern:** totals and severity breakdown are paired with a sortable, contextual issue table. **Apply:** connect a summary to the precise finding and source, and keep filters attached to the list. **Do not copy:** an aggregate “all clear” implication from a low count.

### 4. Burp Suite Enterprise — scan results overview

Source: [OWASP security testing tools comparison](https://beaglesecurity.com/blog/article/best-owasp-security-testing-tools.html).

![Burp Suite Enterprise scan results](https://beaglesecurity.com/blog/images/burp-suite-dashboard.webp)

**Observed pattern:** run timing and total issue count are explicit; severity groups and detailed issue lists are separate but connected. **Apply:** label whether the record is a run, a result or a finding; make the report reachable. **Do not copy:** decorative chart-heavy density into the primary client journey.

### 5. Burp Suite Professional — task status and finding evidence

Source: [Burp AI workflow walkthrough](https://blog.smarttecs.com/posts/2025-002-burp-ai-2/).

![Burp Suite issue detail](https://blog.smarttecs.com/posts/2025-002-burp-ai-2/assets/Active_scan_found_sql_injection.png)

**Observed pattern:** task state, issue list, severity and technical advisory share one workspace. **Apply:** provide a human-readable finding summary plus a clear path to technical detail. **Do not copy:** live-capture controls into a read-only client portal.

### 6. Detectify — vulnerability worklist

Source: [Detectify: view and tag findings](https://blog.detectify.com/product-updates/view-and-tag-findings-on-the-new-vulnerabilities-page-to-fix-them-faster/).

![Detectify vulnerability list](https://blogadmin.detectify.com/app/uploads/2020/12/vulnerabilities-view.png)

**Observed pattern:** sortable findings with discovery dates and team tags. **Apply:** show whether a finding is new/recorded, when it was observed, and what follow-up state is known. **Do not copy:** tiny low-contrast metadata or unlabeled columns.

### 7. Detectify — application-scan profile overview

Source: [AWS Partner Network: Detectify application scanning](https://aws.amazon.com/blogs/apn/strengthening-application-security-how-detectify-and-aws-help-enterprises-control-their-attack-surface/).

![Detectify application scanning profiles](https://d2908q01vomqb2.cloudfront.net/77de68daecd823babbb58edb1c8e14d7106e83bb/2026/03/09/Detectify-Application-Scanning-Screenshot-1.png)

**Observed pattern:** each profile row gives the asset, last scan, status, next scan and a row-level action. **Apply:** put status and the next safe action together; explain warning/failure states before offering another action. **Do not copy:** an active scan action without LightUp's scope, written authorization and approval gates.

### 8. Vanta — penetration-test results

Source: [Vanta's new AI agent and assessment workflow](https://www.vanta.com/resources/introducing-the-all-new-vanta-ai-agent).

![Vanta penetration test results](https://cdn.prod.website-files.com/64009032676f244c7bf002fd/688a63e730032b0e4304f733_FTR_Security%20for%20Startups%20Launch.webp)

**Observed pattern:** a plain-language summary leads into a concrete finding list and a distinct share/report action. **Apply:** use a short explanation of what the assessment actually established, then findings and report. **Do not copy:** “complete” as a synonym for “safe”; completion is a run state, not a coverage guarantee.

### 9. Vanta — security-review findings and evidence

Source: [Vanta product updates, September 2025](https://www.vanta.com/resources/new-in-vanta-september-2025).

![Vanta vendor security review](https://cdn.prod.website-files.com/64009032676f244c7bf002fd/68d200236dc177ec2e6699ad_e2518a12.png)

**Observed pattern:** review status, reviewer, due date, summary, evidence and findings are visibly related. **Apply:** show provenance, reviewer/status and evidence together. **Do not copy:** AI-generated summary language without a clearly identifiable human-confirmed source.

### 10. Vanta/DeepSource integration — vulnerability findings by severity

Source: [DeepSource Vanta integration](https://docs.deepsource.com/docs/platform/integrations/vanta).

![Vanta vulnerability findings](https://docs.deepsource.com/images/dashboard/settings/vanta-dashboard.webp)

**Observed pattern:** a severity summary is paired with a searchable finding table and source labels. **Apply:** filters should reduce the worklist, not hide the evidence that a status comes from an integration. **Do not copy:** severity color as the only signal.

### 11. Dribbble — cyber-risk monitoring SaaS concept

Source: [Cyber Risk Monitoring SaaS Dashboard UI](https://dribbble.com/shots/27090504-Cyber-Risk-Monitoring-SaaS-Dashboard-UI).

![Dribbble cyber risk monitoring concept](https://cdn.dribbble.com/userupload/46750344/file/5df59990b7d490ddff0f8423fcef23ed.png)

**Observed pattern:** visual grouping and compact risk categories. **Apply selectively:** use clear grouping and a restrained hierarchy. **Reject:** glowing gradients, ambiguous radial scores and visual polish that outshines evidence quality.

### 12. Dribbble — cyber-security dashboard concept

Source: [Cyber Security Dashboard Design for SaaS](https://dribbble.com/services/31714-Cyber-security-Dashboard-Design-For-Saas).

![Dribbble cyber security dashboard concept](https://cdn.dribbble.com/userupload/18100113/file/original-6e6408a2653e86df2182e060ee915554.png?resize=%7Bwidth%7Dx%7Bheight%7D&vertical=center)

**Observed pattern:** high-level program context and prioritized investigations. **Apply selectively:** an action-first worklist can coexist with supporting context. **Reject:** speculative scores, tiny low-contrast charts and generic dashboard tropes.

## Keep / Simplify / Merge / Remove

| Decision | Recommendation | Reason |
|---|---|---|
| **Keep** | Distinguish a request from written authorization, operator approval, active testing and recorded evidence. | These are different safety states and must never collapse into one optimistic progress badge. |
| **Keep** | Preserve severity, finding status, coverage-unknown warnings and links to original evidence. | They support real decisions and auditability. |
| **Keep** | Show who must act next and the exact recorded reason a step is waiting. | Reduces ambiguity without granting authority. |
| **Simplify** | Lead with one state-derived “Next action” panel rather than three KPI cards. | The first screen should answer “What do I need to do?” before “How many records exist?” |
| **Simplify** | Keep the request form short: assets/scope, requested risk, optional context, then explicit review/submit. | Avoids making users infer the workflow from a long page. |
| **Simplify** | Collapse historical/fixed records by default while retaining direct access and export. | Keeps current work visible without deleting audit history. |
| **Merge** | Combine the next-human-action worklist with finding/coverage context through source-local deep links. | Avoids contradictory queues and repeated navigation. |
| **Merge** | Reuse one vocabulary for client and operator statuses, with role-specific actions. | “Waiting for review” should mean the same state in both views. |
| **Remove/rename** | Replace “Confirmed fixed” with “Recorded fixed” unless independent verification is present. | A stored status alone is not proof of a complete or safe assessment. |
| **Remove** | Decorative risk scores, success colors without text, and “scan complete” copy when scope/coverage/evidence is unknown. | These can create false assurance. |
| **Remove** | Any direct active-testing affordance from the client intake screen. | Intake must not imply authorization or trigger testing. |

## Proposed task-first vertical flow

1. **Current state:** one plain-language status and one primary next action derived from the original persisted state. Examples: “Waiting for operator review”, “Scope not yet authorized”, “Evidence available for review”.
2. **Scope and risk:** show the exact assets and requested risk as a reviewable summary. An edit or correction is a separate action; do not silently broaden scope.
3. **Authorization review:** explain that submission is a request only. Written authorization, current scope, risk approval and action-time checks remain separate gates.
4. **Assessment and evidence:** show only recorded run state, coverage, findings and evidence provenance. If coverage is unknown, say so next to the status.
5. **Human follow-up:** prioritize the next unresolved action and link to the original finding/evidence, while preserving the full history.

## Short copy matrix

| State | Suggested copy |
|---|---|
| Primary CTA | “Request assessment” |
| Onboarding | “Your request starts a review. It does not start testing.” |
| Empty findings | “No findings are recorded yet. Coverage may still be unknown.” |
| Loading | “Loading recorded findings and coverage…” |
| Error | “We couldn't load the recorded assessment. No new testing was started. Try again or contact the operator.” |
| Submitted | “Request submitted for operator review. Testing remains off until scope, written authorization and risk approval are verified.” |
| Waiting | “Waiting for operator review” |
| Evidence available | “Recorded assessment evidence is ready to review” |
| Unknown coverage | “Coverage is unknown for some capabilities. No findings does not mean the system is safe.” |

Copy must be wired to real stored states; these strings are proposals, not proof that any state exists.

## Accessibility and responsive acceptance criteria

- Semantic landmarks, one clear page heading, descriptive link/button names and a keyboard-visible skip link.
- WCAG 2.2 AA contrast; status is never conveyed by color alone.
- Full keyboard navigation and visible focus, with no keyboard trap; test the actual browser flow with a screen reader.
- At least 44×44 CSS-pixel preferred touch targets for primary actions; verify at 320 CSS-pixel width and zoom.
- No horizontal overflow, reduced-motion-safe behavior and errors associated with their fields.
- Confirmed/fixed, waiting, blocked and unknown states use text labels with a reason and next action.
- Test mobile and desktop with real devices/browser zoom before claiming WCAG conformance.

## Baseline and measurement plan

**Current baseline:** source-defined portal section order is KPIs → findings → coverage → request history → request form. Request submission POSTs and redirects to the same portal; there is no dedicated confirmation route in the inspected renderer. Operator request/risk decisions are inline on the Assessments route. This is a code-derived baseline only.

**Not measured:** real-user task success, time-to-submit, scope mistakes, errors, screen-reader completion, device behavior and WCAG conformance. Do not fill these fields with estimates and call them results.

After screenshot/design review, run the same 3–5 task scenarios before/after with representative client and operator users. Record success without help, time, backtracks, scope/risk mistakes, and whether each person can correctly explain “request vs authorization vs active testing”. Add keyboard/screen-reader and responsive checks. Publish sample size and raw observation method; if there are no participants, report “not measured”.

## Review gate

This is a discovery artifact, **not** a redesign implementation. The references and proposed flow need human review, including which screenshots are appropriate and which visual direction to retain. Only after that review should the low-fi/hi-fi mobile and desktop design and a vertical UI PR begin. No screenshots or user-testing outcomes have been fabricated, and no authorization, scope, consent, scanning or release behavior is changed by this document.
