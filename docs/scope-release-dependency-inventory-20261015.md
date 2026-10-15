# LightUp — offline scope release dependency inventory (2026-10-15)

**Posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.**

This is an **uninstalled, non-authorizing** local review aid, not an authorization or deployment workflow. The source owners of [live grants/revocation #107](https://github.com/Zennay/Lightup/pull/107), [risk-5 step-up #1172](https://github.com/Zennay/Lightup/pull/1172), [pre-handler evidence #1454](https://github.com/Zennay/Lightup/issues/1454), [legacy window #301](https://github.com/Zennay/Lightup/issues/301) and [permanent runner #1144](https://github.com/Zennay/Lightup/issues/1144) remain independent. Only three new owned files are added; none of those owners' files or source/runtime/runner/workflow settings are modified.

## Usage

The tool receives only *fictional* status declarations, never customer identities, tokens, targets, consent records or grants. Input shape is a strict JSON object with exactly 'schema' (integer 1) and 'checks' (one entry per gate). Each status is exactly 'MISSING', 'BLOCKED', or 'SELF_REPORTED'. No status is equivalent to verified permission.

Example via standard input:

    {"schema":1,"checks":{"client_consent":"MISSING","asset_and_capability_scope":"MISSING","live_grant_and_revocation":"BLOCKED","operator_step_up":"BLOCKED","durable_prehandler_evidence":"BLOCKED","installed_ingress_and_egress":"MISSING","permanent_vps_ci":"BLOCKED","independent_security_privacy_review":"MISSING","explicit_human_release":"MISSING"}}

    python scripts/scope_release_dependency_inventory_20261015.py < fictional.json

Every execution returns **exit code 2** and 'status=HOLD'. All six flags remain literal false: scan_allowed, grant_allowed, dispatch_allowed, merge_allowed, deploy_allowed, release_allowed. The result lists gate identifiers in stable order, never input details. Even nine SELF_REPORTED statuses produce HOLD; an empty needs_attention list is not a release signal.

A strict 8192-byte predecode input ceiling, UTF-8 decoding, duplicate-key refusal, exact schema and status type checks, and constant nonfinite refusal prevent ambiguous synthetic checklist intake. Malformed/over-budget input yields a generic, privacy-preserving HOLD.

## Mandatory independent evidence

| Gate ID | Missing trusted evidence required before release |
| --- | --- |
| client_consent | Genuine recorded client purpose-specific approval |
| asset_and_capability_scope | Trusted asset, capability, risk identity |
| live_grant_and_revocation | Current durable same-tenant grant and at-use revocation |
| operator_step_up | Separate current operator authorization for elevated action |
| durable_prehandler_evidence | Durable attempt/provenance before handler side effects |
| installed_ingress_and_egress | Installed Nginx/Gunicorn identity plus lab egress fence |
| permanent_vps_ci | Original exact-SHA jobs on permanently registered VPS |
| independent_security_privacy_review | Independent security and privacy sign-offs |
| explicit_human_release | Explicit named human GO after all independent proofs |

## Tests and limits

Run:

    python -m unittest discover -s tests -p 'test_scope_release_dependency_inventory_20261015.py' -v

Twelve local test groups exercise invalid, oversized, polymorphic, duplicate and nonfinite JSON, stable ordering, all nine gates, real subprocesses and no secret reflection. Synthetic green is not integrated production proof. This helper cannot attest GitHub, Notion, runner registration, consent, source-repair or installed ingress; self-reported claims remain unverified. In particular #301's expired test fixture and missing permanent runner proof may independently keep the repository's full release gate red.

**Do not merge, deploy, grant real authority or scan targets based on this packet.** Owner fixes, exact-head hosted plus permanently registered VPS evidence, privacy/security review and human approval stay outside this work.

## W2 — Nederlandstalig overzicht

De tweede, zelfstandige CLI `scripts/scope_release_dependency_nl_20261015.py` accepteert hetzelfde strikte fictieve JSON-formaat via stdin. De tekst noemt alle negen voorwaarden expliciet in gewone Nederlandse taal, inclusief oorzaak en noodzakelijke externe controle. Ook bij negen zelfgerapporteerde voorwaarden ontbreken geverifieerde releasebronnen en blijft het document expliciet **NIET TOEGESTAAN / HOLD / exit 2**. Er worden geen invoerdetails zoals geheime referenties, hostnames of vrije tekst in het rapport overgenomen.

Gebruik:

    python scripts/scope_release_dependency_nl_20261015.py < fictional.json

De acht extra eigen tests in `tests/test_scope_release_dependency_nl_20261015.py` controleren normale, volledig zelfgerapporteerde, misvormde, te grote en potentieel gevoelige fictieve packets in echte lokale subprocessen, consistente uitkomst ongeacht JSON-volgorde en de onveranderlijke negen veiligheidsvoorbehouden. **Totaal lokaal geverifieerd: 20/20 tests**, Python 3.13. De volledige GitHub-hosted Python 3.11/3.14 en permanent geregistreerde VPS-run voor de laatste exacte commit moeten onafhankelijk worden beoordeeld; CI-wachtrij is geen succes.

## W3 — runnable fictional example

A wholly synthetic, checked-in [fictional packet](fixtures/scope-release-fictional-packet-20261015.json) is provided for reproducible local review. It includes no customer asset, domain, IP, grant, credential or real approval. It demonstrates a self-reported gate next to eight still missing/blocked ones without treating either status as permission.

    python scripts/scope_release_dependency_inventory_20261015.py < docs/fixtures/scope-release-fictional-packet-20261015.json
    python scripts/scope_release_dependency_nl_20261015.py < docs/fixtures/scope-release-fictional-packet-20261015.json

Each command must exit 2 with an explicit HOLD/non-allowed receipt or summary. The new regression reads the actual committed fixture and verifies one unverified self-report, eight remaining attention IDs and all six release/dispatch/scan flags literally false. **21 local groups now passed** (13 base + 8 Dutch), but this local proof is never an integrated security sign-off.

## W4 — deadline en transportgrens voor beide lokale CLI's

Beide standalone reviewers gebruiken nu één gedeelde, **uitsluitend lokale** stdin-lezer. Een anonieme pipe waarvan de schrijver de laatste bytes nooit afsluit mag de offline review niet onbeperkt vasthouden: na een **monotone EOF-deadline van 2 seconden** volgt de bestaande generieke HOLD (exit 2). Een compleet JSON-document zonder EOF is bewust ook HOLD, omdat de transportbron geen volledig afgesloten snapshot heeft geleverd.

- Maximaal 8192 inputbytes, met slechts één extra byte om overschrijding te herkennen. De deadline geldt voor het hele lezen, niet opnieuw per fragment.
- Normale gesloten pipes en reeds geopende reguliere lokale stdin-bestanden blijven toegestaan. Niet-lokale AF_UNIX-socket-stdin en character devices worden zonder lezen afgewezen.
- De oorspronkelijke blocking-mode van stdin wordt na alle aflooproutes teruggezet; er wordt geen pad geopend, geen netwerkverbinding gelegd en geen klantgegevens in de terugkoppeling opgenomen.
- Afzonderlijke nieuwe echte subprocessregressies in `tests/test_scope_release_stdin_deadline_20261015.py` controleren onafgesloten partiële én volledig gevulde pipes, fragmenten gevolgd door EOF, grenswaarden, gewone bestanden, AF_UNIX/character devices en nooit toegekende permissies.

Deze grens verbetert de betrouwbaarheid van **niet-geïnstalleerde** reviewers, maar maakt geen claim over echte runtime-mandaten, operatorconsent, daadwerkelijke runnerregistratie of vrijgave. Geen actief scanverkeer, merge, dispatch, grant of deployment.

