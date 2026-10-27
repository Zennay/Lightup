# LightUp · Nederlandstalige PR-triage met commitversiecontrole

**Fase:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.

De bestaande [Nederlandstalige werkconflictrapportage](scope-issue-full-triage-20261015.md) kijkt naar gedeelde issues en bestandspaden. Bij het verzamelen van veel GitHub-pagina's kan een PR echter nieuwe commits krijgen, waardoor de export tegenstrijdige of achterhaalde bestandsversies bevat. De strengere [offline PR-head-review](scope-issue-pr-head-consistency-20261015.md) controleert de *zelf opgegeven* HEAD voordat een conflictgroep als reviewhint wordt getoond.

## Gebruik

```sh
python scripts/scope_issue_pinned_triage_20261015.py < local-head-receipt.json
python -m unittest discover -s tests -p 'test_scope_issue_pinned_triage_20261015.py' -v
```

De volledige invoer vereist de normale `snapshot`, `pagination`, `pr_file_pages`, `pr_change_pages` en het onafhankelijke `pr_head_receipts`-veld per PR.

**Rapportindeling:** PR-nummers en onbetrouwbare headstatussen, gevolgd door óf volledig zelf-consistente conflictgroepen met gedeelde oude/nieuwe paden, óf een opvallende melding dat de gegevens te tegenstrijdig zijn om conflictgroepen te vertrouwen. Bij niet-overlappende bestanden staat expliciet dat dit **geen vrije taken bewijst**. Bestandspaden zijn Markdown/HTML-escaped; invoerfouten geven geen privé-gegevens terug.

Alle outputs zijn **HOLD**, exitcode **2**, zonder toestemming, automatische issueclaim, runtimegrant, scanner, target, deploy of release. Ook identieke zelf opgegeven SHA's bewijzen niets over live GitHub, Notion of actief werk van anderen. Vergelijk echt GitHub PR-HEAD vóór en ná paginering en bevestig de branchbezitter zelf. Permanente VPS-CI, autorisatie/intrekking door bronhouders, security/privacy en menselijke GO blijven onafhankelijke vereisten.