# LightUp scope-authorization · conflicttriage zonder werk over te nemen

Deze CLI maakt van één **onbetrouwbare, lokaal aangeleverde** scope-issue/PR-snapshot een leesbaar Nederlands overzicht met volledige conflictgroepen. Zij voert geen GitHub/Notion-calls uit en kan nooit een bestaande worker vervangen of een issue claimen.

## Uitvoering

```sh
python scripts/scope_issue_ownership_triage_20261015.py < snapshot.json
python -m unittest discover -s tests -p 'test_scope_issue_ownership*20261015.py' -v
```

Zie [strikt snapshotformaat](scope-issue-ownership-audit-20261015.md) en [algoritme voor transitive conflictgroepen](scope-issue-ownership-clusters-20261015.md). De rapportage groepeert PR's wanneer zij **via meerdere paden of issueclaims** indirect botsen. Bijvoorbeeld: PR #211 claimt hetzelfde issue als #212; #212 raakt hetzelfde pad als #213. De groep #211/#212/#213 moet dan gezamenlijk op live GitHub en Notion worden beoordeeld. Losstaande groepen blijven zelfstandig.

Het uitvoerbestand is Markdown voor menselijk overleg. Bestandsnamen worden onschadelijk gemaakt voor Markdown/HTML; de ruwe snapshot wordt niet op foutpaden uitgegeven. Geen enkel resultaat kan status READY of GO aannemen. **Geldige én ongeldige invoer geven exitcode 2 en HOLD**.

## Geen vrijgave

De snapshot bewijst niet dat alle issues, PR's, branchwissels of actieve workerreserveringen zijn opgehaald. Het ontbreken van een dubbele claim betekent daarom nooit dat een issue vrij is. Er wordt geen netwerk gebruikt, geen execute/handler aangeroepen, niets geschreven, geen customer-scan gestart, geen grant aangemaakt en niet gedeployed. Onafhankelijke security/privacy, echte autorisatie, exacte VPS-CI en menselijke GO blijven vereist. **INCUBATE M3/M7 · DRAFT/HOLD.**
