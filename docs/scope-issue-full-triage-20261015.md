# LightUp: leesbaar eindrapport van PR-bestandsconflicten en hernoemingen

**Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.**

De bestaande offline modules bewaken issue-/PR-paginering, bestandenpagina's en zowel het oude als het nieuwe pad bij een hernoeming. De nieuwe [Nederlandstalige complete triage](../scripts/scope_issue_full_triage_20261015.py) combineert die controles in één rapport zonder dat een operator afzonderlijke JSON-bestanden hoeft te vergelijken.

## Gebruik

Lever één lokaal samengesteld, onbetrouwbaar JSON-receipt aan zoals beschreven in [rename footprints](scope-issue-rename-footprints-20261015.md):

```sh
python scripts/scope_issue_full_triage_20261015.py < local-snapshot.json
python -m unittest discover -s tests -p 'test_scope_issue_full_triage_20261015.py' -v
```

Het rapport toont de huidige interne pagingdekkingsstatus; bij ontbrekende bestanden of wijzigingen verschijnt een grote waarschuwing. Iedere gevonden conflictgroep bevat PR-nummers en de exacte gedeelde of oude/nieuwe bestandsnamen. Namen worden veilig in Markdown weergegeven, inclusief aangeleverde HTML-achtige bestandspaden. Als de gegevens niets laten zien, wordt uitdrukkelijk gezegd dat **de afwezigheid van conflicten geen beschikbaar werk bewijst**.

## Toestemmingsgrens

De brondata blijven untrusted: er vindt geen GitHub-, Notion- of VPS-verbinding plaats en geen enkele bron of identiteit wordt echt geverifieerd. Ook intern complete data kan verouderd of vals zijn. De software neemt geen issue over, geeft geen grant uit, start geen scan/handler en wijzigt geen branch. Zowel geldige als ongeldige CLI-aanroepen eindigen met **exitcode 2 / HOLD**, nooit een release- of werkclaim. Alle bestaande runtime-, self-hosted-CI-, onafhankelijke security/privacy- en menselijke GO-voorwaarden blijven noodzakelijk.
