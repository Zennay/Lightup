# LightUp offline scope-werkverdeling — PR-hernoemingen hebben twee bestandspaden

**Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Geen merge, scans, echte grants of deployment.**

## Welke fout wordt voorkomen?

Het GitHub-veld `filename` beschrijft bij een hernoeming de **nieuwe** locatie. Een andere PR kan het **oude** pad tegelijk aanpassen. Een eenvoudige vergelijking van alleen `filename` laat dat conflict onterecht onzichtbaar. Het nieuwe geïsoleerde [rename-footprint hulpmiddel](../scripts/scope_issue_rename_footprints_20261015.py) neemt bij `status: renamed` daarom ook het exacte `previous_filename` mee in de *read-only* conflictanalyse.

## Invoer

Gebruik de volledige offline snapshot + PR- en file-paginering beschreven in [PR-bestandvolledigheid](scope-issue-file-coverage-20261015.md) en voeg een apart `pr_change_pages` veld toe:

```json
{
  "pr_change_pages": [
    {
      "pr": 201,
      "pages": [
        {
          "page": 1,
          "has_next": false,
          "changes": [
            {"filename": "src/new.py", "status": "renamed", "previous_filename": "src/old.py"}
          ]
        }
      ]
    }
  ]
}
```

Dit veld maakt deel uit van het volledige rootobject met `snapshot`, `pagination` en `pr_file_pages`; de verkorte weergave hierboven is alleen de toevoeging.

```sh
python scripts/scope_issue_rename_footprints_20261015.py < change-receipt.json
python -m unittest discover -s tests -p 'test_scope_issue_rename_footprints_20261015.py' -v
```

Voor iedere open PR moet de caller een onafhankelijke, intern consistente set bestandenwijzigingen aanleveren. De nieuwe `filename`-verzameling moet exact overeenkomen met de eerder geverifieerde lokale bestandslijst. Hernoemde bestanden eisen een exact ander, geldig `previous_filename`; voor alle andere statussen is dat veld verplicht `null`. Ontbrekende paginabewijzen, ongeldige of dubbele paden, onduidelijke Unicode, onbekende statussen en ontbrekende hernoemingsherkomst leiden tot afwijzing of `INCOMPLETE_NOT_EXHAUSTIVE` met onderdrukte kandidaten.

Afzonderlijke issueconflicten en oude/nieuwe padconflicten worden transitief gegroepeerd, zonder werk aan een worker toe te wijzen. Zelfs bij intern volledig bewijs blijven alle vijf toestemming-/merge-/scan-/deploy-/releasevlaggen **false**. De CLI geeft **altijd HOLD / exitcode 2** en publiceert geen lijst met vrije issues.

## Grenzen

Dit is uitsluitend een door de caller aangeleverde, **niet-geauthenticeerde** momentopname. Zelfs als geen conflict wordt gevonden, kan de snapshot verouderd of incompleet zijn, en andere workers kunnen ongemeld bezig zijn. De tool benadert geen GitHub/Notion API, netwerk, host of klantdoelwit, voert geen scanners of handlers uit en wijzigt geen PR. Productie-scope-gates, echte operatorautorisatie/intrekking, onafhankelijke security/privacy-review, exact-head CI op permanente VPS-runner en menselijke GO blijven afzonderlijke releasevoorwaarden.
