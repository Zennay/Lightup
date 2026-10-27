# Offline conflictgroepen voor parallel LightUp scope-authorization werk

**Fase:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Dit is géén toestemming om een issue of branch over te nemen.

## Nieuwe functionaliteit

De bestaande [offline eigenaarschap-audit](scope-issue-ownership-audit-20261015.md) detecteert rechtstreekse dubbele issueclaims en exacte bestandsconflicten. De nieuwe [conflictgroep-analyse](../scripts/scope_issue_ownership_clusters_20261015.py) verenigt ook **transitieve** conflicten: als PR A en PR B hetzelfde issue claimen en PR B en PR C hetzelfde bestand wijzigen, vraagt de hele groep A/B/C één gecoördineerde eigenaarschapcontrole. Losstaande groepen blijven apart. Er wordt geen willekeurige PR als winnaar aangewezen.

## Gebruik en acceptatie

Geef dezelfde beperkte lokale JSON-snapshot via stdin door aan:

```sh
python scripts/scope_issue_ownership_clusters_20261015.py < snapshot.json
python -m unittest discover -s tests -p 'test_scope_issue_ownership_clusters_20261015.py' -v
```

Uitvoer is altijd JSON met `status: HOLD`, exitcode **2**, vijf letterlijk onware uitvoerings-/releasevlaggen, `source_coverage: UNVERIFIED_UNTRUSTED_SNAPSHOT`, en `unknown_worker_activity: true`. De naam `unclaimed_candidates_not_permission` is expres gekozen: een open issue zonder PR in de *aangeleverde momentopname* is niet bewezen beschikbaar. De audit neemt nooit locks, opent geen PR, voert geen handler uit en geeft geen opdracht.

- `review_groups[].prs`: de betrokken open PR's, numeriek oplopend.
- `review_groups[].duplicate_issues`: issues die meerdere open PR's claimen.
- `review_groups[].colliding_paths`: exact gelijke gewijzigde bestanden.
- `review_groups[].review_priority`: `ISSUE`, `PATH` of `PATH_AND_ISSUE` (informatief; geen releasevoorrang).
- Bij ongeldig, onvolledig of dubbel JSON krijgt de caller alleen een generieke `HOLD` zonder originele gegevens.

**Grenzen:** geen live GitHub/Notion-broncontrole, geen temporele verificatie van andere workers, geen semantische detectie van verschillende maar verwante paden, geen automatische toewijzing en geen VPS-/CI-/consentbewijs. Operator, security/privacy en exacte source/runner-controle blijven noodzakelijk. **Geen merge, deploy, scans of echte grants.**
