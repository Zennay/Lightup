# LightUp · offline PR-repository-/branch-identiteit als HOLD-controle

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. Deze controle is opt-in en bestaat uitsluitend uit een *lokale, onbetrouwbare momentopname*. Zij geeft geen werkeigenaarstoewijzing, scanrecht, autorisatie, merge of release.

## Waarom

Een handmatig samengestelde export kan issue #101 of PR #201 uit een andere repository, fork of basisbranch bevatten, terwijl de andere regels bij LightUp horen. GitHub-nummers zijn alleen binnen hun eigen repository uniek. Gemengde exports kunnen daardoor ten onrechte conflicten tonen of verbergen, zelfs wanneer de paginering en commit-HEADs intern constant lijken.

## Uitvoering

```sh
python scripts/scope_issue_repo_identity_20261015.py < local-receipt.json
python -m unittest discover -s tests -p 'test_scope_issue_repo_identity_20261015.py' -v
```

Het volledige invoerobject bevat `snapshot`, `pagination`, `pr_file_pages`, `pr_change_pages`, `pr_head_receipts` (zie [headconsistentie](scope-issue-pr-head-consistency-20261015.md)) en aanvullend:

```json
{
  "repository": {
    "repo": "Zennay/Lightup",
    "base_ref": "main",
    "base_sha": "3333333333333333333333333333333333333333"
  },
  "pr_repository_observations": [
    {
      "pr": 201,
      "base_repo": "Zennay/Lightup",
      "base_ref": "main",
      "base_sha": "3333333333333333333333333333333333333333",
      "head_repo": "Zennay/Lightup",
      "head_sha": "1111111111111111111111111111111111111111"
    }
  ]
}
```

Dit is **alleen de uitbreiding**, geen zelfstandig geldig totaalreceipt. De SHA-waarden zijn synthetisch.

Iedere PR moet een unieke, exact passende base-repo/ref/commit en eigen head-repo/commit hebben. Een fork-PR kan legitiem zijn maar is **niet automatisch een eigen branch**; daarom krijgt zij `EXTERNAL_SOURCE_REQUIRES_OWNER_REVIEW` en worden conflictgroep-hints onderdrukt. Andere basiscommits krijgen `MIXED_BASE_HISTORY`, onbekende repository `WRONG_BASE_REPOSITORY_OR_REF`, afwijkende HEAD `HEAD_RECEIPT_MISMATCH`. Onvolledige pagina-/headgegevens blijven afzonderlijk geblokkeerd.

Ook als alle zelf opgegeven velden overeenkomen, is de status **HOLD**, `SELF_ASSERTED_MATCH_UNVERIFIED`, exitcode **2**, en blijven `source_provenance_verified`, `worker_activity_verified` en alle vijf toestemming-/scan-/merge-/deploy-/releaseflags letterlijk **false**. De tool doet **geen live GitHub/Notion API-aanroep** en kan onjuiste bronclaims niet herkennen wanneer de aangeleverde metadata zelf consistent maar vals is.

Bronhouder moet zelf live PR-HEAD, base, fork, commitgeschiedenis, Notion-lane en andere workeractiviteit controleren. Werk aan productieautorisatie/intrekking, duurzame evidence vóór dispatch, VPS-runnerbewijs, echte labisolatie, privacy/security en menselijke GO blijft afzonderlijk noodzakelijk.