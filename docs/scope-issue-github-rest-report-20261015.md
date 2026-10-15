# LightUp — Nederlandstalig rapport van een offline GitHub-export

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** De [REST-importadapter](scope-issue-github-rest-import-20261015.md) kan echte GitHub API-recordvelden lezen, maar is uitdrukkelijk **geen** geauthenticeerde bron of autorisatie. De [rapport-CLI](../scripts/scope_issue_github_rest_report_20261015.py) gebruikt exact dezelfde invoer en vertaalt de waarnemingen naar menselijke taal.

```sh
python scripts/scope_issue_github_rest_report_20261015.py < github-local-export.json
python -m unittest discover -s tests -p 'test_scope_issue_github_rest_report_20261015.py' -v
```

Het rapport toont drie onafhankelijke signalen: of issue-/PR-/bestandenpagina's en expliciete claims ontbreken; of een PR uit een externe fork komt; en of bestanden of issues direct/transitief door meerdere PR's worden geclaimd, inclusief het oude pad bij een rename. Bij een onvolledige export verschijnt een opvallende waarschuwing. Bij geen waargenomen overlap staat nadrukkelijk dat dit **geen beschikbare taak** bewijst.

Alle padnamen worden veilig als Markdown geëscaped, zelfs wanneer ze HTML-achtige of Markdown-controltekens bevatten. Het rapport geeft geen originele foutinput weer, nooit een issue-toewijzing en geen vertrouwelijk target of runtimegrant. Zowel geldige als ongeldige input eindigt met **HOLD / exitcode 2**.

**Niet inbegrepen:** netwerkverbinding, GitHub/Notion-authenticiteit, alle live pagina's, head-consistentie vóór en ná ophalen, automatische claiming, scans, echte operatorautorisatie/intrekking, security/privacy-review, VPS-acceptatie of menselijke GO. De bestaande aparte head- en repository-identity-audits mogen daarvoor niet stilzwijgend als voldoende worden beschouwd.