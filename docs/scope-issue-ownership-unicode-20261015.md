# Onzichtbare Unicode in scope-ownership-bestandspaden — geïsoleerde controle

**Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Deze verbetering geldt uitsluitend voor het eigen offline werkverdelingshulpmiddel en **verandert niets aan LightUp's productie-ScopePolicy, uitvoerder of klantautorisaties**.

## Waarom

Twee GitHub-paden kunnen in de browser visueel hetzelfde of omgekeerd lijken door bidirectionele stuurtekens (zoals U+202E), zero-width tekens (zoals U+200D) of canoniek gelijkende maar byte-verschillende Unicodecombinaties. Een simpele stringvergelijking kan dan ten onrechte geen overlap rapporteren. In dat geval is het veiliger de offline momentopname geheel af te wijzen dan een geruststellende, maar misleidende werkverdeling te tonen.

## Gedrag

`scripts/scope_issue_ownership_audit_20261015.py` eist nu NFC-canonieke paden, verwerpt Unicode-controle-/format-/surrogate-tekens en directionele embedding/isolation-markers. Zichtbare NFC-Unicode in een bestandsnaam blijft mogelijk; ook dat levert nooit permission of release op. De controle doet geen normalisatie die twee verschillende Git-objectpaden stilzwijgend gelijkstelt.

Bij afwijzing houden alle drie bestaande offline scripts hun **HOLD / exitcode 2** en geven geen target of originele misleidende padinhoud in een foutmelding. Dit is reviewmetadata en geen vervanging voor actuele PR-diffcontrole of beveiligingsreview.

```sh
python -m unittest discover -s tests -p 'test_scope_issue_ownership_unicode_20261015.py' -v
```

De acht nieuwe tests behandelen zichtbare NFC-positieve controle, NFD-negatief, directionele override/isolation, zero-width markers, C0-tekens, UTF-16 surrogate en een gesimuleerde collision met misleidende tweede bestandsnaam.

**Geen merge, echte scans, grants, activatie of deployment.** Permanente VPS-tests, expliciete human security/privacy GO en overige productiebronhouders blijven onafhankelijk noodzakelijk.
