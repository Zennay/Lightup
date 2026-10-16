# LightUp #1495 — fictieve scopeverklaring vóór handmatige beoordeling

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Dit is een geïsoleerde, niet aangesloten preview voor een menselijke reviewer. Geen toestemming of scan-/uitvoeringsbevoegdheid.

## Wat nu echt werkt

`src/lightup/synthetic_scope_notice_1495.py` levert `render_scope_notice((ScopeProposal(...),), review_at=...)`. De uitvoer is een vaste, beknopte Nederlandstalig te duiden reviewkaart (tekst bewust Engelstalig voor herkenbare STOP-woorden) waarin de voorgestelde fictieve assets, exacte capabilities, risico's, UTC-vensters, hoog-risico-step-up en de exacte woorden **NOT AUTHORIZED** zichtbaar zijn.

- Zonder invoer, met onbegrensde invoer (>32), met duplicate asset+capability, of bij ééń kapot veld volgt **één atomische HOLD** zonder hergebruik/echo van input.
- Alleen strikt kleine synthetische `<subdomain>.example.test` assets zijn toegestaan. Het is onmogelijk om hier echte klantdomeinen als goedgekeurd af te beelden.
- Alleen exacte `str`/ `int` / UTC-`datetime` veldtypes; geen bool-risicoscore, subclassing, IDNA alias, gemengde tijdzones, fold, fractional seconds, verlopen/zeer lange vensters of stilzwijgende normalisatie.
- Geldige gesorteerde voorbeelden geven alleen **REVIEW_ONLY**; `authorized`, `consent_verified`, `dispatch_allowed`, `release_allowed` blijven letterlijk `False`. Dat blijft zo voor risico 4–5.
- Geen data-opslag, netwerk, DNS, HTTP, SQLite, subprocess, toolhandlers, scan of echte identiteits-/consentcontrole. De functie is bewust **unwired**.
- Deterministisch en veilig herhaalbaar, ook als een andere worker aan originele `ScopePolicy`, `ActivationGate`, of `ExecutionPolicy` werkt.

## Synthetisch voorbeeld

```python
from datetime import datetime, timezone, timedelta
from lightup.synthetic_scope_notice_1495 import ScopeProposal, render_scope_notice
now = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
example = ScopeProposal(
    asset="test-desk.example.test",
    capability="inventory_read",
    risk=4,
    valid_from=now-timedelta(hours=1),
    valid_until=now+timedelta(hours=1),
)
notice = render_scope_notice((example,), review_at=now)
assert notice.status == "REVIEW_ONLY"
assert not notice.authorized and not notice.dispatch_allowed
print(notice.text)
```

## Bewijs en gates

`python -m unittest discover -s tests -p 'test_synthetic_scope_notice_1495.py' -v` en projectbrede CI op **dezelfde immutable commit**. Lokale ongeverifieerde of oudere runs tellen niet als hosted resultaat. Geen kunstmatig groen claimen wanneer een andere historische test (#301) faalt of wanneer VPS operatorissue #1144 nog open is.

Voor een echte UI-functie is een **afzonderlijke source owner** vereist die authenticatie, klanten-/operatorscope, echte goedkeuring met ondertekende herkomst, intrekking bij gebruik, tenant-isolatie, security/privacy, het echte gedrag van runtime en een geregistreerde VPS-runner vastlegt. Deze fictieve renderfunctie **mag nooit** als consent-verificatie, issuance of dispatch gate worden aangesloten zonder onafhankelijke review.

**Geen merge, deployment, echte grants, clientsystemen, live scans, handlers of release zonder expliciete menselijke GO.**
