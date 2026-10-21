# Original PRIVATE assessment note masking · credential-bearing source formats

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This offline utility
helps a human with masking known credential *patterns* in locally
owned assessment notes. It **does not certify** absence of secrets,
client identifiers or personal data, and never grants permission to
share, scan, approve, assign or deploy.

## Newly covered source formats

When a human locally prepares an original owner-private review packet
using `notes.py prepare`, the existing original `lightup.redaction`
producer runs first. The extra local-only
`private_masking.mask_private_notes` phase handles further concrete
forms frequently present in assessment writeups:

- **Shell and cURL:** quoted `-H`, `--header` and `--proxy-header`
  with sensitive Authorization, Cookie, Set-Cookie or API-token headers;
  explicit `-u`, `--user`, `--proxy-user`, `--password`,
  `--api-key`, `--access-token`, `--refresh-token`,
  `--client-secret` and `--auth-token` credential options.
  This treats pasted commands as **inert text**; it never runs them.
- **Copied HTTP exchanges:** direction-marked `>`, `<` or `*`
  Cookie, Authorization and token-bearing header lines, as well as
  the existing plain header-at-start-of-line handling.
- **Structured snippets:** JSON quote-delimited password, key,
  Authorization, Cookie, session and common camelCase token values;
  owner-private YAML/config scalars with known sensitive field names;
  existing uppercase/suffixed environment-style credentials.
- **Network locations:** HTTP/FTP/SSH/WS/WSS/LDAP/SMTP and known DB
  protocol URL user-info; common sensitive URL query or fragment fields,
  including bearer/session identifiers, and semicolon-prefixed
  session IDs in application paths.
- **Existing masks stay in place:** PEM private key blocks, JWT-shaped
  values, known provider token prefixes, query/fragment signature fields,
  the original Basic/Bearer authorization redactor and the original
  per-file bound HUMAN review.

Example of a **synthetic** owner-private input:

```text
curl -u example_user:example_password \
  -H 'Cookie: sid=example_cookie; csrf=example_nonce' \
  -H 'Authorization: ExampleScheme example_secret' \
  'https://example.invalid/api;jsessionid=example_session?token=example_token'
{"accessToken": "example_key", "sessionId": "example_session"}
client_secret: "example confidential value"
```

This is a description of recognition, **not an executable command,
functional test, or proof of comprehensive masking**. Unknown field names,
arbitrary secret formats, browser automation dumps, screenshots, original
customer data, values encoded in unexpected ways and personal identifiers
may remain. Original redacted text is still **PRIVATE**. No output may be
published or sent to a customer solely because a pattern was replaced.

## NEW: offline PRIVATE original-by-original HUMAN masking-cue desk

After creating a PRIVATE original notes workroom, use the native command
below to get a separate owner-private, **source-minimal** HTML and CSV desk
for reviewing the literal known redaction-placeholder shapes observed
in each already-masked original source:

```sh
python3 private-assessment-notes/notes.py masking-cues \
  --original-kit /private/operator-lightup-work/PRIVATE-lightup-notes-<actual-id> \
  --private-parent /private/operator-lightup-work
```

The original source-bound masked content, SHA/byte source manifest, owner-
private file modes and ordinal roster are checked by the **same native
original `load_workroom` function**, without scanning or rereading
unmasked original customer evidence. This produces a NEW 0700 owner-only
directory with 0600 `PRIVATE-masking-cues.html`,
`PRIVATE-masking-cues.csv` and `PRIVATE-masking-cues-receipt.json`.

The read-only scriptless view groups literal placeholder appearances by
HTTP/shell, URL/session, JSON/YAML/config and token/key families, indexed
by **original source ordinal** only. No masked note text, free HUMAN notes,
source filenames or source hashes enter the HTML/CSV. The original
manifest and masked note hashes appear only in a separate PRIVATE unsigned
receipt; they do NOT authenticate a producer.

**This is NOT a count of detected secrets or completeness score.** Literal
placeholder strings can already exist in source text, and unknown secrets
will not have placeholders. Zero is not safe, nonzero is not a privacy
verdict, and neither authorizes disclosure, actual target assessment,
automated decision-making or a merge. The original independent HUMAN
review remains mandatory. The command creates no model/network/target
work and exits REVIEW_ONLY (2).

## Operator behavior and original source custody

Use the existing `notes.py prepare --source ... --private-parent ...`
command with 0600 owner-private original inputs and 0700 output parent;
it writes a **new** 0700 owner-private review kit, while leaving original
source inputs unchanged. The existing HTML/HUMAN decisions and separate
`finalize` are still mandatory. All output remains private and always
REVIEW_ONLY/HOLD.

Previously completed original HUMAN packets are not rewritten or
silently re-masked by this code change. Only newly prepared original
PRIVATE note kits use the new shape coverage. If a human wants a fresh
masking result for old material, the original source-owner must explicitly
prepare a **new** workroom with current source input, review it, and
compare outputs separately. Original source SHA-256 content identities
remain unsigned local evidence identifiers, never signatures.

All original LightUp exact-head CI, independent source-owner,
security/privacy/browser reviews, issues #177/#182/#829 and separate
authenticated current client/operator consent with action-time revocation,
plus explicit HUMAN GO, remain mandatory for any authorized actual
customer use, production merge or deploy. This work introduces no new
assessments, active scanning, network calls, releases or automation.
