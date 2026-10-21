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
  compact `-H'Authorization: ...'` and `-H"Cookie: ..."` forms
  (without a space after `-H`);
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
- **HAR/JSON HTTP header objects:** adjacent quoted
  `"name": "Authorization", "value": "…"` and reversed
  `"value": "…", "name": "Authorization"`; also Cookie,
  Set-Cookie and known API-token headers. The quoted header value
  is masked, not the header name. Unusual HAR layouts still require
  independent HUMAN inspection.
- **HAR cookie/query/form parameters:** common HTTP Archive exports can
  encode sensitive fields in adjacent JSON \`"name"\` and \`"value"\`
  members inside \`cookies\`, \`queryString\` or \`postData.params\`, rather
  than as JSON object keys. Known session ID, CSRF/XSRF, bearer/auth
  token, API key, password, signature and other credential-like names
  now mask the paired *value* in either member order, including escaped
  quoted values. The ordinary human-readable name is kept for local
  review. HAR field names that do **not** match the known list, unusual
  key order/extra members, multiline values and overlong fields are not
  guaranteed masked. This is **not** general HAR sanitization; never
  upload or disclose an output on the strength of this feature.
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
{"cookies":[{"name":"sessionId","value":"example_cookie"}]}
{"postData":{"params":[{"value":"example_key","name":"api_key"}]}}
```

This is a description of recognition, **not an executable command,
functional test, or proof of comprehensive masking**. Unknown field names,
arbitrary secret formats, browser automation dumps, screenshots, original
customer data, values encoded in unexpected ways and personal identifiers
may remain. Original redacted text is still **PRIVATE**. No output may be
published or sent to a customer solely because a pattern was replaced.

## Immediate optional HUMAN cue preview inside a NEW original workroom

A human operator who needs the literal original-source marker-navigation
**during** their initial private note review can opt in to a same-room
source-minimal preview:

```sh
python3 private-assessment-notes/notes.py prepare \
  --source /private/first-private-note.txt \
  --private-parent /private/operator-lightup-work \
  --with-mask-cues
```

This adds two 0600 files, `PRIVATE-masking-cues.html` and
`PRIVATE-masking-cues.csv`, inside the **new** 0700 original PRIVATE
prepared workroom, with an explicit clickable local link in its
`OPEN-PRIVATE.html`. Source hashes, content, decisions, current
HUMAN statuses and the original `PRIVATE-source-bindings.json` format
are unchanged. The original editor/finalizer remains mandatory and no
external action occurs.

This embedded preview is merely a navigation aid, **not a separate
independently receipted artifact**. For byte-bound independent custody,
run the standalone original native `masking-cues` command described
below, and keep its source-linked 0600 receipt. When this option is
omitted, `notes.py prepare` retains its original product behavior;
previously generated packets are not changed or reinterpreted.
Neither presence nor absence of masking placeholders is evidence
that secrets or personal data are absent.

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

The current PRIVATE cue receipt is source-bound **v3**. Known HAR
cookie, query and form credential placeholders appear in the
**Structured config** category; prior HAR HTTP-header placeholders remain
under **HTTP/shell**. Cue counts are literal placeholder occurrences,
not claims that a value was safely removed. Previously issued **v1 and
v2 receipts remain exactly reopenable without reinterpretation**; the
native reopen command applies their historical marker lists and leaves
older workrooms unchanged.

**This is NOT a count of detected secrets or completeness score.** Literal
placeholder strings can already exist in source text, and unknown secrets
will not have placeholders. Zero is not safe, nonzero is not a privacy
verdict, and neither authorizes disclosure, actual target assessment,
automated decision-making or a merge. The original independent HUMAN
review remains mandatory. The command creates no model/network/target
work and exits REVIEW_ONLY (2).

### Reopen the original PRIVATE masking-cue receipt without writes

After preserving that new cue room as owner-private 0700 (and every
artifact 0600), a human may inspect it again against the **unchanged
original prepared source workroom**:

```sh
python3 private-assessment-notes/notes.py masking-cues-reopen \
  --original-kit /private/operator-lightup-work/PRIVATE-lightup-notes-<actual-id> \
  --room /private/operator-lightup-work/PRIVATE-lightup-masking-cues-<actual-id>
```

This reopens the original owner-private per-source masked note SHA/size
manifest and source bytes; it recomputes the literal marker summary,
private unsigned source-bound receipt, 0600 CSV and scriptless HTML
and requires their exact bytes. Missing or changed originals, receipts,
CSV or HTML refuse before any effect. The command **never modifies
the earlier original note source, its review kit or cue room** and
always returns HOLD (3) even on a successful local re-open.
Neither an unsigned digest nor an unchanged redacted marker can prove
source-owner identity, safe masking, authenticity or client consent.

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
