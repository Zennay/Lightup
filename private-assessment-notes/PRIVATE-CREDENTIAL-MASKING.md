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
  `-b` and `--cookie` arguments (cookie text or private cookie-file
  argument masked) and quoted form/data arguments such as
  `--data-urlencode 'access_token=…'`, `-d 'password=…'` or
  `-F 'api_key=…'`; the known field name remains visible locally.
  Also explicit `-u`, `--user`, `--proxy-user`, `--password`,
  `--api-key`, `--access-token`, `--refresh-token`,
  `--client-secret` and `--auth-token` credential options.
  This treats pasted commands as **inert text**; it never runs them.
- **Multi-field cURL payloads:** bounded quoted `--data`, `--data-raw`,
  `--data-binary`, `--data-urlencode`, `--form`, `--form-string`, `-d` and
  `-F` source text can now withhold **each separately named known credential
  field** in `field=value&session_id=...&foo=...` or semicolon-separated
  fragments. Quoted `token@/private/path` is masked as a file-source value;
  common `%5F` and `%2D` encoding of field-name separators is recognized.
  A single unquoted `name=value` or `name@source` argument is also recognized
  within a bounded shell word. Other field values are retained only inside
  the PRIVATE original notes; **their retention is not a privacy guarantee**.
  Embedded shell expressions, complicated escaping, non-form payloads,
  arbitrary field names and noncanonical encodings remain HUMAN/HOLD.
- **Additional cURL credential switches:** OAuth2 bearer, proxy password,
  TLS username/password, client key and certificate argument values are also
  withheld as inert copied text; raw originals are never executed.
- **SOAP/XML snippets:** bounded named secret elements (for example
  `<clientSecret>...</clientSecret>`) and matching quoted secret attributes
  receive a local `[REDACTED_XML_VALUE]` placeholder where their shape
  survives earlier core redaction. Nested/mixed-content XML, unknown names,
  comments and arbitrary encodings still require original HUMAN review.
- **Copied HTTP exchanges:** direction-marked `>`, `<` or `*`
  Cookie, Authorization and token-bearing header lines, as well as
  the existing plain header-at-start-of-line handling.
- **Quoted standalone HTTP header values:** known credential-bearing
  `Authorization: ...`, `Cookie: ...`, `Set-Cookie: ...` and selected token
  headers inside a single or double-quoted Python/JS/config string are now
  withheld even when not at the start of a line or attached to cURL `-H`.
  This never certifies that other literal strings lack secrets.
- **Structured snippets:** JSON quote-delimited password, key,
  Authorization, Cookie, session and common camelCase token values;
  owner-private YAML/config scalars with known sensitive field names;
  existing uppercase/suffixed environment-style credentials.
- **Nested, valid JSON/HAR records:** an additional, bounded inert JSON
  parser locates credential-bearing named fields in original JSON fragments,
  including `headers`, `cookies`, `queryString` and `postData.params`
  arrays where `"name"` and `"value"` are separated by other harmless
  members or appear in reverse order. Recognized direct JSON credential
  properties are masked even when they use escaped Unicode key spelling.
  Original JSON whitespace, non-sensitive fields and ordering are preserved.
  Each parsed fragment is capped at 128 KiB, 24 nesting levels and 4096
  nodes, with a maximum of 96 candidate parses per note. Invalid JSON,
  duplicate keys, unknown secret names, non-string values and oversized
  inputs are **NOT** certified clean. The original redactor still runs.
- **HAR postData body privacy:** in a valid, bounded original HAR JSON
  object containing exact string `mimeType` and `text` properties, a
  `application/x-www-form-urlencoded` body with a recognized credential
  field name (including strictly UTF-8 percent-decoded field names) now
  **withholds the entire original body text string**. Known
  `application/json` or `application/*+json` text bodies are withheld
  when a separate non-recursive bounded JSON parse finds an original named
  credential-bearing string value. This recognizes a real HAR body that
  previously bypassed ordinary adjacent HAR name/value field masking.
  Body inspection is limited to 16 KiB / 128 form entries and does not
  certify unknown MIME, malformed input, unusually encoded field names,
  oversize bodies or unrecognized credentials. No actual HTTP requests.
  New local markers: `[REDACTED_HAR_FORM_TEXT]` and
  `[REDACTED_HAR_EMBEDDED_JSON]`; they are **literal text cues only**.
- **HAR multipart/form-data postData:** original HTTP Archive
  `postData.text` values labeled `multipart/form-data` now also mask the
  **entire** bounded body when a conventional
  `Content-Disposition: form-data; name="credential_field"` part header
  names a known sensitive credential. This avoids exposing that part's
  raw value or other bytes of the same body in the derived PRIVATE note.
  A new `[REDACTED_HAR_MULTIPART_TEXT]` placeholder is a literal
  HUMAN navigation cue. Unknown/long/folded headers, noncanonical MIME,
  nested multipart, unusually encoded part names and bodies longer than
  16 KiB remain HUMAN/HOLD without a sanitization claim.
- **Original HAR body minimisation (new PRIVATE derivatives only):**
  when the bounded JSON parser recognises structurally nested original
  `request.postData.text` or `response.content.text` within an HAR entry,
  the **entire body string** is withheld regardless of declared MIME type,
  field names or base64 encoding. Response and request metadata remain
  available for human review; the original owner-held source is unchanged.
  Chrome-style `_webSocketMessages[].data` and `payload` frame strings
  are likewise withheld, while frame timing/type metadata is retained.
  Local original-note placeholders are
  `[REDACTED_HAR_REQUEST_BODY]`,
  `[REDACTED_HAR_RESPONSE_BODY]` and
  `[REDACTED_HAR_WEBSOCKET_FRAME]`. They are **not findings, privacy
  clearance or evidence that every original byte was masked**. Malformed
  JSON, duplicate keys, over-limit fragments, irregular exporter fields,
  HAR URLs/query values and unknown fields still require source-bound
  HUMAN privacy review. Already-created packages remain immutable.
- **HAR cookies with application-specific names:** a well-formed bounded
  original HAR entry's \`request.cookies[]\` and \`response.cookies[]\`
  now withhold **every string cookie value**, including names that do not
  resemble a known token. This prevents a derived PRIVATE workroom from
  echoing arbitrary opaque session cookies. Literal cookie names and
  surrounding original metadata remain for HUMAN inspection; the source
  itself is unchanged. \`[REDACTED_HAR_COOKIE_VALUE]\` is a local
  navigation marker, not proof of complete privacy or permission to send.
- **HAR request URL, redirect, header and upload-path minimisation:**
  new PRIVATE derivatives now withhold the entire original bounded HAR
  \`request.url\` string (including path/query/fragment), the
  \`response.redirectURL\` string and **all** string header values in
  \`request.headers[]\` and \`response.headers[]\`, even under unknown
  header names. Original names, array order and non-sensitive structural
  metadata remain available to the HUMAN reviewer. Original
  \`request.postData.params[].fileName\` paths are also withheld.
  Local cues distinguish request URL, redirect URL, generic header value
  and file-reference occurrences. This protects against opaque custom
  authentication headers and path-embedded personal identifiers but
  does NOT classify the original HAR as shareable. Nonstandard/malformed
  exports, alternate field names, source filenames and other identifiers
  are still HUMAN/HOLD; there is no network call or scan.
- **HAR request parameter minimisation:** structural original
  \`request.queryString[]\` and \`request.postData.params[]\` name/value
  string entries now withhold every literal value, even when the original
  field name is not in the known credential list. User searches, personal
  identifiers and arbitrary application-specific form fields can contain
  private data. Markers \`[REDACTED_HAR_QUERY_VALUE]\` and
  \`[REDACTED_HAR_FORM_PARAM_VALUE]\` preserve only original parameter
  names and other local HUMAN metadata. The original source is unchanged.
  Structural parser limits, malformed exports and unknown other locations
  still require actual HUMAN privacy review; no sharing certification.
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
- **Percent-encoded URL parameter names:** original copied URL
  query/fragment names such as \`api%5Fkey\`, \`access%5Ftoken\` and
  percent-escaped variants of known session/secret field names now
  receive bounded UTF-8 name-decoding before the local credential value
  is withheld as \`[REDACTED_URL_VALUE]\`. The original parameter-name
  spelling and non-secret URL context are retained for PRIVATE HUMAN
  review. Limits: 96 URL candidates / 8192 characters each; malformed
  percent-escapes, deeply nested encodings, JavaScript-generated URLs,
  unrecognized names and non-URL text are not certified safe. This
  uses no HTTP request, browser, DNS or execution.
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

## PRIVATE HUMAN notes and Unicode spreadsheet safety

When a HUMAN original assessment reviewer enters free notes or follow-up
questions, the **native** acceptance boundary now rejects formula-leading
Unicode compatibility forms, initial invisible/combining marks and
bidirectional control characters, in addition to ordinary spreadsheet
prefixes. The local browser editor mirrors that guard for immediate
feedback; native finalization remains separate and authoritative. No
unsafe original historical input is rewritten or silently accepted on
reopening. This is a CSV-format precaution only, never masking completeness,
safe disclosure, authenticated source identity or review approval.

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

## NEW: navigable original-ordinal masking-cue desk (v12)

The native `notes.py masking-cues` and optional
`notes.py prepare --with-mask-cues` now render a fully offline
**script-free HUMAN navigator**, preserving the complete original ordinal
roster and providing expandable category-focused links that jump to source
positions with literal known masking markers. Links are ordered by literal
placeholder appearance count **only**, never security severity. These
groups show no original text, customer names, source digests, freeform
HUMAN notes, credentials or authority claims. Zero counts are *not* clearance.

New independent native cue receipts use
`lightup.private_assessment_masking_cues.v12`, including new
opaque original HAR request/response body, WebSocket message, cookie,
queryString, form-parameter, URL/redirect, arbitrary header and file-reference
markers in their literal-count families. The original v11 query/form,
v10 cookie, v9 body/frame, v8 HAR form/JSON/multipart and v1-v7 families
remain exactly reopenable under their historical marker algorithms,
without silent upgrade.
The original source-bound 0700/0600 custody is unchanged. The read-only
`notes.py masking-cues-reopen` accepts **v1 through v11** historical
receipts and their original HTML/CSV bytes; existing historical packets
are never rewritten, auto-upgraded or silently normalized. In particular,
new cue navigation does not change the canonical original source manifest,
the original HUMAN editor/finalizer, or older completed review packets.

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

The current PRIVATE cue receipt is source-bound **v4**. Quoted cURL
form/data markers appear under **HTTP/shell**. Known HAR
cookie, query and form credential placeholders appear in the
**Structured config** category; prior HAR HTTP-header placeholders remain
under **HTTP/shell**. Cue counts are literal placeholder occurrences,
not claims that a value was safely removed. Previously issued **v1, v2 and v3 receipts remain exactly reopenable
without reinterpretation**; the
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
