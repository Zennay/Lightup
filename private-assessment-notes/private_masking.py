"""Bounded defence-in-depth masking for original owner-private assessment notes.

IMPORTANT: heuristic patterns, never PII anonymization, security PASS or
permission to share. This extends, never weakens, the original core redactor.
"""
from __future__ import annotations

import re

from lightup.redaction import redact_text
from curl_payload_mask import FIELD_BOUNDARY_GUARD, mask_curl_form_payloads
from private_json_mask import mask_json_fields, _SECRET_FIELD
from private_query_mask import mask_url_query_names
from private_har_gate import HOLD_MARKER, hold_unadmitted_har

# Entire credential-bearing HTTP header values are withheld. In particular,
# Cookie may contain several sensitive fields with punctuation and spaces.
_HEADER = re.compile(
    r"(?im)^([ \t]*(?:proxy-authorization|authorization|x-api-key|"
    r"x-auth-token|x-access-token|x-amz-security-token|x-goog-api-key|"
    r"x-csrf-token|x-xsrf-token|cookie|set-cookie)[ \t]*:[ \t]*)[^\r\n]*"
)
# Preserve only scheme, not the credentials or user identity embedded in it.
_URL_USERINFO = re.compile(
    r"(?i)\b((?:https?|ftps?|sftp|postgres(?:ql)?|mysql|redis|rediss|"
    r"mongodb(?:\+srv)?|amqps?|wss?|ldaps?|ssh|smtps?)://)[^/\s?#@]+@"
)
# Human notes routinely paste cURL examples, HAR command extracts and
# request headers into a shell line. A beginning-of-line-only header masker
# misses these. Hide the *whole quoted sensitive header value*, not a guessed
# token within it (Cookie can contain multiple semicolon-delimited fields).
# This handles both -H and --header and preserves the quote used by the shell.
_SHELL_HEADER = re.compile(
    r"""(?i)(?P<prefix>(?<![A-Za-z0-9_-])(?:-H(?:[ \t]+|=)?|--(?:proxy-)?header(?:[ \t]+|=)))(?P<quote>["'])(?P<header>
    (?:proxy-authorization|authorization|x-api-key|x-auth-token|
    x-access-token|x-amz-security-token|x-goog-api-key|
    x-csrf-token|x-xsrf-token|cookie|set-cookie)[ \t]*:[ \t]*)
    (?:\\.|(?! (?P=quote) ).)*?(?P=quote)""",
    re.VERBOSE,
)
# Header lines sometimes appear as quoted *values* in copied Python/JS
# arrays and sample configuration, not as command --header arguments or
# beginning-of-line HTTP text. Withhold a known sensitive header's entire
# quoted value; this is still heuristic and only for PRIVATE/HOLD output.
_QUOTED_HTTP_HEADER = re.compile(
    r"""(?ix)(?P<quote>["'])
    (?P<header>(?:proxy-authorization|authorization|x-api-key|
    x-auth-token|x-access-token|x-amz-security-token|x-goog-api-key|
    x-csrf-token|x-xsrf-token|cookie|set-cookie)[ \t]*:[ \t]*)
    (?:\\.|(?! (?P=quote) )[^\\\r\n]){0,4096}(?P=quote)""",
    re.VERBOSE,
)
# Credential-bearing command switches are not HTTP headers:
# curl -u user:pass, curl --proxy-user='u:p', --api-key=secret.
# No untrusted command is ever executed; mask text only.
_SHELL_CREDENTIAL = re.compile(
    r"""(?i)(?<![A-Za-z0-9_-])
    (?P<prefix>--(?:proxy-user|user|password|passwd|api-key|
    access-token|refresh-token|client-secret|auth-token|cookie|
    oauth2-bearer|proxy-password|tlsuser|tlspassword|key|cert)
    (?:[ \t]+|=)|-u[ \t]+|-b(?:[ \t]+|=)?)
    (?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s\r\n]+)""",
    re.VERBOSE,
)
# Pasted cURL form/data examples can carry secrets even when they do not
# use an HTTP header or a dedicated --password flag. Match known sensitive
# name=value parameters in quoted --data*, --form* and -d/-F arguments.
# Preserve the parameter name for local HUMAN review, not its raw value.
# Arbitrary encodings, unnamed fields and other shapes remain PRIVATE/HOLD.
_SHELL_FORM_SECRET = re.compile(
    r"""(?i)(?<![A-Za-z0-9_-])
    (?P<prefix>--(?:data(?:-raw|-binary|-urlencode)?|form(?:-string)?)
    (?:[ \t]+|=)|-[dF][ \t]+)
    (?P<quote>["'])
    (?P<key>(?:password|passwd|api[_-]?key|secret|client[_-]?secret|
    (?:access|refresh|auth|id)[_-]?token|session[_-]?(?:id|token)|
    csrf(?:[_-]?token)?|xsrf(?:[_-]?token)?|jwt|signature|sig))
    =(?:\\.|(?! (?P=quote) )[^\\\r\n]){0,4096}(?P=quote)""",
    re.VERBOSE,
)

# Raw HTTP exchange excerpts may start with a direction marker:
# > Cookie: session=... / < Set-Cookie: session=...
_RAW_HTTP_HEADER = re.compile(
    r"(?im)^([ \t]*[><*][ \t]+(?:proxy-authorization|authorization|"
    r"x-api-key|x-auth-token|x-access-token|x-amz-security-token|"
    r"x-goog-api-key|x-csrf-token|x-xsrf-token|cookie|set-cookie)[ \t]*:[ \t]*)[^\r\n]*"
)
# Servlet / app path parameters also commonly contain bearer session IDs.
_PATH_SESSION = re.compile(
    r"(?i)(;(?:jsessionid|phpsessid|sessionid)=)[^;/\s?#\"'<>]+"
)
# Remove URL query/fragment credential values including URL-encoded tokens.
_URL_PARAMETER = re.compile(
    r"(?i)([?&#](?:api[_-]?key|access[_-]?token|id[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|password|secret|"
    r"token|jwt|bearer|session[_-]?(?:id|token)|"
    r"authorization|auth[_-]?token|signature|sig|"
    r"x-amz-signature|x-amz-security-token)=)[^&#\s\"'<>]+"
)
# Quoted JSON-style values can contain punctuation/spaces. Original generic
# key=value masking does not identify all quoted JSON object members.
_JSON_SECRET = re.compile(
    r'''(?i)(["'](?:api[_-]?key|access[_-]?token|id[_-]?token|
    refresh[_-]?token|client[_-]?secret|password|passwd|secret|
    private[_-]?key|auth[_-]?token|authorization|proxy-authorization|
    cookie|set-cookie|x-api-key|x-auth-token|x-access-token|
    session[_-]?id|session[_-]?token|sessionId|accessToken|
    refreshToken|clientSecret|apiKey|authToken|privateKey|
    secretKey|bearerToken|jwt)["'][ \t]*:[ \t]*)(["'])(?:\\.|(?!\2)[^\r\n\\])*\2''',
    re.VERBOSE,
)
# Browser/HAR-style header objects often encode name and value as TWO
# fields rather than a literal HTTP header. Match only sensitive header
# names paired with an adjacent JSON-style value (quoted strings), and
# redact the complete value without parsing or executing unrelated input.
# Arbitrary HAR blobs/unknown fields still require independent HUMAN review.
_HAR_HEADER_VALUE = re.compile(
    r"""(?i)(?P<prefix>["']name["'][ \t]*:[ \t]*
    (?P<name_quote>["'])(?:proxy-authorization|authorization|
    x-api-key|x-auth-token|x-access-token|x-amz-security-token|
    x-goog-api-key|x-csrf-token|x-xsrf-token|cookie|set-cookie)(?P=name_quote)
    [ \t\r\n]*,[ \t\r\n]*["']value["'][ \t]*:[ \t]*)
    (?P<value_quote>["'])(?:\\.|(?! (?P=value_quote) )[^\\\r\n]){0,4096}
    (?P=value_quote)""",
    re.VERBOSE,
)
# HAR/JSON objects do not require key order. Also handle the common
# inverse serialization where the sensitive value precedes name.
_HAR_HEADER_REVERSE = re.compile(
    r"""(?i)(?P<prefix>["']value["'][ \t]*:[ \t]*)
    (?P<value_quote>["'])(?:\\.|(?! (?P=value_quote) )[^\\\r\n]){0,4096}
    (?P=value_quote)(?P<suffix>[ \t\r\n]*,[ \t\r\n]*
    ["']name["'][ \t]*:[ \t]*(?P<name_quote>["'])
    (?:proxy-authorization|authorization|x-api-key|x-auth-token|
    x-access-token|x-amz-security-token|x-goog-api-key|
    x-csrf-token|x-xsrf-token|cookie|set-cookie)(?P=name_quote))""",
    re.VERBOSE,
)
# HAR cookies, queryString and form postData.params commonly serialize a
# sensitive field as adjacent "name"/"value" members instead of "token":
# "secret". Unlike the named HTTP-header cases above, the *field name* is
# variable. Admit only known credential-like names, without inspecting or
# exporting actual values. Unknown field names still require HUMAN review.
# Values are conservatively capped per field to avoid unbounded regex scans;
# longer/multiline/irregular encodings may remain. Never a privacy PASS.
_HAR_PARAM_VALUE = re.compile(
    r"""(?i)(?P<prefix>["']name["'][ \t]*:[ \t]*
    (?P<name_quote>["'])(?:session(?:id|[_-]?(?:id|key|token))?|
    (?:x-)?(?:csrf|xsrf)(?:[_-]?token)?|(?:auth|access|refresh|id)[_-]?token|
    jwt|bearer|api[_-]?key|client[_-]?secret|password|passwd|
    secret|signature|sig|sid|phpsessid|jsessionid|
    aws[_-]?secret[_-]?access[_-]?key|x-amz-security-token)
    (?P=name_quote)[ \t\r\n]*,[ \t\r\n]*
    ["']value["'][ \t]*:[ \t]*)
    (?P<value_quote>["'])(?:\\.|(?! (?P=value_quote) )[^\\\r\n]){0,4096}
    (?P=value_quote)""",
    re.VERBOSE,
)
_HAR_PARAM_REVERSE = re.compile(
    r"""(?i)(?P<prefix>["']value["'][ \t]*:[ \t]*)
    (?P<value_quote>["'])(?:\\.|(?! (?P=value_quote) )[^\\\r\n]){0,4096}
    (?P=value_quote)
    (?P<suffix>[ \t\r\n]*,[ \t\r\n]*["']name["'][ \t]*:[ \t]*
    (?P<name_quote>["'])(?:session(?:id|[_-]?(?:id|key|token))?|
    (?:x-)?(?:csrf|xsrf)(?:[_-]?token)?|(?:auth|access|refresh|id)[_-]?token|
    jwt|bearer|api[_-]?key|client[_-]?secret|password|passwd|
    secret|signature|sig|sid|phpsessid|jsessionid|
    aws[_-]?secret[_-]?access[_-]?key|x-amz-security-token)
    (?P=name_quote))""",
    re.VERBOSE,
)

# E.g. DB_PASSWORD="long password" and INTERNAL_API_TOKEN=abc (not merely a
# word-boundary 'token' or 'password' in the original producer regex).
_ENV_SECRET = re.compile(
    r'''(?im)\b((?:[A-Z][A-Z0-9_]*_)?(?:PASSWORD|PASSWD|SECRET|
    PRIVATE_KEY|ACCESS_TOKEN|REFRESH_TOKEN|AUTH_TOKEN|API_KEY|
    CLIENT_SECRET|SESSION_ID|SESSION_TOKEN|BEARER_TOKEN|JWT|
    AWS_SECRET_ACCESS_KEY|COOKIE)
    [ \t]*=[ \t]*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s#]+)''',
    re.VERBOSE,
)
# Plain YAML / config object scalars (not quoted JSON members). Hide
# the entire value, including embedded spaces, before any browser display.
_YAML_CREDENTIAL = re.compile(
    r"""(?im)^([ \t]*(?:authorization|proxy-authorization|cookie|
    set-cookie|x-api-key|x-auth-token|x-access-token|
    x-amz-security-token|x-goog-api-key|x-csrf-token|x-xsrf-token|
    password|passwd|api[_-]?key|client[_-]?secret|private[_-]?key|
    access[_-]?token|refresh[_-]?token|auth[_-]?token|
    session[_-]?id|session[_-]?token|jwt)[ \t]*:[ \t]*)
    (?:"[^"\r\n]*"|'[^'\r\n]*'|[^\r\n#]+)""",
    re.VERBOSE,
)
# Copied SOAP/XML manifests and configuration snippets can carry credentials
# as element text or quoted attributes. Keep the element/attribute identity,
# withhold only bounded text values. Mixed-content XML remains HUMAN/HOLD.
_XML_NAME = (r"password|passwd|secret|api[_-]?key|apiKey|client[_-]?secret|"
             r"clientSecret|access[_-]?token|accessToken|refresh[_-]?token|"
             r"refreshToken|auth[_-]?token|authToken|session[_-]?id|sessionId|"
             r"private[_-]?key|privateKey|bearerToken|jwt")
_XML_ELEMENT = re.compile(
    r"(?is)(?P<open><(?P<key>" + _XML_NAME + r")\b(?:[ \t]+[^<>]{0,256})?[ \t]*>)"
    r"(?P<content>[^<>]{0,4096})(?P<close></(?P=key)[ \t]*>)"
)
_XML_ATTRIBUTE = re.compile(
    r"(?i)(?P<prefix>\b(?:" + _XML_NAME + r")[ \t]*=[ \t]*)"
    r"(?P<quote>[\"'])(?:\\.|(?! (?P=quote) )[^\\\r\n]){0,4096}(?P=quote)",
    re.VERBOSE,
)

_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----", re.I
)
# Common unlabelled bearer-shaped token, not intended as a complete
# secret/PII classifier. Require three JWT segments.
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\."
    r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])"
)
_PROVIDER = re.compile(
    r"(?<![A-Za-z0-9_])(?:ghp_[A-Za-z0-9]{24,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|"
    r"sk-(?:proj-)?[A-Za-z0-9_-]{24,})(?![A-Za-z0-9_-])"
)


def mask_private_notes(original: str) -> str:
    """Mask known credential *shapes* on an owner-private local text copy.

    No original source mutation, network, classification or approval. Masking
    remains incomplete; outputs are always PRIVATE/HOLD regardless of count.
    """
    # Mask individual named fields before the generic producer mutates their
    # syntactic delimiters. This is only local defence-in-depth, never PASS.
    # JSON-aware masking first identifies separate HAR name/value fields even
    # when harmless metadata appears between them. The original canonical
    # redact_text producer still runs; no authorization boundary is changed.
    original = hold_unadmitted_har(original)
    if original == HOLD_MARKER:
        # Do not pass withheld originals to any heuristic scanner. No
        # partial snippet or private URL may appear in the derived room.
        return HOLD_MARKER
    value = redact_text(mask_curl_form_payloads(mask_json_fields(
        mask_url_query_names(original, _SECRET_FIELD))))
    value = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY_BLOCK]", value)
    value = _HEADER.sub(r"\1[REDACTED_HEADER_VALUE]", value)
    value = _RAW_HTTP_HEADER.sub(r"\1[REDACTED_HTTP_VALUE]", value)
    value = _SHELL_HEADER.sub(
        lambda m: m.group("prefix") + m.group("quote") + m.group("header")
        + "[REDACTED_HTTP_VALUE]" + m.group("quote"), value)
    value = _QUOTED_HTTP_HEADER.sub(
        lambda m: m.group("quote") + m.group("header")
        + "[REDACTED_HTTP_VALUE]" + m.group("quote"), value)
    value = _SHELL_CREDENTIAL.sub(
        lambda m: m.group("prefix") + "[REDACTED_COMMAND_CREDENTIAL]", value)
    value = _SHELL_FORM_SECRET.sub(
        lambda m: m.group("prefix") + m.group("quote") + m.group("key")
        + "=[REDACTED_FORM_VALUE]" + m.group("quote"), value)
    value = _URL_USERINFO.sub(r"\1[REDACTED_USERINFO]@", value)
    value = _URL_PARAMETER.sub(r"\1[REDACTED_URL_VALUE]", value)
    value = _PATH_SESSION.sub(r"\1[REDACTED_SESSION_VALUE]", value)
    value = _JSON_SECRET.sub(lambda m: m.group(1) + m.group(2)
                             + "[REDACTED_JSON_VALUE]" + m.group(2), value)
    value = _HAR_HEADER_VALUE.sub(
        lambda m: m.group("prefix") + m.group("value_quote")
        + "[REDACTED_HAR_HEADER_VALUE]" + m.group("value_quote"), value)
    value = _HAR_HEADER_REVERSE.sub(
        lambda m: m.group("prefix") + m.group("value_quote")
        + "[REDACTED_HAR_HEADER_VALUE]" + m.group("value_quote")
        + m.group("suffix"), value)
    value = _HAR_PARAM_VALUE.sub(
        lambda m: m.group("prefix") + m.group("value_quote")
        + "[REDACTED_HAR_PARAM_VALUE]" + m.group("value_quote"), value)
    value = _HAR_PARAM_REVERSE.sub(
        lambda m: m.group("prefix") + m.group("value_quote")
        + "[REDACTED_HAR_PARAM_VALUE]" + m.group("value_quote")
        + m.group("suffix"), value)
    value = _XML_ELEMENT.sub(
        lambda m: m.group("open") + "[REDACTED_XML_VALUE]" + m.group("close"),
        value)
    value = _XML_ATTRIBUTE.sub(
        lambda m: m.group("prefix") + m.group("quote")
        + "[REDACTED_XML_VALUE]" + m.group("quote"), value)
    value = _ENV_SECRET.sub(r"\1[REDACTED_ENV_VALUE]", value)
    value = _YAML_CREDENTIAL.sub(r"\1[REDACTED_CONFIG_VALUE]", value)
    value = _JWT.sub("[REDACTED_JWT_SHAPE]", value)
    value = _PROVIDER.sub("[REDACTED_PROVIDER_TOKEN_SHAPE]", value)
    # Restore the actual original field-name syntax after BOTH masking layers;
    # no protected marker or original credential value may leave this method.
    return value.replace(FIELD_BOUNDARY_GUARD, "")
