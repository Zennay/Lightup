"""Bounded defence-in-depth masking for original owner-private assessment notes.

IMPORTANT: heuristic patterns, never PII anonymization, security PASS or
permission to share. This extends, never weakens, the original core redactor.
"""
from __future__ import annotations

import re

from lightup.redaction import redact_text

# Entire credential-bearing HTTP header values are withheld. In particular,
# Cookie may contain several sensitive fields with punctuation and spaces.
_HEADER = re.compile(
    r"(?im)^([ \t]*(?:proxy-authorization|authorization|x-api-key|"
    r"x-auth-token|x-access-token|cookie|set-cookie)[ \t]*:[ \t]*)[^\r\n]*"
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
    r"""(?i)(?P<prefix>(?<![A-Za-z0-9_-])(?:-H|--(?:proxy-)?header)
    (?:[ \t]+|=))(?P<quote>["'])(?P<header>
    (?:proxy-authorization|authorization|x-api-key|x-auth-token|
    x-access-token|cookie|set-cookie)[ \t]*:[ \t]*)
    (?:\\.|(?! (?P=quote) ).)*?(?P=quote)""",
    re.VERBOSE,
)
# Credential-bearing command switches are not HTTP headers:
# curl -u user:pass, curl --proxy-user='u:p', --api-key=secret.
# No untrusted command is ever executed; mask text only.
_SHELL_CREDENTIAL = re.compile(
    r"""(?i)(?<![A-Za-z0-9_-])
    (?P<prefix>--(?:proxy-user|user|password|passwd|api-key|
    access-token|refresh-token|client-secret|auth-token)
    (?:[ \t]+|=)|-u[ \t]+)
    (?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s\r\n]+)""",
    re.VERBOSE,
)
# Raw HTTP exchange excerpts may start with a direction marker:
# > Cookie: session=... / < Set-Cookie: session=...
_RAW_HTTP_HEADER = re.compile(
    r"(?im)^([ \t]*[><*][ \t]+(?:proxy-authorization|authorization|"
    r"x-api-key|x-auth-token|x-access-token|cookie|set-cookie)[ \t]*:[ \t]*)[^\r\n]*"
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
    password|passwd|api[_-]?key|client[_-]?secret|private[_-]?key|
    access[_-]?token|refresh[_-]?token|auth[_-]?token|
    session[_-]?id|session[_-]?token|jwt)[ \t]*:[ \t]*)
    (?:"[^"\r\n]*"|'[^'\r\n]*'|[^\r\n#]+)""",
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
    value = redact_text(original)
    value = _PRIVATE_KEY.sub("[REDACTED_PRIVATE_KEY_BLOCK]", value)
    value = _HEADER.sub(r"\1[REDACTED_HEADER_VALUE]", value)
    value = _RAW_HTTP_HEADER.sub(r"\1[REDACTED_HTTP_VALUE]", value)
    value = _SHELL_HEADER.sub(
        lambda m: m.group("prefix") + m.group("quote") + m.group("header")
        + "[REDACTED_HTTP_VALUE]" + m.group("quote"), value)
    value = _SHELL_CREDENTIAL.sub(
        lambda m: m.group("prefix") + "[REDACTED_COMMAND_CREDENTIAL]", value)
    value = _URL_USERINFO.sub(r"\1[REDACTED_USERINFO]@", value)
    value = _URL_PARAMETER.sub(r"\1[REDACTED_URL_VALUE]", value)
    value = _PATH_SESSION.sub(r"\1[REDACTED_SESSION_VALUE]", value)
    value = _JSON_SECRET.sub(lambda m: m.group(1) + m.group(2)
                             + "[REDACTED_JSON_VALUE]" + m.group(2), value)
    value = _ENV_SECRET.sub(r"\1[REDACTED_ENV_VALUE]", value)
    value = _YAML_CREDENTIAL.sub(r"\1[REDACTED_CONFIG_VALUE]", value)
    value = _JWT.sub("[REDACTED_JWT_SHAPE]", value)
    value = _PROVIDER.sub("[REDACTED_PROVIDER_TOKEN_SHAPE]", value)
    return value
