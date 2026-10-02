"""Explicit HTTP trust boundary; forwarding headers never choose the origin."""
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlsplit
import re


def origin(value: str) -> tuple[str, str, int]:
    if not isinstance(value, str) or re.search(r"[\s\\,]", value):
        raise ValueError("invalid origin")
    parts = urlsplit(value)
    if (parts.scheme not in {"http", "https"} or not parts.hostname
            or parts.username is not None or parts.password is not None
            or parts.path or parts.query or parts.fragment
            or parts.netloc.endswith(":")):
        raise ValueError("expected an http(s) origin without a path")
    port = parts.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("invalid port")
    return parts.scheme, parts.hostname.lower(), port or (443 if parts.scheme == "https" else 80)


class RequestRejected(ValueError):
    pass


@dataclass(frozen=True)
class WebSecurity:
    public_origin: str | None = None
    trusted_proxy_ip: str = "127.0.0.1"

    def __post_init__(self):
        if self.public_origin is not None:
            if origin(self.public_origin)[0] != "https":
                raise ValueError("production public origin must use HTTPS")
            if not ip_address(self.trusted_proxy_ip).is_loopback:
                raise ValueError("the deployment proxy must be on loopback")

    @property
    def production(self) -> bool:
        return self.public_origin is not None

    def validate(self, environ) -> None:
        try:
            self._validate(environ)
        except (ValueError, TypeError):
            raise RequestRejected("request origin or transport rejected") from None

    def _validate(self, environ) -> None:
        if self.production:
            # Verify the socket peer, never X-Forwarded-For.
            if environ.get("REMOTE_ADDR") != self.trusted_proxy_ip:
                raise ValueError("untrusted proxy")
            if environ.get("HTTP_X_FORWARDED_PROTO") != "https":
                raise ValueError("HTTPS required")
            expected = origin(self.public_origin)
            actual = origin("https://" + environ.get("HTTP_HOST", ""))
            if actual != expected:
                raise ValueError("host mismatch")
        else:
            # Missing Host is accepted only for direct in-process WSGI use.
            host = environ.get("HTTP_HOST") or environ.get("SERVER_NAME", "localhost")
            actual = origin("http://" + host)
            if actual[1] not in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError("development host must be loopback")
            expected = actual

        if environ.get("REQUEST_METHOD", "GET").upper() == "POST":
            if environ.get("HTTP_SEC_FETCH_SITE") == "cross-site":
                raise ValueError("cross-site submission")
            supplied = environ.get("HTTP_ORIGIN")
            if supplied is not None:
                if origin(supplied) != expected:
                    raise ValueError("cross-origin submission")
            elif self.production:
                # Browsers that omit Origin may send an exact same-origin Referer.
                referer = environ.get("HTTP_REFERER", "")
                if re.search(r"[\s\\,]", referer):
                    raise ValueError("invalid referer")
                parsed = urlsplit(referer)
                if origin(parsed.scheme + "://" + parsed.netloc) != expected:
                    raise ValueError("origin evidence required")
