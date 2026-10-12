"""Offline, non-authorizing Nginx example review for issue #1158.

This is a syntactic LAB acceptance oracle, NOT loaded Nginx proof.
Never opens sockets, executes a subprocess, or inspects installed configs.
"""
from __future__ import annotations

from pathlib import Path
import re
import unittest


PATH_HINT_HEADERS = (
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Original-URI",
    "X-Forwarded-URI",
    "X-Forwarded-Path",
    "X-Forwarded-Prefix",
    "X-Script-Name",
)
NGINX_TEMPLATE = Path(__file__).resolve().parents[1] / "deploy" / "nginx.conf.example"


class TemplateGateError(ValueError):
    """A static example cannot establish the expected deny-only hygiene."""


def review_nginx_path_hint_template(source: str) -> None:
    """Validate a deliberately narrow, complete literal example, not a live config.

    Whitelists only empty proxy_set_header declarations for known path-hint names.
    Fails closed on includes, rewrite directives and dynamic proxy upstreams, all
    of which require separate human/installed-ingress inspection.
    Returns None, never an authorization, launch or target decision.
    """
    if type(source) is not str:
        raise TemplateGateError("template must be an exact string")
    # This lab-only lexical reviewer intentionally does not resolve Nginx includes,
    # macros, maps, inheritance, nested locations or runtime directives.
    lines = [line.split("#", 1)[0].strip() for line in source.splitlines()]
    clean = "\n".join(lines)
    if not re.search(r"(?im)^location\s+/\s*\{\s*$", clean):
        raise TemplateGateError("missing literal root location")
    if re.search(r"(?im)^\s*(?:include|rewrite|try_files|error_page|map|if)\s", clean):
        raise TemplateGateError("complex routing requires installed review")
    if re.search(r"(?im)^\s*proxy_pass\s+[^;]*\$", clean):
        raise TemplateGateError("dynamic proxy destination requires installed review")

    directives = re.findall(
        r"(?im)^\s*proxy_set_header\s+([A-Za-z0-9-]+)\s+([^;]+);\s*$",
        clean,
    )
    seen = {}
    for header, value in directives:
        key = header.casefold()
        if key in {name.casefold() for name in PATH_HINT_HEADERS}:
            if key in seen:
                raise TemplateGateError("duplicate path-hint forwarding declaration")
            seen[key] = value.strip()
    required = {name.casefold() for name in PATH_HINT_HEADERS}
    if set(seen) != required:
        raise TemplateGateError("missing explicit path-hint removal")
    if any(value not in ('""', "''") for value in seen.values()):
        raise TemplateGateError("path-hint header must be removed, not forwarded")
    # Reject loose/unparsed declarations that could override empty settings.
    parsed_lines = {
        (h.casefold(), v.strip())
        for h, v in directives
        if h.casefold() in required
    }
    for line in lines:
        if re.match(r"(?i)^proxy_set_header\s+X-(?:Original|Rewrite|Forwarded|Script)-", line):
            match = re.fullmatch(
                r"(?i)proxy_set_header\s+([A-Za-z0-9-]+)\s+([^;]+);", line
            )
            if match is None or (match[1].casefold(), match[2].strip()) not in parsed_lines:
                raise TemplateGateError("unparsed path-hint directive")


def _clean_fixture() -> str:
    removals = "\n".join(
        f'        proxy_set_header {h} "";' for h in PATH_HINT_HEADERS
    )
    return (
        "server {\n    listen 443 ssl;\n    location / {\n"
        "        proxy_pass http://127.0.0.1:8766;\n"
        + removals + "\n    }\n}\n"
    )


class PathHintTemplateReferenceTest(unittest.TestCase):
    def test_explicit_empty_headers_pass_offline_syntax_only(self):
        self.assertIsNone(review_nginx_path_hint_template(_clean_fixture()))

    def test_each_missing_header_is_denied(self):
        for header in PATH_HINT_HEADERS:
            with self.subTest(header=header):
                modified = _clean_fixture().replace(
                    f'proxy_set_header {header} "";', ""
                )
                with self.assertRaises(TemplateGateError):
                    review_nginx_path_hint_template(modified)

    def test_forwarding_caller_supplied_path_fails(self):
        for header in PATH_HINT_HEADERS:
            with self.subTest(header=header):
                modified = _clean_fixture().replace(
                    f'proxy_set_header {header} "";',
                    f'proxy_set_header {header} $http_x_original_url;',
                )
                with self.assertRaises(TemplateGateError):
                    review_nginx_path_hint_template(modified)

    def test_duplicate_removed_header_fails_closed(self):
        modified = _clean_fixture().replace(
            "    }", '        proxy_set_header X-Original-URL "";\n    }'
        )
        with self.assertRaises(TemplateGateError):
            review_nginx_path_hint_template(modified)

    def test_complex_routing_or_includes_need_human_gate(self):
        for directive in (
            "include /etc/nginx/conf.d/*.conf;",
            "rewrite ^/(.*)$ /clients last;",
            "try_files $uri /clients;",
            "proxy_pass http://$backend;",
        ):
            with self.subTest(directive=directive):
                modified = _clean_fixture().replace(
                    "    location / {", f"    {directive}\n    location / {{"
                )
                with self.assertRaises(TemplateGateError):
                    review_nginx_path_hint_template(modified)

    def test_no_root_location_fails(self):
        with self.assertRaises(TemplateGateError):
            review_nginx_path_hint_template(
                _clean_fixture().replace("location / {", "location /clients {")
            )

    def test_rejected_inputs_remain_unchanged(self):
        source = _clean_fixture().replace(
            'proxy_set_header X-Rewrite-URL "";',
            "proxy_set_header X-Rewrite-URL $http_x_rewrite_url;",
        )
        before = source
        with self.assertRaises(TemplateGateError):
            review_nginx_path_hint_template(source)
        self.assertEqual(source, before)

    @unittest.expectedFailure
    def test_existing_main_example_has_not_yet_stripped_path_hints(self):
        # Expected RED: #1158 cannot be closed by WSGI-only #1156.
        # Promotion requires source-owner config change and installed proof.
        review_nginx_path_hint_template(NGINX_TEMPLATE.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
