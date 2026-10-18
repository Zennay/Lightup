# ScopePolicy literal scope admission — DRAFT/HOLD

LightUp remains INCUBATE M3/M7 / PLAN-LAB ONLY. This is a **production-source security narrowing** candidate, not permission to activate a target, issue a grant, merge or deploy.

## Implemented product behavior

Original ScopePolicy treated Python `ipaddress.is_private` as implicitly lab-authorized, including certain reserved/special-use address space not actually designated as a private lab. The revised policy permits implicit lab decisions only for loopback or the **explicit standard private/link-local** IPv4/IPv6 networks: 10/8, 172.16/12, 192.168/16, 169.254/16, fc00::/7 and fe80::/10. Explicit network authorization remains separately available subject to the existing public authorization requirement; this patch does NOT authorize new public target identities.

Policy configuration now validates exact boolean switches and all network text before any target branch can be evaluated. Caller-owned built-in sets/lists are copied into immutable host/network collections at construction. Non-string network entries, malformed CIDR values, decorated explicit host identities, multiple DNS root dots and configuration polymorphism cannot silently alter scope membership.

Target host parsing now rejects percentage-encoded host aliases and IPv6 zone/interface suffixes, decorated double-root-dot aliases and the previously truncated bare IPv6 interpretation. Canonical bracketed IPv6 targets, valid one-terminal-root-dot DNS names and literal loopback/private lab targets retain their intentionally bounded semantics. This is purely in-memory syntax: no DNS, sockets or network calls.

## Integration constraints

Own new branch changes only `src/lightup/scope.py` and this document. Original source-owning draft PRs #165/#1290 and independent acceptance branches remain untouched. No QA, regressions or testsuites written or run. AST source syntax inspection is not security signoff. Evaluable source guards are **not** durable client approval, authenticated client/operator consent, action-time revocation, tenant-safe binding, scan authority or release. Existing original exact-head hosted and permanently registered named VPS CI, original #177/#673/#829 source owners, independent security/privacy and explicit HUMAN GO are mandatory before owner-reviewed integration. The PR must remain DRAFT/HOLD.
