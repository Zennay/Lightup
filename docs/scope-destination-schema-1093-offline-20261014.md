# Offline destination-role schema shape review · #1093

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This additive, opt-in
reviewer evaluates **self-asserted, untrusted tool-definition JSON**. It cannot
authenticate a registry, issue a permit, grant scope, dispatch a handler, scan,
or approve a merge/deploy/release. Every exit is nonzero (2 HOLD, 3 REVIEW_ONLY).

Use only with disposable synthetic metadata and a closed stdin pipe:

    python scripts/review_scope_destination_schema_1093_offline.py --stdin-json < synthetic.json
    python -m unittest discover -s tests -p 'test_scope_destination_schema_1093_offline.py' -v

Input must be UTF-8 JSON, maximum 4096 bytes, precisely a `tools` array of
1–8 tool objects, with unique canonical ASCII `tool_id` and 1–16
`parameters`. Each parameter is exactly `name`, `kind`, `role`, with
unique canonical ASCII name. Valid roles: `host`, `endpoint`, `port`,
`port_set`, `none`; string destination roles accept only `string` kind,
`port` accepts only `integer`. The non-destination `none` role is allowed
for metadata such as timeout but each tool must claim at least one destination.
Duplicate JSON keys, Unicode lookalikes, subclasses in direct API calls,
nonfinite numbers and malformed/oversized payloads are HOLD. Any invalid member
HOLDs the entire packet.

For example, these three *synthetic* tool shape declarations match currently
documented LAB_ACTIVE argument forms but DO NOT prove they are the actual
registry definitions: `http_baseline.url` → endpoint/string,
`tls_baseline.host` + `port` → host/string + port/integer,
`service_inventory.host` + `ports` → host/string + port_set/string.

The reviewer deliberately has **no installed registry/production imports**.
Therefore an attacker can supply a self-consistent invented tool ID and still
receive REVIEW_ONLY. The privacy-minimal receipt contains only status, counts,
and seven literal-false authority/dispatch/release flags. It never echoes tool
names, targets, credentials or raw JSON.

**Remaining production owner gates:** #107 must bind trustworthy immutable
`ToolRegistry` / `ToolDefinition` role metadata, apply exact role+kind checks,
and enforce #1092 destination vs separately authorized asset **before** handler
and on every retry/queue; #966 owns duplicate argument admission. The current
reviewer neither integrates with those paths nor changes their ownership.
Require independently verified exact-head hosted/VPS runner logs, operator and
customer consent, independent security review and an explicit human release
decision. Do not merge this draft or deploy it as authorization.
