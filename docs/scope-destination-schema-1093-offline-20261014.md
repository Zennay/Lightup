# Offline destination-role schema shape review · #1093

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This additive, opt-in
reviewer evaluates **self-asserted, untrusted tool-definition JSON**. It cannot
authenticate a registry, issue a permit, grant scope, dispatch a handler, scan,
or approve a merge/deploy/release. Every exit is nonzero (2 HOLD, 3 REVIEW_ONLY).

Use only with disposable synthetic metadata on a private FIFO/pipe stdin.
A regular file, device, socket, incomplete pipe without EOF, or a pipe whose
writer keeps its end open fails atomically to HOLD after at most two seconds.
All reads use bounded 1024-byte chunks and an absolute monotonic deadline.
Fd0 is temporarily nonblocking, so another FIFO reader draining bytes between
`select` and `read` cannot create an unbounded stall; `EAGAIN` retries are
limited by the same absolute deadline. The inherited fd0 blocking mode is
restored on all paths, including HOLD and successful EOF. As with fd1, this
changes a shared POSIX open-file-description *transiently*, so always use a
private input pipe if simultaneous writers/readers need strict isolation.
This is a Python userland guard, not an OS sandbox. Stdout receipts are
independently sealed to an exact 10-field, all-denial ASCII JSON shape (seven
literal false flags), capped at 512 bytes. Only private FIFO/pipe and real TTY
stdout sinks are accepted; inherited regular files, sockets, devices and
full/unconsumed pipes return nonzero without writing private claims. Output
has its own absolute two-second deadline and restores the original fd1
blocking mode on success or failure. A shared POSIX open-file-description
can be transiently nonblocking during the write: use a private output pipe
when another process could write the same descriptor.

Feed a finite packet via a pipe, not shell `< synthetic.json` redirection.
The latter passes a **regular file fd0** and intentionally yields HOLD:

    cat synthetic.json | python scripts/review_scope_destination_schema_1093_offline.py --stdin-json
    python -m unittest discover -s tests -p 'test_scope_destination_schema_1093_offline.py' -v

Input must be UTF-8 JSON, maximum 4096 bytes, precisely a `tools` array of
1–8 tool objects, with unique lowercase ASCII `tool_id` (hyphens allowed, matching the actual lab tool IDs) and 1–16
`parameters`. Each parameter is exactly `name`, `kind`, `role`, `required`, with
unique lowercase ASCII parameter name (underscore allowed; hyphen rejected). The current real `ParamKind` vocabulary is exactly `string`, `integer`, `number`, `boolean`; extra kinds such as `array` and `object` are rejected. Valid roles: `host`, `endpoint`, `port`,
`port_set`, `none`; string destination roles accept only `string` kind,
`port` accepts only `integer`. The non-destination `none` role is allowed
for metadata such as timeout but each tool must claim at least one destination.
Duplicate JSON keys, Unicode lookalikes, subclasses in direct API calls,
nonfinite numbers and malformed/oversized payloads are HOLD. This includes
**dictionary field names** supplied through the direct Python API: a custom
str subclass that happens to compare equal to `tools`, `tool_id`,
`parameters`, `name`, `kind`, `role`, `required` or an output receipt key
must not become a trusted-looking canonical field. Field key identities are
checked before membership/set hashing, so hostile str subclasses do not get
rehashed or compared as a side effect of validation. Ordinary Python/JSON
parser-created built-in strings remain valid. This is *Python API input
hygiene*, not proof against arbitrary in-process code or an OS sandbox.
Any invalid member HOLDs the entire packet.

A well-formed tool also needs a **single unambiguous destination shape**:
either exactly one ENDPOINT field, or exactly one HOST field with at most
one of PORT **or** PORT_SET. HOST alone is valid. Non-destination metadata
with role NONE may accompany any valid shape but can never establish one.
All parameters must declare `required` with an **exact JSON boolean**
(not 0/1, string, missing, nullable or a Python bool subclass). Each
destination-bearing HOST/ENDPOINT/PORT/PORT_SET parameter must be **required:
true**; only NONE metadata may be optional (`required: false`).
This follows the installed `ToolParameter.required` field: if the destination
can disappear from an actual call, its structural declaration is incomplete.
The test imports the three actual LAB_ACTIVE ToolDefinitions and compares
tool IDs, parameter names, kind **and requiredness**. Claims still originate
from an untrusted caller, so a forged `required: true` is never an
authorization or proof of actual runtime arguments.

PORT/PORT_SET without HOST, repeated destination roles on different argument
names, HOST+ENDPOINT, ENDPOINT+PORT, or PORT+PORT_SET are HOLD even if every
individual parameter has a valid name/kind pair. Mixed multi-tool packets
reject **atomically** with zero tool/parameter counts, regardless of whether
the invalid member appears first or last. The synthetic acceptance suite
also exhaustively enumerates all **780** sequences of 1–4 elements from the
five role values and compares status/counts to an independent fixed allowlist
of exactly four permitted destination shapes. This is broad **synthetic
structural** coverage only: it does not authenticate the claims or exercise
production network authorization. Shape consistency is explicitly not proof
that any caller supplied a genuinely trusted destination.


For example, these three *synthetic* tool shape declarations match currently
implemented LAB_ACTIVE argument forms but DO NOT prove they are the actual
registry definitions: `lab-http-baseline.url` → endpoint/string,
`lab-tls-baseline.host` + `port` → host/string + port/integer,
`lab-service-inventory.host` + `ports` → host/string + port_set/string.

Dedicated read-only source tests import the three **actual, currently
installed** LAB_ACTIVE ToolDefinition objects and compare the exact tool IDs,
parameter name/kind/required shapes and a separate, explicitly **test-owned**
known-role mapping against the synthetic fixtures. Future addition of trusted
source-owned roles is permitted; the reference never asserts their absence.

Additional opt-in integration acceptance invokes the three **real** current
HTTP/TLS/service-inventory handler functions in a disposable lab context,
while patching their producer calls and raw socket/HTTP entry points to
explicitly fail if reached. It checks that the exact destination arguments
are passed to the *mocked* producer and reflected in synthetic evidence,
and separately that a synthetic non-lab context is rejected **before** any
producer invocation. All destinations in these fixtures are 127.0.0.1,
and **no DNS request, HTTP connection, TLS handshake, socket or scan occurs**.
These tests intentionally bypass the actual registry/executor to inspect
handler-local contracts, so they are NOT evidence that production dispatch,
live grants, resolver binding or network egress fencing is safe.

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
