# LightUp scope W65 — self-asserted proof claims stay HOLD (#1429)

**Posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This isolated, opt-in, uninstalled script is *not* a security gate, release decision, evidence verifier, or production authority. It only examines JSON *submitted by an untrusted party* for internal consistency, then returns **HOLD**. It neither trusts nor validates the truth of any `pass` status.

## Ownership / separation

New paths only: `scripts/scope_self_asserted_proof_hold_1429.py`, `tests/test_scope_self_asserted_proof_hold_1429.py`, this note. No changes to original `ScopePolicy`, grants, executor, existing workers' draft PRs, installed proxy, CI workflow, self-hosted VPS, customer data or deployments. PR #1310 owns *independent GitHub-hosted/VPS metadata verification*. PRs #1425–#1428 own separate lab address and ingress preview work. None of those proofs is replaced here.

## Synthetic input

Exactly one `--stdin-json` argument and up to 16 KiB of UTF-8 JSON bytes. Empty/oversized input, malformed UTF-8, duplicate keys at any nesting depth, JSON NaN/Infinity, unknown fields, mixed commit heads, non-lowercase/non-40-hex SHAs, missing/duplicate/unknown lanes or type confusion **atomically reject**.

```json
{
  "schema": "lightup.scope.self_asserted_proof.v1",
  "head": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "claims": [
    {"lane": "hosted_python_311", "head": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "result": "pass"},
    {"lane": "hosted_python_314", "head": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "result": "pass"},
    {"lane": "registered_vps", "head": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "result": "queued"},
    {"lane": "installed_ingress", "head": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "result": "unknown"}
  ]
}
```

Allowed result strings: `pass`, `fail`, `queued`, `cancelled`, `unknown`. These are self-declarations, **not** verified workflow or ingress observations. No workflow URL or arbitrary credential is accepted. Every lane must share exactly the top-level immutable head. Output intentionally omits that SHA and all raw input, including names, targets, grants, tokens, and claims.

## W66 — finite one-shot stdin receipt (2026-10-14)

An untrusted producer can keep a pipe open after sending partial data, or even after sending one well-formed JSON object. The original buffered read could wait indefinitely for EOF, making this offline review a potential hung process. The opt-in CLI now uses a single POSIX inherited **stdin fd 0**, `select.select` + bounded `os.read` chunks with an absolute **2-second monotonic read deadline**, and reads at most **16 KiB + 1 byte**. On deadline expiry, incomplete stream, byte overflow, unsupported fd, or read error, it discards all collected bytes and emits only privacy-minimal `HOLD` with exit 2. The producer **must close stdin** for a coherent review; a complete JSON document without EOF is explicitly **not accepted**.

New genuine child-process regressions keep their write pipe intentionally **open** after (a) a secret-bearing fragment, (b) a complete apparently valid all-pass packet, and (c) an oversized secret-bearing packet. They require bounded termination, exactly false release/permit/dispatch and no secret echoes or traceback. A bad-argv unopened pipe must also return HOLD without reading stdin. A valid packet split across two writes **with EOF** remains structurally `COHERENT`, still never authorized. These prove CLI transport liveness and atomicity, **not** external evidence truth, OS-level isolation, production safety or a registered VPS runner.

Additional W66 acceptance enumerates **all 625 combinations** of the five allowed self-asserted status labels across four lanes: every combination remains exact HOLD with six false authorization flags. It also checks an exact 16KiB valid JSON envelope versus 16KiB+1, concatenated object smuggling, Unicode lookalike field names, escaped duplicate-key forms, nonfinite numeric representations and inherited non-stdin fd aliases. This is synthetic contract coverage; 625 fake inputs are not 625 real CI/ingress proofs.

This bounded-read implementation targets POSIX/Linux hosting. Failure of fd/select on an unsupported runtime is a conservative HOLD, not a fallback to an unbounded read. The script itself opens no other file, network connection or subprocess; normal Python interpreter module startup is not an OS sandbox.
## W67 — inherited stdin descriptor provenance (2026-10-14)

**Pipe/FIFO-only stdin** is enforced before calling `select` or `os.read`. Even fd 0 can originate from a socket, regular file, device, directory or another inherited source: accepting a valid JSON document from such a descriptor would violate the promise of a closed offline, non-networking review. The CLI checks **`os.fstat(0).st_mode`** and accepts only `stat.S_ISFIFO`. Non-pipe descriptors and metadata errors are **HOLD** without even attempting an input read. This policy deliberately rejects `< file.json` input or interactive terminal input; callers must feed exactly one finite pipe (`printf ... | python ... --stdin-json`) and close its writer. It also rejects a socket inherited as stdin even when the socket is locally connected.

New direct no-I/O canaries deny five synthetic fd kinds and assert neither `select` nor `os.read` is invoked. Independent genuine subprocess tests redirect fd 0 from a disposable regular file (asserting its position is unchanged) and an in-process AF_UNIX socketpair (asserting the peer bytes were left unread): both produce a privacy-minimal HOLD, exit 2, and no echo. The existing successful closed-pipe EOF cases remain valid. Only synthetic data is ever used; no network target, grant, credential, production configuration or deployment is contacted.

This is **descriptor-class preflight**, not an OS sandbox: a malicious parent could feed network-derived bytes through a pipe; `stdin` source contents and claimed `pass` labels remain untrusted and never authorize anything.

## W68 — sealed privacy-minimal receipt regression (2026-10-14)

The offline proof reviewer must produce one bounded ASCII JSON line with **exactly the 11 documented output keys**, never extra debugging fields, claim bodies, raw SHAs, targets or credentials. The new sealed-receipt contract checks full key equality, literal boolean flags, integer-only count, length <= **512 bytes**, exactly one newline, and rejection of injected confidential-looking fields on genuine child processes. Every outcome is `HOLD` and always returns exit 2. Existing 625 self-asserted four-lane combinations now additionally prove this entire output schema with each synthetic input, not only a few individual flags.

This makes privacy regressions visible in tests even if a future code refactor accidentally appends a raw input field. It does **not** prove an authenticated real CI source, prevent a malicious parent from exfiltrating the content before supplying it, or provide permission for any active security interaction.

## W69 — bounded receipt delivery and zero surprise output destinations (2026-10-14)

A safe bounded stdin reader is insufficient when the parent process provides a **full stdout pipe** and never consumes its bytes: even the single JSON receipt could block during flush. The opt-in CLI now serializes a single <=512-byte ASCII receipt and attempts a nonblocking `os.write(1, ...)` using a **2-second absolute monotonic output deadline**. An undrainable stdout pipe, write error, unavailable output fd or sink metadata error causes immediate or bounded **exit 2/HOLD**, never success. On a pipe with enough space, the tiny one-write receipt remains one JSON line. Partial delivery to terminals is possible on I/O failure; partial output is never authorization.

The output fd is also checked before any write. Only a FIFO/pipe or verified terminal (`os.isatty(1)`) may receive the receipt. Other character devices (including `/dev/null`) are rejected before writing. Inherited **socket, regular file, directory or block device** stdout destinations are refused entirely: a caller cannot smuggle a network send or on-disk output into the reviewer through a redirected fd1. This intentionally means `> report.json` writes no receipt: collect it through a normal pipe and let an independent process own any optional storage. Both stdin and stdout fd contracts now reject sockets/files while keeping ordinary finite pipe use.

New genuine subprocess regressions use a disposable redirected regular file, an AF_UNIX local socketpair, a non-tty `/dev/null` sink and an **intentionally prefilled unread stdout pipe**. Separate real local POSIX pseudoterminal and closed-pipe process tests prove that a genuine terminal still receives one HOLD-only JSON line while broken output pipes exit 2 without traceback. The child must exit within a bounded interval with return code 2, no traceback, no file bytes written and no socket bytes transmitted. Direct tests deny spoofed stdout fileno, forbidden fd mode and oversized receipt before touching the sink. No customer targets, installed ingress, real policy/grant, actual network addresses or deploy infrastructure are involved. This is a Python/userland compatibility proof, **not an OS sandbox or release permission**.

## W70 — inherited pipe status restoration (2026-10-14)

**Concrete safety defect in W69:** `os.set_blocking(1, False)` modifies `O_NONBLOCK` on the underlying **open-file description**. An inherited pipe's original writer can share that same description with the child; the reviewer previously exited with the *parent writer left nonblocking*. That is an observable ambient side effect, even though the JSON receipt itself is always HOLD.

The bounded stdout writer now snapshots `os.get_blocking(1)` and temporarily changes only a previously blocking descriptor. A `finally` restores its prior blocking state across successful writes, full-output-pipe deadline expiry and broken-pipe/`EPIPE` failure; an already-nonblocking writer is left unchanged. New **genuine subprocess tests** inspect the actual parent `os.get_blocking(writefd)` **after child termination** in both initial mode states, on a deliberately filled originally-blocking pipe, and on a broken originally-blocking pipe. They also preserve the normal one-line HOLD receipt and exact exit code 2.

Important limitation: the state can be transiently nonblocking **while** the child writes, because this is a shared POSIX open-file description. Restoring the state on exit eliminates the persistent leak, not the brief cross-process race. Integrators requiring strict simultaneous writer isolation should supply a dedicated private pipe, not a shared writer. This remains synthetic diagnostics, not a hardened OS sandbox or permission to release.

## W71 — sealed stdout payload admission before fd access (2026-10-14)

The transport-level `_emit_hold_receipt` accepted **any** <=512-byte `bytes` value. Although normal `main` already created a privacy-minimal HOLD packet, an accidental future direct call or refactor could send arbitrary secret-bearing bytes through this lower-level output helper. **W71 requires exact canonical HOLD JSON as an independent precondition before touching inherited fd1**. The emitter now checks exactly the 11 known keys, canonical lower-level compact ASCII serialization plus one trailing newline, exact schema, `status=HOLD`, canonical `COHERENT|REJECTED`, 0–4 **int-not-bool** unverified claimed passes (exactly 0 for REJECTED), `verified_evidence=false`, and **six literal false authorization flags**. Duplicate JSON keys, extra unknown fields, type-confused values, mixed case, unexpected trailing bytes, non-ASCII and noncanonical whitespace are rejected before `fileno/fstat/write`. This guard is deliberately conservative; it does not validate the truth of any input claims.

New isolated tests check all synthetic claim labels, both coherent and rejected canonical receipts, mutations of each false permission field into `true` or numeric impostors, schema/status tampering, forbidden nonzero rejected-pass counts, unexpected secret fields, mixed newline/whitespace/duplicate-key encodings and actual child-process output. An in-process I/O tripwire asserts malformed receipts do **not even touch stdout's file descriptor**. Existing finite pipe/TTY semantics remain unchanged. No real security targets, external networks, authority grants, production handlers or workflow ownership are involved.

## W72 — immutable denial flag map (2026-10-14)

The six false authorization markers were previously held in an ordinary mutable module dictionary. An in-process import could accidentally mutate a denial value to `True`, remove a key or add an unreviewed field. The W71 sealed stdout serializer would then conservatively suppress malformed output, but **`review_bytes` itself could return a misleading object** to a caller. The false-flag template is now a read-only `MappingProxyType`: all six known entries remain literal false, and attempts to set, delete or add a key raise `TypeError`. Independent tests exercise every marker and verify ordinary real subprocess output continues to be the unchanged canonical HOLD-only report. This only defends accidental mutation of the existing object; arbitrary hostile Python code able to rebind module globals is beyond this script's authority boundary and cannot be regarded as a hardened sandbox.

## W73 — simultaneous backpressure and invalid-argv EOF independence (2026-10-14)

A partial secret-bearing producer can keep fd0 open forever **at the same time** that an undrained parent keeps fd1 completely full. Two independent I/O budgets must compose to finite total process lifetime without stack trace, permission promotion, or lasting mutation of the parent writer's status flags. A genuine child-process acceptance now pre-fills a disposable stdout pipe, restores its parent's blocking state to its original value, deliberately sends only a partial `SECRET-...` stdin packet without EOF, and asserts the child terminates with **exit 2 within 7.5 seconds**, stderr empty and the original parent pipe's blocking mode unchanged. An additional real-process test passes bad argv with an intentionally **unclosed** secret-bearing stdin writer, requiring a sealed privacy-minimal rejected HOLD line without reading or echoing that input. All descriptors are local synthetic test pipes. This validates bounded **combined** transport failure, not any claimed CI/ingress evidence or actual authorization.

## Execution and fail-closed result

```sh
printf '%s' '<synthetic JSON from above>' | python -B scripts/scope_self_asserted_proof_hold_1429.py --stdin-json
python -B -m unittest tests/test_scope_self_asserted_proof_hold_1429.py -v
```

The only CLI exit is **2 (HOLD)**, even if all four self-assertions say `pass`. `status=HOLD` and every `authorized`, `permit`, `dispatch`, `merge`, `deploy`, `release` flag is exact JSON `false`. A structurally consistent bundle yields `input_integrity=COHERENT` and a count of *unverified* claimed passes. Any invalid member yields `REJECTED` and count zero. A printed coherence label does **not** authorize a call or a merge. The CLI never reads another file or accesses DNS, sockets, subprocesses or customer targets.

## Required independent promotion gates (not met by this script)

- Fetch authentic immutable SHA and per-job raw hosted Python3.11 and Python3.14 logs from GitHub.
- Fetch genuine registered permanent-VPS runner job logs on that **same** SHA; queued/cancelled is not pass.
- Validate installed Nginx/Gunicorn identity/provenance and actual ingress request behaviour, independently of synthetic fixtures.
- Obtain source-owner scope fixes, current target-specific consent, independent security/privacy review and explicit human release authorization.

Until those have separately passed: **do not merge this draft, deploy, issue grants or run active security scans**. A passing synthetic structural test cannot become proof of any other requirement.
