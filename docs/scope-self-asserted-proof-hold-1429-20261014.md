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
