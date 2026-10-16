# #920 — Exact dictionary-key admission, before caller equality

**INCUBATE M3/M7 · LAB / PLAN ONLY · DRAFT/HOLD.** This is an isolated opt-in reference improvement, **not** a patch to installed `WebSecurity`.

## Findings and corrective code

The prior, separately owned, standalone `tests/scope_920_offline_transport_guard.py` admitted an exact `dict` outer object but then immediately evaluated `metadata.keys() != _KEYS` before checking key types. An input with a `str` subclass or custom hashing/equality key could pass a set-like key view check, or cause untrusted comparison code to run. That violates the guard's own rule of checking actual types **before** any caller-controlled comparisons; it is **not** proof of exploitation of the live WebSecurity source.

On a new child branch based on exact parent `cb44861a38de225669159dcfb51d7c42477ad344`:

1. Reject non-exact dict or wrong key count before iteration.
2. Iterate exact built-in `dict` keys, using `type(key) is str` only; reject all noncanonical keys without hashing, equality, coercion or caller methods.
3. Only then compare `metadata.keys()` against the trusted fixed expected set, and only then index trusted built-in keys and check exact value types.
4. Append two regression methods with tracked string-subclass and non-string spoof keys: `HOLD`, zero post-insertion invocations of their `__hash__`/`__eq__`, and six literal false authority flags.
5. Preserve existing canonical synthetic `.example` HTTPS/loopback REVIEW_ONLY cases, CLI nonzero exits and privacy non-echo.

The exact branch is independent, retains the original parent, touches **only** the helper, its existing tests and this new document. PR #202 retains the real production boundary, and inherited source-RED defects #918/#919 remain **unfixed**.

## Verification gate

The new cases have been **committed but not executed in Python or on CI** as part of this iteration; GitHub SHA/diff is not equivalent to tests passing. Review code, then execute targeted hermetic tests on the authorized self-hosted runner once #1144 permits reliable capacity; review exact SHA, original stdout and runner assignment. Do not trigger or cancel unrelated queued canonical CI. This branch has no network/target/scan/handler/grant/release behavior, and no PR/merge/deploy is authorized.

**Owner action**: absorb/validate input-key guard only if desired; actual WebSecurity exact proxy/origin object admission stays with source-owner #202 and requires independent proof plus customer/operator consent and human GO.

## Additional CLI opt-in boundary on the same isolated child

The standalone `main(argv)` previously compared an unverified caller-owned object with `["--offline-synthetic-only"]`, potentially invoking its overridden `__eq__` and reading stdin on a forged match. This child now admits only `type(args) is list`, length exactly one and `type(args[0]) is str` before comparing the trusted flag. Two additional regression methods assert that a list-spoofing object or string-subclass option cannot trigger caller equality or a stdin read; both must return HOLD/exit 2 with six literal false authority flags.

**All newly added tests remain authored-only, not executed in this run**. No runtime wiring, external I/O, customer details, new CLI permission, hosted/VPS proof or source-RED remediation is claimed.
