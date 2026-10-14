# Issue #1422 — installed ScopePolicy lab admission audit (W38)

## Scope and intent

A **read-only, opt-in diagnostic of the source in the exact current checkout**, not a deployed-service probe and not a replacement for the source-owner fix in [PR #100](https://github.com/Zennay/Lightup/pull/100).

Source: `src/lightup/scope.py` currently treats `ipaddress.is_private` (which means non-global, not strictly private-use lab) or link-local as `PRIVATE_LAB` membership. Consequently reserved/documentation/benchmarking addresses may be treated as allowed without authorization. That is an actual production-code acceptance gap, tracked in [#1422](https://github.com/Zennay/Lightup/issues/1422) and illustrated in independent expected-RED [PR #1423](https://github.com/Zennay/Lightup/pull/1423).

## Offline use

```bash
python -I -B scripts/audit_scope_installed_lab_policy_1422_offline.py
python -B -m unittest discover -s tests -p 'test_scope_installed_lab_audit_1422_offline.py' -v
```

No CLI arguments (including `--help`) are admitted, no input files or stdin are read, and no remote addresses are contacted. All checked literals are fictional static in-code examples; loopback/private ranges are **parsed only**, never probed. There is no host-name resolution, socket activity, active executor invocation, customer data, target-specific credential, durable permission/grant mutation, workflow configuration, or deployment.

## Exact outcome

The only stdout is a single minimal JSON line with `status`, `checked_count`, `total_count` and five literal `false` fields:
`authorization_verified`, `permit_issued`, `execution_enabled`, `merge_approved`, `release_approved`.

- **HOLD (exit code 2, checked_count=0):** any unexpected/malformed source result, exception, wrong literal classification, even one forbidden address auto-admitted, or any supplied CLI parameter. Atomic HOLD never claims a partial pass.
- **REVIEW_ONLY (exit code 3):** all fixed positive, negative and disabled-private-lab check cases satisfy the current source-policy behavioral contract. **This still does not grant scope, consent, approval, permit, merge, execution or release.**
- Exit code 0 is impossible by design. Scripts that assume zero means success MUST NOT treat this tool as an authorization prerequisite.
- No failing IP literals, traceback, credential or input arguments are echoed; the static case count is non-sensitive.
- Python 3.11 and 3.14 should run independently to detect `ipaddress` version-dependent classifications. One interpreter's results do not attest to another.


## W39 extension — broad network still requires an authentic grant

The additional third decision per forbidden literal creates an explicit `ScopePolicy(allow_private_lab=False, require_authorization_for_public=True, explicit_networks=("0.0.0.0/0", "::/0"))`, and calls real `decide(Target(literal))` with **no `Target.authorization`**. It must return **`allowed is False` and `reason is AUTHORIZATION_MISSING`**, despite the very broad explicit-network configuration. This specifically guards against a misleading source repair that closes private-lab membership but accidentally lets public or reserved targets through the explicit-network fallback without a grant. This is a simulated no-grant, no-target-I/O scenario — it does **not** test or create a signed real-world customer grant.

The negative matrix now also includes mapped RFC1918 / mapped loopback IPv6 and 6to4 / Teredo transition samples, alongside neighbors on each side of the RFC1918, 127/8 and ULA ranges. Every denial must preserve exact canonical `ScopeDecision`, exact `bool` and `ScopeReason` types, never an outer duck-type. A cross-version difference can only reduce confidence to HOLD, never grant authority. `total_count` is **124** (11 positive × 2 policy configurations plus 34 negative × 3), with `checked_count=0` on any HOLD.

Two new synthetic negative-control tests prove that admitting one public address without a grant, **or returning an incorrect denial reason** in the explicit-network case, forces atomic HOLD. A separate strict synthetic fixture still demonstrates REVIEW_ONLY without ever granting permission. Hosted Python3.11 and 3.14 and separate permanent VPS evidence must be verified on the **new immutable head**; earlier green jobs do not transfer to this revision.

## W39 safety hardening — prevent accidental different-package review

The installed-source reviewer must read the exact checkout's original `lightup.scope` and `lightup.models` modules, not a different version left in `sys.modules` or inherited from a global Python installation. The auditor now checks both imported modules' **exact built-in module and `__file__` path identities** against the script's source checkout and fails closed to HOLD on mismatch. Synthetic tests explicitly patch the scope/model module paths and replace one preimported module with an invalid object; all must HOLD. An additional real subprocess check runs the CLI with Python `-I -B` (isolated interpreter flags and no bytecode writing).

This is a **local path consistency guard**, not a signed CI provenance attestation and not a guarantee that arbitrary Python startup hooks, filesystem aliases, Git replace references or hostile interpreter environments are absent. The owner must still validate the actual original source independently. For ordinary manual runs prefer the isolated interpreter command above.

## W40 — explicit-host missing/expired authorization must deny

The same installed-source offline diagnostic now checks **three static synthetic hostname spellings** for an explicitly listed host: lower-case `review.invalid`, mixed case plus terminal dot `REVIEW.INVALID.`, and the URL-form `https://review.invalid/no-network`. These are **never resolved or contacted**, and the `.invalid` domain is used precisely to avoid representing a customer asset. For each variant the real `ScopePolicy(allow_private_lab=False, require_authorization_for_public=True, explicit_hosts=frozenset({"review.invalid"}))` is called twice:

- **Absent authorization:** `allowed is False`, canonical `ScopeReason.AUTHORIZATION_MISSING`, normalized host exactly `review.invalid`.
- **Expired synthetic authorization:** `allowed is False`, canonical `ScopeReason.AUTHORIZATION_EXPIRED`, normalized host exactly `review.invalid`. The only `Authorization` instance in this diagnostic is a static, fictional, definitively expired object (January 1, 2000 UTC). Its label/reference are **not trusted credentials**.

Any incorrect admission, canonicalization drift, unexpected type or exception yields **atomic HOLD**. Three dedicated negative-mutant unit tests require this behavior: no-grant bypass, expired-grant bypass and normalized-host drift on URL input. The complete static audit has **130 individual policy decisions**, while the original W39 positive/negative matrix and source provenance checks remain untouched. This tests denial-only behavior; **no valid grant is produced or evaluated as an approval**. Even passing output is `REVIEW_ONLY`, never a permit or release authority.

## W41 — expiry remains restrictive across every broad explicit-network address

The previous W39 check denied each fixed forbidden IP under a synthetic overbroad `0.0.0.0/0` / `::/0` explicit-network policy with missing authorization. W41 makes that **dual-condition**: each of the **34 negative IP literals** must also be denied with a static and definitively expired **2000-01-01 UTC** `Authorization`, returning exact `AUTHORIZATION_EXPIRED`. The same immutable synthetic expired record previously used for W40's three hostname variants is reused; there are **no customer credentials or actual permits**.

This adds 34 real checked-out `ScopePolicy.decide` calls (**164 decisions total**) and two dedicated negative-mutant tests that explicitly reject (a) execution admission despite an expired grant and (b) incorrectly reporting a missing rather than expired authorization. There are now **26 dedicated unittest methods**. The static receipt remains deliberately privacy-minimal: only total count, status, and five false flags, and CLI still never exits 0. Neither an expiry result nor REVIEW_ONLY is permission or a source-owner fix.

## W42 — authorization not yet effective is denied before its start instant

W42 adds the missing **future-validity start boundary**, without changing a production policy or creating an effective grant. A fixed fictional `Authorization(owner="offline-fixture", reference="not-effective-permit", valid_from=2999-01-01T00:00:00+00:00)` is supplied to the **actual checked-out** `ScopePolicy.decide` for each of the **34 already forbidden IP literals** inside explicit `0.0.0.0/0` and `::/0` networks, and each of the **3 synthetic `review.invalid` hostname spellings**. This document does not authorize use of those broad networks: they are a simulation used to prove fail-closed decisions without ever contacting targets.

In every one of these **37 additional decisions**, the result must remain `allowed is False` with exact `ScopeReason.AUTHORIZATION_EXPIRED` (this is the existing implementation's generic out-of-validity reason, including a start date in the future). The synthetic future record is intentionally not presently effective and never tested as a valid grant. Four negative mutation tests independently demand atomic HOLD when a not-yet-effective host or network grant is incorrectly admitted **or** receives the wrong denial reason. The matrix now comprises **201 fixed, static actual source policy decisions**, with **30 dedicated unit methods**.

The receipt remains wholly non-authorizing. If any single decision fails, reports HOLD and `checked_count=0`; if every check passes, reports REVIEW_ONLY while authority/permit/dispatch/merge/release flags remain explicitly false. Hosted CI for Python 3.11 and 3.14, genuine producer integration tests and separately registered VPS-run evidence must be tied to this exact revision. A passing test cannot waive the source-owner repair tracked by #1422.

## W43 — keep exact refused-target identity in every negative decision

When the installed policy returns a rejected `ScopeDecision` for a fixed forbidden IP, the reviewer now also verifies that **`normalized_host` is still that very literal IP**. Only outer IPv6 URI brackets are removed from the predefined sample. It checks this invariant under every one of the five evaluated configurations: default private-lab enabled; private-lab disabled; explicitly broad networks with missing authorization, expired authorization, and a future-start authorization. A deny result that quietly replaces a public, documentation or reserved target with a trusted loopback or RFC1918/ULA address must **HOLD**, even if its `allowed=False` and `reason` look correct. This prevents a misleading normalized target from propagating through later review steps; it does not replace any actual executor gate or approve network traffic.

Three new injected mutants independently corrupt (1) an ordinary denial's normalized address, (2) a missing-grant IPv4 decision's address, and (3) an expired-grant IPv6 decision's address. The strict synthetic fixture now returns the exact hostname, not a placeholder. All **201 fixed policy decisions** remain denial-only, with **33 dedicated unittest methods** after W43. No additional target addresses, network probes, customer grants, deployment or production source edits have been introduced.

## Safety and ownership

This deliberately evaluates **real unmodified** `ScopePolicy.decide(Target(...))` from this checkout, unlike [#1424/#1425](https://github.com/Zennay/Lightup/pull/1425), which supplies a standalone reference reviewer. It does not write to or import the tool executor, production admission wiring, tenancy logic or the neighboring target parser. All three new files are owned by W38; source-owner #100, RED owner #1423, standalone reviewer #1425, CIDR #1318, CI and runners remain untouched.

Successful green unit tests verify that this diagnostic detects synthetic denial faults. They are not evidence that the **installed policy is fixed**: the currently unsafe source is expected to emit HOLD, not a green release verdict. The source-owner must narrow production IP membership, convert issue #1422 RED assertions to regular passing tests, and obtain independent security/privacy and explicit human review before any activation.

**Project stage: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/SCAN.**
