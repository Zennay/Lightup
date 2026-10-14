# #1386 — Socket-construction tripwire for offline NUMBER review

The [finite NUMBER offline reviewer](../scripts/review_scope_finite_number_offline.py) is an optional, non-authorizing synthetic input checker for [#1143](https://github.com/Zennay/Lightup/issues/1143). It must not create a socket, even if it never calls `connect`, `sendto`, or DNS.

## Tested boundary

The isolated `tests/test_scope_finite_number_cli_socket_creation_20261014.py` runs the **actual** reviewer CLI in a disposable copy with a `sitecustomize` module loaded *before* the command code. The pre-import hook replaces socket construction (`socket.socket`, `socket.socketpair`, `socket.create_connection`, `socket.create_server`) with a noncatchable `os._exit(92)` sentinel. The unmodified CLI is checked with finite input, NaN, overflow and underflow, always returning the fixed `REVIEW_ONLY`/ `HOLD` receipt, nonzero exit code, and all five authority flags `false`. Six independent mutated copies intentionally attempt IPv4/IPv6/UNIX construction, socketpair and convenience constructors under `except BaseException`; each must exit 92 with zero output. No actual socket construction happens in these child cases.

This is a **separate additive test** from [#1385](https://github.com/Zennay/Lightup/pull/1385), which owns UDP `sendto`/`sendmsg` detection. No files, tests or branches from that worker are modified. No production path, workflow, runner, client database, grant, scan or target is touched.

## Limits and owner handoff

The test is a Python-level execution boundary check for this **one opt-in CLI**, not an OS-level sandbox, no general egress proof, and not an attestation that arbitrary imported or native code cannot bypass monkeypatches. In particular, network APIs below Python hooks require independent OS/network egress fencing. Passing these tests **does not** fix the real `ParamKind.NUMBER.accepts` source bug on [#1143](https://github.com/Zennay/Lightup/issues/1143), grant consent or confer execution, merge or release authority.

Run without any external targets: `python -m unittest discover -s tests -p 'test_scope_finite_number_cli_socket_creation_20261014.py' -v`. Require exact-head hosted Python 3.11 and 3.14 with the independent producer integration checks, registered permanent VPS evidence where mandated, current-main review, original source-owner and security/privacy sign-off before any broader promotion. **LightUp: INCUBATE M3/M7 · PLAN/LAB ONLY · NO ACTIVE SCANS/PRODUCTION DEPLOY.**
