# LightUp scope #1531 · offline handler-admission assurance (2026-10-17)

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This dossier is not a production authorization, a permission grant, a consent record, a release decision, or an active tool. The branch is intentionally isolated from concurrent owners and no original LightUp runtime code was changed.

## Installed-source observation

On unchanged `main` at `e73b7445c87ad239bdb03c50a99078ef93163b02`, `ToolRegistry.register(definition, handler)` checks tool-ID uniqueness and capability identity but does not reject a non-callable handler such as `None` or `123`. The handler is stored in `_tools` and the tool is advertised in `definitions()`. Later `ToolExecutor.execute` invokes the stored value only after policy decisions. Misconfigured registrations therefore can result in late `TypeError` and availability failure. **This does not prove a policy bypass, a handler invocation, or any external vulnerability.**

## Exact isolated deliverables

1. `scripts/scope_handler_admission_review_20261017.py`: optional reviewer for strictly fictional metadata-only Python function pairs. Accepts exact immutable tuples of 1–32 unique lower-ASCII synthetic identifiers and plain two-positional-argument, nonasync, nongenerator, nonclosure Python functions. Ambiguous shapes, subclasses, callable objects, defaults, keyword-only or variadic functions, malformed identifiers and duplicates return generic `HOLD`. The reviewer only examines values; it does **not** call handlers. A function may change its code/defaults after a review, so callers must never treat this observation as a durable code binding. A shape-conforming record receives `REVIEW_ONLY`, which is neither a registry permit nor authentication of origin.
2. `tests/test_scope_handler_admission_20261017.py`: 18 ordinary stdlib synthetic and installed-source positive checks, and 4 deliberately marked `expectedFailure` checks for the unchanged original `ToolRegistry.register` source gap. `tests/test_scope_handler_admission_boundary_20261017.py`: seven additional ordinary adversarial checks for production import isolation via AST, ASCII byte-class completeness, strict tuple/subclass traps and 32-row atomic HOLD. The tests never call `ToolExecutor.execute`, any handler, a worker, a network target, a scanner or a database.
3. `.github/workflows/scope-handler-admission-1531.yml`: opt-in branch-scoped isolated GitHub-hosted Python 3.11/3.14 test lane, SHA-pinned checkout/setup-python, read-only token scope, no credentials retention, no deploy and no self-hosted runner trigger. The own CI job now compares exact Git commit objects with a pinned main ancestor before and after tests, requires exactly the five exclusively new regular-mode owned files, and rejects modifications to original/source-owner paths. This is not a general-purpose Git trust or full-worktree attestation.

The receipt constructor accepts only exact built-in `str` status `HOLD` or `REVIEW_ONLY`; it rejects spoofed statuses, type subclasses and user-supplied authority flags. Each `HandlerAdmissionReview` is a new frozen instance with `authorized=False`, `consent_verified=False`, `dispatch_allowed=False`, `release_allowed=False`. None of these fields can be supplied to its ordinary constructor. Forced in-process instance mutation does not taint subsequent review output. This structure does not provide a cryptographic provenance assurance or robust hostile-process boundary.

## Acceptance and ownership

- Real VPS disposable checkout via authorized zSSH on `vps-bb300bba`, Python3.14 `-I -S -B`: **30 tests executed: 26 ordinary PASS, 4 original-source expected failures, 0 unexpected fails**. Clean checkout and exact own branch SHA verified; the unchanged pre-existing `capability_registry_history_report.py` raises a nonfatal `SyntaxWarning` during AST parsing. This is an isolated test result, **not** registered named-runner CI proof.
- The original source-owner for `ToolRegistry` definition admission and schema remains #907 and #911; #1520 owns duplicate parameter names. #940 owns registry identity binding. This #1531 lane makes **no** change to those files/branches and is not a replacement for their production repair.
- Additional deliberately open source REDs demonstrate acceptance of an asynchronous handler and a wrong-arity handler despite correct existing registrations; they do not invoke either handler. After production repair by the appropriate source owner, convert the four intentional source expected failures into ordinary mandatory PASS; confirm fail-atomic invalid handler admission, preserve legitimate registrations, and complete independent security review before any source promotion.
- The current entire original hosted CI and permanent named VPS runner are not verified GREEN by this package. Other known original red source admission gaps and expired-date fixture #301 remain separate. No synthetic review output is evidence of real client/operator approval.

## Release gates

**NO MERGE, NO DEPLOY, NO REAL TARGET, NO SCAN, NO HANDLER DISPATCH, NO GRANT, NO RELEASE.**

Real independently authenticated client plus operator consent with at-use revocation, source-owner hardening, full exact-head hosted and permanently registered named VPS validation, independent security/privacy review and explicit HUMAN GO are necessary before release.
