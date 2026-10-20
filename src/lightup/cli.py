from __future__ import annotations

import argparse
import json

from .models import Target
from .orchestrator import Planner
from .scope import ScopePolicy


def _policy(args: argparse.Namespace) -> ScopePolicy:
    return ScopePolicy(
        allow_private_lab=not args.no_private_lab,
        explicit_hosts=frozenset(args.allow_host or []),
        explicit_networks=tuple(args.allow_cidr or []),
        require_authorization_for_public=True,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lightup")
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--allow-host", action="append", default=[])
    shared.add_argument("--allow-cidr", action="append", default=[])
    shared.add_argument("--no-private-lab", action="store_true")

    sub = parser.add_subparsers(dest="command", required=True)
    scope = sub.add_parser("scope-check", parents=[shared])
    scope.add_argument("target")

    plan = sub.add_parser("plan", parents=[shared])
    plan.add_argument("target")

    serve = sub.add_parser("serve", help="run the loopback-only web shell")
    serve.add_argument("--db", default="lightup.db")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8766)

    lab = sub.add_parser("lab-baseline",
                         help="run the HTTP header baseline against a lab fixture")
    lab.add_argument("url", nargs="?", default="http://127.0.0.1:18080/")
    lab.add_argument("--db", default="lightup-lab.db")
    lab.add_argument("--expect-fixture", action="store_true")

    assess = sub.add_parser("lab-assess",
                            help="planner-driven multi-lane lab assessment with "
                                 "AI review (scripted demo gateway by default)")
    assess.add_argument("url", nargs="?", default="http://127.0.0.1:18080/")
    assess.add_argument("--db", default="lightup-lab.db")
    assess.add_argument("--gateway-config")
    assess.add_argument("--profile")
    assess.add_argument("--no-review", action="store_true")

    review = sub.add_parser(
        "review-change",
        help="pre-merge security review of a git range (offline, inferred verdict)")
    review.add_argument("--repo", default=".", help="local git checkout")
    review.add_argument("--base", default="origin/main")
    review.add_argument("--head", default="HEAD")
    review.add_argument("--repository", help="owner/name (default: from origin)")
    review.add_argument("--client-id", default="local")
    review.add_argument("--compare-json",
                        help="GitHub compare API JSON instead of a local git range")
    review.add_argument("--policy", help="policy JSON (default: <repo>/.lightup-review.json)")
    review.add_argument("--format", choices=("markdown", "json", "sarif"),
                        default="markdown")
    review.add_argument("--output", help="write the report here instead of stdout")
    review.add_argument("--sarif-output", help="additionally write SARIF here")
    review.add_argument("--json-output", help="additionally write JSON here")
    review.add_argument("--no-merge-base", action="store_true",
                        help="diff base..head directly instead of from the merge base")
    review.add_argument("--db", help="also store the review for --client-id in this "
                                     "LightUp database (shown in the web shell)")
    review.add_argument("--fail-on", default="block",
                        choices=("never", "warning", "review", "block"),
                        help="exit 1 when the verdict is at least this severe")

    boot = sub.add_parser("create-operator",
                          help="bootstrap the first operator account")
    boot.add_argument("--db", default="lightup.db")
    boot.add_argument("--email", required=True)
    boot.add_argument("--name", required=True)
    boot.add_argument("--password", help="omit to be prompted securely")

    cuser = sub.add_parser("create-client-user",
                           help="create a client portal account")
    cuser.add_argument("--db", default="lightup.db")
    cuser.add_argument("--email", required=True)
    cuser.add_argument("--name", required=True)
    cuser.add_argument("--client-id", required=True)
    cuser.add_argument("--password", help="omit to be prompted securely")
    return parser


def _account_command(args: argparse.Namespace) -> int:
    from getpass import getpass

    from .domain import AccessContext, DomainStore, Role

    password = args.password or getpass("Password (min 10 chars): ")
    store = DomainStore(args.db)
    if args.command == "create-operator":
        user = store.bootstrap_operator(args.email, args.name, password)
    else:
        ctx = AccessContext("cli-bootstrap", Role.OPERATOR)
        user = store.create_user(ctx, args.email, args.name,
                                 Role.CLIENT_ADMIN, args.client_id)
        store.set_password(ctx, user.user_id, password)
    print(json.dumps({"user_id": user.user_id, "email": user.email,
                      "role": user.role.value, "client_id": user.client_id}, indent=2))
    return 0


_FAIL_ON = {
    "never": None,
    "warning": "PASS_WITH_WARNING",
    "review": "REVIEW_REQUIRED",
    "block": "BLOCK",
}


def _review_change_command(args: argparse.Namespace) -> int:
    import os
    import sys
    from pathlib import Path

    from .change_review import (
        ChangeReviewPolicy, render_markdown, render_sarif, review_change,
    )
    from .changes import ChangeSourceKind
    from .change_review import POLICY_FILE
    from .git_changes import GitChangeError, collect_git_range, read_file_at

    repo = Path(args.repo)

    def _policy(base_revision: str | None) -> ChangeReviewPolicy:
        # An explicit --policy wins. Otherwise the policy comes from the *base*
        # revision, so a change can never relax the policy it is reviewed by.
        if args.policy:
            return ChangeReviewPolicy.load(args.policy)
        if base_revision is not None:
            text = read_file_at(repo, base_revision, POLICY_FILE)
            return (ChangeReviewPolicy.from_mapping(json.loads(text))
                    if text is not None else ChangeReviewPolicy())
        local = repo / POLICY_FILE
        return ChangeReviewPolicy.load(local) if local.is_file() else ChangeReviewPolicy()

    try:
        if args.compare_json:
            compare = json.loads(Path(args.compare_json).read_text(encoding="utf-8"))
            base = compare.get("merge_base_commit", {}).get("sha") or compare["base_commit"]["sha"]
            head = compare["commits"][-1]["sha"] if compare.get("commits") else args.head
            review = review_change(
                client_id=args.client_id,
                repository=args.repository or "local/repository",
                base_revision=base, head_revision=head,
                files=compare.get("files", []),
                source_kind=ChangeSourceKind.GITHUB_COMMIT,
                policy=_policy(None),
            )
        else:
            git_range = collect_git_range(
                repo, args.base, args.head, repository=args.repository,
                merge_base=not args.no_merge_base,
            )
            review = review_change(
                client_id=args.client_id,
                repository=git_range.repository,
                base_revision=git_range.base_revision,
                head_revision=git_range.head_revision,
                files=git_range.files,
                structured_deltas=git_range.structured_deltas,
                policy=_policy(git_range.base_revision),
            )
    except (GitChangeError, KeyError, ValueError, OSError) as exc:
        print(f"lightup: change review failed: {exc}", file=sys.stderr)
        return 2

    markdown = render_markdown(review)
    rendered = {
        "markdown": lambda: markdown,
        "json": lambda: json.dumps(review.to_dict(), indent=2) + "\n",
        "sarif": lambda: json.dumps(render_sarif(review), indent=2) + "\n",
    }
    text = rendered[args.format]()
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    if args.sarif_output:
        Path(args.sarif_output).write_text(rendered["sarif"](), encoding="utf-8")
    if args.json_output:
        Path(args.json_output).write_text(rendered["json"](), encoding="utf-8")
    if args.db:
        from .domain import AccessContext, DomainStore, Role

        try:
            stored = DomainStore(args.db).record_change_review(
                AccessContext("cli-change-review", Role.OPERATOR),
                args.client_id, review.to_dict())
        except (LookupError, PermissionError, ValueError) as exc:
            print(f"lightup: could not store change review: {exc}", file=sys.stderr)
            return 2
        print(f"lightup: stored change review {stored.review_id}", file=sys.stderr)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write(markdown)

    threshold = _FAIL_ON[args.fail_on]
    if threshold is None:
        return 0
    order = ["PASS", "PASS_WITH_WARNING", "REVIEW_REQUIRED", "BLOCK"]
    return 1 if order.index(review.verdict.value) >= order.index(threshold) else 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "serve":
        from .webapp.__main__ import main as serve_main

        return serve_main(["--db", args.db, "--host", args.host, "--port", str(args.port)])

    if args.command == "lab-baseline":
        from .labrun import main as labrun_main

        argv = [args.url, "--db", args.db]
        if args.expect_fixture:
            argv.append("--expect-fixture")
        return labrun_main(argv)

    if args.command == "lab-assess":
        from .labrun import main_assess

        argv = [args.url, "--db", args.db]
        if args.gateway_config:
            argv += ["--gateway-config", args.gateway_config]
        if args.profile:
            argv += ["--profile", args.profile]
        if args.no_review:
            argv.append("--no-review")
        return main_assess(argv)

    if args.command == "review-change":
        return _review_change_command(args)

    if args.command in {"create-operator", "create-client-user"}:
        return _account_command(args)

    planner = Planner(_policy(args))
    target = Target(args.target)
    plan = planner.build(target)

    if args.command == "scope-check":
        print(json.dumps({
            "allowed": plan.scope.allowed,
            "host": plan.scope.normalized_host,
            "reason": plan.scope.reason.value,
        }, indent=2))
        return 0 if plan.scope.allowed else 2

    print(json.dumps(plan.to_dict(), indent=2))
    return 0 if plan.scope.allowed else 2


if __name__ == "__main__":
    raise SystemExit(main())
