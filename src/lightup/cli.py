from __future__ import annotations

import argparse
import json

from .models import Target
from .orchestrator import Planner
from .scope import ScopePolicy


def _policy(args: argparse.Namespace) -> ScopePolicy:
    return ScopePolicy(
        allow_private_lab=bool(args.allow_private_lab),
        explicit_hosts=frozenset(args.allow_host or []),
        explicit_networks=tuple(args.allow_cidr or []),
        require_authorization_for_public=True,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lightup")
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--allow-host", action="append", default=[])
    shared.add_argument("--allow-cidr", action="append", default=[])
    private_lab = shared.add_mutually_exclusive_group()
    private_lab.add_argument(
        "--allow-private-lab",
        action="store_true",
        help="explicitly trust ordinary private IP space as isolated lab scope",
    )
    private_lab.add_argument(
        "--no-private-lab",
        action="store_true",
        help=argparse.SUPPRESS,
    )

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
