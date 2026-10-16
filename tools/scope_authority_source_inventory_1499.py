"""#1499: isolated offline source-shape inventory of fixed LightUp authority gates.

This is developer-pinned regression metadata ONLY, not signed source
provenance, customer authorization, a scope decision, DLP, or release approval.
The script never imports or executes ANY target module. It statically parses
a fixed 5-file source allowlist, never scans a target or grants a permit.
"""
from __future__ import annotations

import ast
from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path

CONTRACT = "LIGHTUP-SOURCE-AUTHORITY-INVENTORY-1499-V1"
REPO_ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 131072

# Developer-selected SHA256 pins for immutable main e73b7445c87ad239...
# These pins verify equality to a known snapshot, not correctness, safety,
# provenance or ownership of that snapshot.
PINNED_SOURCES = {
    "src/lightup/scope.py": "1bf081d0b85490466fbb4ad95b2d12917882ed51d05627139bdd5abf110018c0",
    "src/lightup/activation.py": "8fc499131cb8b5b231649326ccb3db2c524bde7b0af0f95102714645d87553bc",
    "src/lightup/execution_policy.py": "8272b9254a7a5ed27043ce2ed1c9a8e533fedfb4a2c20c14d24e5fd993bacaff",
    "src/lightup/models.py": "f84779b55f193c2d0a143418cf569c3539ee2bdb92e76a542ffda39643d3b541",
    "src/lightup/engagements.py": "fb214d4ad2fd86cbb5d19695e644e85f7e5841aec1b8f987d2cfc71080d08488",
}
REQUIRED_METHODS = {
    "src/lightup/scope.py": {
        "ScopePolicy": {"normalize_host": 1, "_networks": 1, "decide": 2},
    },
    "src/lightup/activation.py": {
        "ActivationPolicy": {"validate": 1},
        "ActivationGate": {"__init__": 3, "issue": 3},
    },
    "src/lightup/execution_policy.py": {
        "ExecutionPolicy": {"decide": 2},
    },
    "src/lightup/models.py": {
        "Authorization": {"is_current": 2},
    },
    "src/lightup/engagements.py": {
        "AuthorizationGrant": {"is_current": 2},
        "ScopeDefinition": {"allows_asset": 2, "allows_capability": 2},
    },
}
_FORBIDDEN_CALLS = frozenset({"eval", "exec", "compile", "__import__"})

# Call topology hints are structural *presence/order* checks only. They do NOT
# prove that conditionals are effective; the original source still needs a
# human security review and source-owner RED fixes.
EXPECTED_ORDERED_CALLS = {
    ("src/lightup/scope.py", "ScopePolicy", "decide"): (
        "normalize_host", "ip_address", "is_current",
    ),
    ("src/lightup/activation.py", "ActivationGate", "issue"): (
        "decide", "ExecutionPermit", "token_urlsafe",
    ),
    ("src/lightup/execution_policy.py", "ExecutionPolicy", "decide"): (
        "is_current", "allows_asset", "allows_capability",
    ),
}


def _static_call_names(fn: ast.FunctionDef) -> tuple[str, ...]:
    """Lexical call name sequence only. Never resolves or executes callees."""
    nodes = [node for node in ast.walk(fn) if isinstance(node, ast.Call)]
    nodes.sort(key=lambda item: (item.lineno, item.col_offset))
    return tuple(
        node.func.id if type(node.func) is ast.Name else
        node.func.attr if type(node.func) is ast.Attribute else ""
        for node in nodes
    )


def _has_early_scope_denial(fn: ast.FunctionDef) -> bool:
    """Check the source AST's first unconditional-looking permission boundary.

    Specifically verifies: decision = scope_policy.decide(target), then
    if not decision.allowed: raise PermissionError(...) before permit return.
    This DOES NOT prove the runtime condition's semantics.
    """
    decisions = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
                 and type(n.func) is ast.Attribute and n.func.attr == "decide"]
    permits = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
               and type(n.func) is ast.Name and n.func.id == "ExecutionPermit"]
    denies = []
    for statement in fn.body:
        if not isinstance(statement, ast.If):
            continue
        test = statement.test
        if not (type(test) is ast.UnaryOp and type(test.op) is ast.Not
                and type(test.operand) is ast.Attribute
                and test.operand.attr == "allowed"
                and type(test.operand.value) is ast.Name
                and test.operand.value.id == "decision"):
            continue
        if any(type(n) is ast.Raise for child in statement.body for n in ast.walk(child)):
            denies.append(statement)
    return (len(decisions) == 1 and len(permits) == 1 and len(denies) == 1
            and decisions[0].lineno < denies[0].lineno < permits[0].lineno)



@dataclass(frozen=True)
class InventoryVerdict:
    status: str
    source_count: int
    contract: str = field(default=CONTRACT, init=False)
    authorized: bool = field(default=False, init=False)
    consent_verified: bool = field(default=False, init=False)
    dispatch_allowed: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if (type(self.status) is not str or type(self.source_count) is not int
                or self.contract != CONTRACT
                or (self.status == "HOLD" and self.source_count != 0)
                or (self.status == "REVIEW_ONLY" and self.source_count != len(PINNED_SOURCES))
                or self.status not in {"HOLD", "REVIEW_ONLY"}):
            raise ValueError("invalid non-authorizing source inventory verdict")


def _hold() -> InventoryVerdict:
    return InventoryVerdict("HOLD", 0)


def inspect_static_shape(path: str, source: str) -> bool:
    """Pure structural tests; no execution, module import or side effects."""
    if type(path) is not str or path not in REQUIRED_METHODS or type(source) is not str:
        return False
    if len(source) > MAX_FILE_BYTES:
        return False
    try:
        root = ast.parse(source, filename="<fixed-authority-source>", mode="exec")
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
    classes = [item for item in root.body if isinstance(item, ast.ClassDef)]
    for cname, methods in REQUIRED_METHODS[path].items():
        matches = [item for item in classes if item.name == cname]
        if len(matches) != 1:
            return False
        cls = matches[0]
        for method, arguments in methods.items():
            items = [node for node in cls.body if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and node.name == method]
            if len(items) != 1 or type(items[0]) is not ast.FunctionDef:
                return False
            fn = items[0]
            # These source functions either have no argument defaults, or
            # a single optional current-time arg in is_current.
            if (fn.args.vararg is not None or fn.args.kwarg is not None
                    or fn.args.kwonlyargs or fn.args.posonlyargs
                    or fn.args.kw_defaults or len(fn.args.args) != arguments):
                return False
            if len(fn.args.defaults) != (1 if method == "is_current" else 0):
                return False
            expected_decorators = ("staticmethod",) if method == "normalize_host" else ()
            decorators = tuple(node.id if type(node) is ast.Name else None for node in fn.decorator_list)
            if decorators != expected_decorators:
                return False
            for node in ast.walk(fn):
                if type(node) is ast.Call and type(node.func) is ast.Name:
                    if node.func.id in _FORBIDDEN_CALLS:
                        return False
            expected_calls = EXPECTED_ORDERED_CALLS.get((path, cname, method))
            if expected_calls is not None:
                calls = _static_call_names(fn)
                # Names are listed in original AST lexical call-site order.
                # Exact expected call names may be repeated in real code
                # (ScopePolicy checks both explicit host & network). Require
                # canonical first-occurrence order without banning repeats.
                first = tuple(next((i for i, name in enumerate(calls) if name == expected), -1)
                              for expected in expected_calls)
                if -1 in first or first != tuple(sorted(first)):
                    return False
            if (path, cname, method) == ("src/lightup/activation.py", "ActivationGate", "issue"):
                if not _has_early_scope_denial(fn):
                    return False
    return True


def review_source_bytes(source_files: object) -> InventoryVerdict:
    """Pure all-or-nothing reviewer hint: only five exact pinned files."""
    if type(source_files) is not dict or source_files.keys() != PINNED_SOURCES.keys():
        return _hold()
    for path, pinned in PINNED_SOURCES.items():
        raw = source_files[path]
        if type(raw) is not bytes or not (1 <= len(raw) <= MAX_FILE_BYTES):
            return _hold()
        if hashlib.sha256(raw).hexdigest() != pinned:
            return _hold()
        try:
            source = raw.decode("utf-8", "strict")
        except UnicodeError:
            return _hold()
        if not inspect_static_shape(path, source):
            return _hold()
    return InventoryVerdict("REVIEW_ONLY", len(PINNED_SOURCES))


def review_checked_in_sources() -> InventoryVerdict:
    """Read only built-in relative, nonsymlink source paths; no CLI path args."""
    paths = {}
    for rel in PINNED_SOURCES:
        full = REPO_ROOT / rel
        if full.is_symlink() or full.parent.is_symlink() or full.parent.parent.is_symlink():
            return _hold()
        try:
            if not full.is_file() or full.stat().st_size > MAX_FILE_BYTES:
                return _hold()
            with full.open("rb") as stream:
                data = stream.read(MAX_FILE_BYTES + 1)
        except (OSError, ValueError):
            return _hold()
        if len(data) > MAX_FILE_BYTES:
            return _hold()
        paths[rel] = data
    return review_source_bytes(paths)


def main(args: tuple[str, ...] | None = None) -> int:
    import sys

    args = tuple(sys.argv[1:]) if args is None else args
    result = review_checked_in_sources() if args == ("--offline-review-only",) else _hold()
    print(json.dumps(asdict(result), sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return 2 if result.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
