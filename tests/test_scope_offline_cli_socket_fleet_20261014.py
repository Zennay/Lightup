"""No socket construction in the real offline scope-review CLI fleet (#1388).

Python-level subprocess tripwires only; this test is not an OS sandbox, a
scope authorization, or proof against native code that bypasses Python hooks.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


_REPO = Path(__file__).resolve().parents[1]
_SCRIPTS = _REPO / "scripts"
_FLAGS = (
    "authorization_verified", "permit_issued", "execution_enabled",
    "merge_approved", "release_approved",
)
# Installed automatically by Python before the actual CLI imports anything.
# Hook BOTH public socket wrappers and the direct _socket C-extension symbol.
_TRIPWIRE = """import _socket
import _sqlite3
import builtins
import io
import mmap
try:
    import fcntl as _fcntl
except ImportError:  # Python-platform optional; hosted CI is Linux.
    _fcntl = None
import os
import pathlib
import socket
import sqlite3
import subprocess

def forbidden(*args, **kwargs):
    os._exit(92)

# Native mmap reads bypass Python os.read/ReadBuffer/open call interception.
# Real offline review CLIs must not construct any memory-mapped file.
mmap.mmap = forbidden

_socket.socket = forbidden
socket.socket = forbidden
socket.socketpair = forbidden
socket.create_connection = forbidden
socket.create_server = forbidden
socket.fromfd = forbidden
# DNS / reverse DNS can run through native system resolvers WITHOUT first
# allocating a Python socket. Instrument both the public Python wrapper
# and the directly importable C extension entrypoints before CLI import.
for module in (socket, _socket):
    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex",
                 "gethostbyaddr", "getnameinfo", "getfqdn"):
        if hasattr(module, name):
            setattr(module, name, forbidden)
subprocess.Popen = forbidden
os.system = forbidden
os.popen = forbidden
for name in ("fork", "forkpty", "spawnv", "spawnve", "spawnvp",
             "spawnvpe", "execv", "execve", "execvp", "execvpe",
             "posix_spawn", "posix_spawnp"):
    if hasattr(os, name):
        setattr(os, name, forbidden)

# Catch attempts, even if application code swallows BaseException. Ordinary
# read-only file opens remain available for local manifest inspection.
_real_open = builtins.open
_real_io_open = io.open
_real_path_open = pathlib.Path.open
_real_os_open = os.open
_real_os_close = os.close
_real_fdopen = os.fdopen
# Track only file descriptors opened through the allowlisted path admission.
# The numeric fd itself is untrusted until tied to that safe open operation.
_ADMITTED_READ_FDS = set()
_FD_READ_ORIGINALS = {
    name: getattr(os, name) for name in ("read", "readv", "pread", "preadv")
    if hasattr(os, name)
}

def _read_only_mode(mode):
    return type(mode) is str and not any(c in mode for c in "wax+")

# The eight real review CLIs may inspect only these explicitly supplied,
# synthetic, regular local manifests. No arbitrary host file reads, even
# when the attempted read is wrapped in a catch-all exception handler.
_READ_ROOT = os.path.realpath(os.getcwd())
_READ_ALLOWLIST = frozenset(os.path.join(_READ_ROOT, name) for name in (
    "baseline.json", "equal-but-distinct.json", "changed.json",
))

# Never execute untrusted __fspath__ hooks during admission. Exact built-in
# pathlib paths are used by the real CLI fleet; subclass/path proxies HOLD.
_CANONICAL_PATH_TYPE = type(pathlib.Path())

def _allowed_read(path):
    if type(path) is not str and type(path) is not _CANONICAL_PATH_TYPE:
        return False
    try:
        value = os.fspath(path)
        return type(value) is str and os.path.realpath(value) in _READ_ALLOWLIST
    except (TypeError, ValueError, OSError):
        return False

def _no_custom_opener(args, kwargs):
    # open(file, mode, buffering, encoding, errors, newline, closefd, opener)
    # A custom opener may hand back an inherited/unapproved FD even when the
    # supplied filename points to an allowed synthetic manifest.
    return kwargs.get("opener") is None and (len(args) < 6 or args[5] is None)

def checked_open(path, mode="r", *args, **kwargs):
    if (not _read_only_mode(mode) or not _no_custom_opener(args, kwargs)
            or not _allowed_read(path)):
        forbidden()
    return _real_open(path, mode, *args, **kwargs)

def checked_io_open(path, mode="r", *args, **kwargs):
    if (not _read_only_mode(mode) or not _no_custom_opener(args, kwargs)
            or not _allowed_read(path)):
        forbidden()
    return _real_io_open(path, mode, *args, **kwargs)

def checked_path_open(path, mode="r", *args, **kwargs):
    if not _read_only_mode(mode) or not _allowed_read(path):
        forbidden()
    return _real_path_open(path, mode, *args, **kwargs)

def checked_os_open(path, flags, *args, **kwargs):
    deny_mask = (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC
                 | os.O_APPEND | os.O_EXCL | getattr(os, "O_TMPFILE", 0))
    if (type(flags) is not int or flags & deny_mask
            or not _allowed_read(path) or kwargs.get("dir_fd") is not None):
        forbidden()
    fd = _real_os_open(path, flags, *args, **kwargs)
    _ADMITTED_READ_FDS.add(fd)
    return fd

def checked_os_close(fd):
    try:
        return _real_os_close(fd)
    finally:
        _ADMITTED_READ_FDS.discard(fd)

def _guarded_descriptor_read(name, original):
    def guarded(fd, *args, **kwargs):
        if type(fd) is not int or fd not in _ADMITTED_READ_FDS:
            forbidden()
        return original(fd, *args, **kwargs)
    return guarded

def checked_fdopen(fd, mode="r", *args, **kwargs):
    # An inherited FD is unbound to our three reviewed file identities.
    forbidden()

builtins.open = checked_open
io.open = checked_io_open
pathlib.Path.open = checked_path_open
os.open = checked_os_open
os.close = checked_os_close
os.fdopen = checked_fdopen
for _name, _original in _FD_READ_ORIGINALS.items():
    setattr(os, _name, _guarded_descriptor_read(_name, _original))
# A previously admitted numeric fd could be retargeted by dup2/dup3;
# fail hard rather than letting its stale allowlist membership survive.
for _name in ("dup", "dup2", "dup3"):
    if hasattr(os, _name):
        setattr(os, _name, forbidden)
# os.closerange (and optional os.close_range) can bypass checked_os_close
# and leave stale admitted numeric descriptors after the kernel closes them.
for _name in ("closerange", "close_range"):
    if hasattr(os, _name):
        setattr(os, _name, forbidden)
# fcntl duplicates descriptors without invoking os.dup/dup2/dup3. An
# admitted numeric descriptor may not be copied outside our provenance set.
if _fcntl is not None:
    _real_fcntl = _fcntl.fcntl
    _FD_DUP_COMMANDS = frozenset(
        getattr(_fcntl, name) for name in ("F_DUPFD", "F_DUPFD_CLOEXEC")
        if hasattr(_fcntl, name)
    )
    def checked_fcntl(fd, cmd, *args):
        if type(cmd) is not int or cmd in _FD_DUP_COMMANDS:
            forbidden()
        return _real_fcntl(fd, cmd, *args)
    _fcntl.fcntl = checked_fcntl
for name in ("write_text", "write_bytes", "touch", "mkdir",
             "rename", "replace", "unlink", "rmdir", "symlink_to",
             "hardlink_to", "chmod", "lchmod"):
    if hasattr(pathlib.Path, name):
        setattr(pathlib.Path, name, forbidden)
for name in ("mkdir", "makedirs", "rename", "replace", "remove",
             "unlink", "rmdir", "removedirs", "symlink", "link",
             "chmod", "chown", "fchmod", "fchown", "ftruncate",
             "truncate"):
    if hasattr(os, name):
        setattr(os, name, forbidden)
sqlite3.connect = forbidden
sqlite3.dbapi2.connect = forbidden
_sqlite3.connect = forbidden
# Direct inherited-descriptor writes bypass high-level open()/os.open() hooks.
# The CLI may emit through sys.stdout, but must never use descriptor write APIs.
for name in ("write", "writev", "pwrite", "pwritev", "sendfile",
             "copy_file_range", "splice"):
    if hasattr(os, name):
        setattr(os, name, forbidden)
"""


class OfflineReviewCliSocketFleetTests(unittest.TestCase):
    def setUp(self):
        sandbox = tempfile.TemporaryDirectory(prefix="lightup-scope-cli-sockets-")
        self.addCleanup(sandbox.cleanup)
        self.root = Path(sandbox.name)
        (self.root / "sitecustomize.py").write_text(_TRIPWIRE, encoding="utf-8")
        self.env = os.environ.copy()
        self.env["PYTHONPATH"] = os.pathsep.join((
            str(self.root), str(_REPO / "src"), str(_REPO),
        ))
        self.env["PYTHONNOUSERSITE"] = "1"
        self.env.pop("PYTHONPYCACHEPREFIX", None)

        exporter = self.run_script("export_scope_capability_registry_offline.py")
        self.assertEqual(exporter.returncode, 3, exporter.stderr)
        self.assertEqual(exporter.stderr, b"")
        source = json.loads(exporter.stdout)
        self.assertIn("capabilities", source)
        self.original = self.root / "baseline.json"
        self.original.write_bytes(exporter.stdout)
        # Historical snapshots must have distinct physical inode identities.
        # Reusing one path triggers an intentional HOLD even with equal bytes.
        self.equal = self.root / "equal-but-distinct.json"
        self.equal.write_bytes(exporter.stdout)
        source["capabilities"][0]["requires_explicit_activation"] = False
        self.changed = self.root / "changed.json"
        self.changed.write_text(json.dumps(source), encoding="utf-8")

    def run_script(self, script: str, *args: Path | str, stdin: bytes = b""):
        self.assertTrue((_SCRIPTS / script).is_file(), script)
        return subprocess.run(
            [sys.executable, "-B", str(_SCRIPTS / script), *map(str, args)],
            cwd=self.root, env=self.env, input=stdin, capture_output=True,
            check=False, timeout=15,
        )

    def fingerprint(self):
        return {
            str(p.relative_to(self.root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.root.rglob("*") if p.is_file()
        }

    def assert_receipt(self, proc, expected: str, *, markdown: bool = False):
        expected_code = 3 if expected == "REVIEW_ONLY" else 2
        self.assertEqual(proc.returncode, expected_code, proc.stderr)
        self.assertEqual(proc.stderr, b"")
        self.assertTrue(proc.stdout)
        if markdown:
            self.assertIn(expected, proc.stdout.decode("utf-8"))
            self.assertIn("**Authority: NONE.**", proc.stdout.decode("utf-8"))
            self.assertNotIn("execution_enabled: true", proc.stdout.decode("utf-8"))
            return
        self.assertEqual(len(proc.stdout.splitlines()), 1)
        receipt = json.loads(proc.stdout)
        self.assertEqual(receipt["status"], expected)
        for field in _FLAGS:
            self.assertIs(receipt[field], False, field)

    def test_eight_real_offline_entrypoints_never_allocate_sockets(self):
        cases = (
            ("review_scope_capability_registry_offline.py",
             (self.original, self.equal), b"", False),
            ("review_scope_registry_history_offline.py",
             (self.original, self.equal), b"", False),
            ("review_scope_history_against_checkout_offline.py",
             (self.original, self.equal), b"", False),
            ("render_scope_registry_history_offline.py",
             (self.original, self.equal), b"", True),
            ("review_scope_incubation_registry_offline.py", (), b"", False),
            ("review_scope_incubation_catalog_offline.py", (), b"", False),
            ("review_scope_finite_number_offline.py", (),
             b'{"arguments":[["synthetic",1.5]]}', False),
        )
        before = self.fingerprint()
        for script, args, payload, markdown in cases:
            with self.subTest(script=script):
                proc = self.run_script(script, *args, stdin=payload)
                self.assert_receipt(proc, "REVIEW_ONLY", markdown=markdown)
                self.assertEqual(self.fingerprint(), before)
        # The real eighth entrypoint is the exporter invoked in setUp.
        self.assertEqual(self.fingerprint(), before)

    def test_invalid_inputs_hold_without_socket_allocation_or_side_effect(self):
        cases = (
            ("review_scope_capability_registry_offline.py",
             (self.original, self.changed), b"", False),
            ("review_scope_registry_history_offline.py",
             (self.original, self.changed), b"", False),
            ("review_scope_history_against_checkout_offline.py",
             (self.changed, self.changed), b"", False),
            ("render_scope_registry_history_offline.py",
             (self.original, self.changed), b"", True),
            ("review_scope_incubation_registry_offline.py", ("--activate",), b"", False),
            ("review_scope_incubation_catalog_offline.py", ("--activate",), b"", False),
            ("review_scope_finite_number_offline.py", (),
             b'{"arguments":[["synthetic",NaN]]}', False),
        )
        before = self.fingerprint()
        for script, args, payload, markdown in cases:
            with self.subTest(script=script):
                proc = self.run_script(script, *args, stdin=payload)
                self.assert_receipt(proc, "HOLD", markdown=markdown)
                self.assertEqual(self.fingerprint(), before)

    def test_uncatchable_constructor_tripwire_has_real_negative_controls(self):
        # Every negative control must stop before construction even with a
        # catch-all handler. No socket is ever allocated in this test.
        variants = (
            "_socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)",
            "socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)",
            "socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)",
            "socket.socketpair()",
            'socket.create_connection(("127.0.0.1", 9), timeout=0.01)',
            'socket.create_server(("127.0.0.1", 0))',
            "socket.fromfd(0, socket.AF_INET, socket.SOCK_STREAM)",
        )
        before = self.fingerprint()
        for statement in variants:
            with self.subTest(statement=statement):
                program = (
                    "import socket, _socket\n"
                    "try:\n"
                    f"    {statement}\n"
                    "except BaseException:\n"
                    "    pass\n"
                    "print('UNEXPECTED_EXECUTION')\n"
                )
                proc = subprocess.run(
                    [sys.executable, "-B", "-c", program], cwd=self.root,
                    env=self.env, capture_output=True, check=False, timeout=15,
                )
                self.assertEqual(proc.returncode, 92, statement)
                self.assertEqual(proc.stdout, b"")
                self.assertEqual(proc.stderr, b"")
                self.assertEqual(self.fingerprint(), before)


    def test_uncatchable_child_process_and_shell_tripwires(self):
        # This never spawns a child: the pre-import fixture exits immediately.
        variants = (
            'subprocess.Popen(["/bin/true"])',
            'subprocess.run(["/bin/true"], check=False)',
            'os.system("true")',
            'os.popen("true")',
            'os.spawnv(os.P_NOWAIT, "/bin/true", ["/bin/true"])',
            'os.execv("/bin/true", ["/bin/true"])',
            'os.fork()',
            'os.posix_spawn("/bin/true", ["/bin/true"], os.environ)',
        )
        before = self.fingerprint()
        for statement in variants:
            with self.subTest(statement=statement):
                program = (
                    "import os, subprocess\n"
                    "try:\n"
                    f"    {statement}\n"
                    "except BaseException:\n"
                    "    pass\n"
                    "print('UNEXPECTED_EXECUTION')\n"
                )
                proc = subprocess.run(
                    [sys.executable, "-B", "-c", program], cwd=self.root,
                    env=self.env, capture_output=True, check=False, timeout=15,
                )
                self.assertEqual(proc.returncode, 92, statement)
                self.assertEqual(proc.stdout, b"")
                self.assertEqual(proc.stderr, b"")
                self.assertEqual(self.fingerprint(), before)


    def test_uncatchable_filesystem_and_sqlite_mutation_tripwires(self):
        # Each operation is intercepted pre-import, before actual mutation,
        # while the injected child catches BaseException and would fake success
        # under a catchable-only tripwire.
        variants = (
            'open("synthetic.marker", "w").write("secret")',
            'io.open("synthetic.marker", "a").write("secret")',
            'pathlib.Path("synthetic.marker").open("w").write("secret")',
            'pathlib.Path("synthetic.marker").write_text("secret")',
            'pathlib.Path("synthetic.marker").touch()',
            'os.open("synthetic.marker", os.O_CREAT | os.O_WRONLY, 0o600)',
            'os.rename("absent-old", "absent-new")',
            'os.unlink("absent-file")',
            'sqlite3.connect("candidate.sqlite")',
            'sqlite3.dbapi2.connect("candidate.sqlite")',
        )
        before = self.fingerprint()
        for statement in variants:
            with self.subTest(statement=statement):
                program = (
                    "import io, os, pathlib, sqlite3\n"
                    "try:\n"
                    f"    {statement}\n"
                    "except BaseException:\n"
                    "    pass\n"
                    "print('UNEXPECTED_EXECUTION')\n"
                )
                proc = subprocess.run(
                    [sys.executable, "-B", "-c", program], cwd=self.root,
                    env=self.env, capture_output=True, check=False, timeout=15,
                )
                self.assertEqual(proc.returncode, 92, statement)
                self.assertEqual(proc.stdout, b"")
                self.assertEqual(proc.stderr, b"")
                self.assertEqual(self.fingerprint(), before)


    def test_uncatchable_low_level_fd_writes_and_direct_sqlite(self):
        # No write may occur, including attempts made through inherited FDs.
        variants = (
            ("write", 'os.write(1, b"synthetic")'),
            ("writev", 'os.writev(1, [b"synthetic"])'),
            ("pwrite", 'os.pwrite(1, b"synthetic", 0)'),
            ("pwritev", 'os.pwritev(1, [b"synthetic"], 0)'),
            ("sendfile", "os.sendfile(1, 0, 0, 1)"),
            ("copy_file_range", "os.copy_file_range(0, 1, 1)"),
            ("splice", "os.splice(0, 1, 1)"),
            ("direct_sqlite", '_sqlite3.connect("candidate.sqlite")'),
        )
        before = self.fingerprint()
        for api, statement in variants:
            if api != "direct_sqlite" and not hasattr(os, api):
                continue
            with self.subTest(api=api):
                program = (
                    "import os, _sqlite3\n"
                    "try:\n"
                    f"    {statement}\n"
                    "except BaseException:\n"
                    "    pass\n"
                    "print('UNEXPECTED_EXECUTION')\n"
                )
                proc = subprocess.run(
                    [sys.executable, "-B", "-c", program], cwd=self.root,
                    env=self.env, capture_output=True, check=False, timeout=15,
                )
                self.assertEqual(proc.returncode, 92, statement)
                self.assertEqual(proc.stdout, b"")
                self.assertEqual(proc.stderr, b"")
                self.assertEqual(self.fingerprint(), before)


    def test_uncatchable_dns_resolver_attempts_without_socket_creation(self):
        # These are intercepted BEFORE any libc/DNS resolver runs. A
        # catchable denial could be swallowed into a false REVIEW_ONLY.
        variants = (
            ('socket', 'getaddrinfo', 'socket.getaddrinfo("synthetic.invalid", 443)'),
            ('socket', 'gethostbyname', 'socket.gethostbyname("synthetic.invalid")'),
            ('socket', 'gethostbyname_ex', 'socket.gethostbyname_ex("synthetic.invalid")'),
            ('socket', 'gethostbyaddr', 'socket.gethostbyaddr("127.0.0.1")'),
            ('socket', 'getnameinfo', 'socket.getnameinfo(("127.0.0.1", 443), 0)'),
            ('socket', 'getfqdn', 'socket.getfqdn("synthetic.invalid")'),
            ('_socket', 'getaddrinfo', '_socket.getaddrinfo("synthetic.invalid", 443)'),
            ('_socket', 'gethostbyname', '_socket.gethostbyname("synthetic.invalid")'),
            ('_socket', 'gethostbyname_ex', '_socket.gethostbyname_ex("synthetic.invalid")'),
            ('_socket', 'gethostbyaddr', '_socket.gethostbyaddr("127.0.0.1")'),
            ('_socket', 'getnameinfo', '_socket.getnameinfo(("127.0.0.1", 443), 0)'),
        )
        before = self.fingerprint()
        for module, function, statement in variants:
            if not hasattr(__import__(module), function):
                continue
            with self.subTest(module=module, function=function):
                program = (
                    "import socket, _socket\n"
                    "try:\n"
                    f"    {statement}\n"
                    "except BaseException:\n"
                    "    pass\n"
                    "print('UNEXPECTED_EXECUTION')\n"
                )
                proc = subprocess.run(
                    [sys.executable, "-B", "-c", program], cwd=self.root,
                    env=self.env, capture_output=True, check=False, timeout=15,
                )
                self.assertEqual(proc.returncode, 92, statement)
                self.assertEqual(proc.stdout, b"")
                self.assertEqual(proc.stderr, b"")
                self.assertEqual(self.fingerprint(), before)


    def test_uncatchable_out_of_scope_file_reads_and_path_aliases(self):
        # All attempted reads must abort before accessing the local decoy.
        # No real host-private files are used or opened in test children.
        decoy = self.root / "synthetic-private.txt"
        decoy.write_text("synthetic-secret-never-open", encoding="utf-8")
        variants = (
            'open("synthetic-private.txt", "r").read()',
            'io.open("synthetic-private.txt", "rb").read()',
            'pathlib.Path("synthetic-private.txt").open("r").read()',
            'pathlib.Path("synthetic-private.txt").read_text()',
            'os.open("synthetic-private.txt", os.O_RDONLY)',
            'os.open("./equal-but-distinct.json/../synthetic-private.txt", os.O_RDONLY)',
            'os.fdopen(0, "r").read()',
        )
        before = self.fingerprint()
        for statement in variants:
            with self.subTest(statement=statement):
                program = (
                    "import io, os, pathlib\n"
                    "try:\n"
                    f"    {statement}\n"
                    "except BaseException:\n"
                    "    pass\n"
                    "print('UNEXPECTED_EXECUTION')\n"
                )
                proc = subprocess.run(
                    [sys.executable, "-B", "-c", program], cwd=self.root,
                    env=self.env, capture_output=True, check=False, timeout=15,
                )
                self.assertEqual(proc.returncode, 92, statement)
                self.assertEqual(proc.stdout, b"")
                self.assertEqual(proc.stderr, b"")
                self.assertEqual(self.fingerprint(), before)


    def test_uncatchable_inherited_descriptor_reads_and_rebindings(self):
        # Untrusted numeric descriptors were never admitted by guarded
        # os.open(). Native fd reads and range-closes must be rejected
        # before observation, mutation or stale numeric fd provenance.
        variants = (
            ("read", "os.read(0, 1)"),
            ("readv", "os.readv(0, [bytearray(1)])"),
            ("pread", "os.pread(0, 1, 0)"),
            ("preadv", "os.preadv(0, [bytearray(1)], 0)"),
            ("dup", "os.dup(0)"),
            ("dup2", "os.dup2(0, 7)"),
            ("dup3", "os.dup3(0, 7, 0)"),
            ("closerange", "os.closerange(0, 1)"),
            ("close_range", "os.close_range(0, 1)"),
        )
        before = self.fingerprint()
        for api, statement in variants:
            if not hasattr(os, api):
                continue
            with self.subTest(api=api):
                program = (
                    "import os\n"
                    "try:\n"
                    f"    {statement}\n"
                    "except BaseException:\n"
                    "    pass\n"
                    "print('UNEXPECTED_EXECUTION')\n"
                )
                proc = subprocess.run(
                    [sys.executable, "-B", "-c", program], cwd=self.root,
                    env=self.env, capture_output=True, check=False, timeout=15,
                )
                self.assertEqual(proc.returncode, 92, statement)
                self.assertEqual(proc.stdout, b"")
                self.assertEqual(proc.stderr, b"")
                self.assertEqual(self.fingerprint(), before)


    def test_uncatchable_fcntl_descriptor_duplication(self):
        # fcntl(F_DUPFD*) does not pass through os.dup*. All attempted
        # duplications are intercepted before native fcntl sees a descriptor.
        try:
            import fcntl
        except ImportError:
            self.skipTest("fcntl is not available on this platform")
        commands = tuple(
            name for name in ("F_DUPFD", "F_DUPFD_CLOEXEC")
            if hasattr(fcntl, name)
        )
        self.assertTrue(commands, "expected a supported fcntl duplicate command")
        before = self.fingerprint()
        for command in commands:
            with self.subTest(command=command):
                program = (
                    "import fcntl\n"
                    "try:\n"
                    f"    fcntl.fcntl(0, fcntl.{command}, 7)\n"
                    "except BaseException:\n"
                    "    pass\n"
                    "print('UNEXPECTED_EXECUTION')\n"
                )
                proc = subprocess.run(
                    [sys.executable, "-B", "-c", program], cwd=self.root,
                    env=self.env, capture_output=True, check=False, timeout=15,
                )
                self.assertEqual(proc.returncode, 92, command)
                self.assertEqual(proc.stdout, b"")
                self.assertEqual(proc.stderr, b"")
                self.assertEqual(self.fingerprint(), before)


    def test_uncatchable_custom_openers_and_user_pathlike_callbacks(self):
        # Every opener could return inherited stdin instead of the requested
        # manifest FD; custom __fspath__ can execute code during admission.
        # No callback must actually run, including under broad BaseException.
        variants = (
            ('builtin_keyword',
             'open("baseline.json", "rb", opener=lambda _p, _f: 0).read(1)'),
            ('builtin_positional',
             'open("baseline.json", "rb", -1, None, None, None, True, '
             'lambda _p, _f: 0).read(1)'),
            ('io_keyword',
             'io.open("baseline.json", "rb", opener=lambda _p, _f: 0).read(1)'),
            ('io_positional',
             'io.open("baseline.json", "rb", -1, None, None, None, True, '
             'lambda _p, _f: 0).read(1)'),
            ('builtin_pathlike', 'open(SyntheticPath(), "rb").read(1)'),
            ('io_pathlike', 'io.open(SyntheticPath(), "rb").read(1)'),
            ('os_pathlike', 'os.open(SyntheticPath(), os.O_RDONLY)'),
        )
        before = self.fingerprint()
        for label, statement in variants:
            with self.subTest(label=label):
                program = (
                    "import io, os\n"
                    "class SyntheticPath:\n"
                    "    def __fspath__(self):\n"
                    "        print('CALLBACK_RAN')\n"
                    "        return 'baseline.json'\n"
                    "try:\n"
                    f"    {statement}\n"
                    "except BaseException:\n"
                    "    pass\n"
                    "print('FALSE_REVIEW_ONLY')\n"
                )
                proc = subprocess.run(
                    [sys.executable, "-B", "-c", program], cwd=self.root,
                    env=self.env, capture_output=True, check=False, timeout=15,
                )
                self.assertEqual(proc.returncode, 92, label)
                self.assertEqual(proc.stdout, b"")
                self.assertEqual(proc.stderr, b"")
                self.assertEqual(self.fingerprint(), before)


    def test_uncatchable_memory_map_creation_inherited_fd(self):
        # Mapping an inherited descriptor could expose its contents without
        # os.read()/os.open(); a direct anonymous mapping must also be denied.
        attempts = (
            ("stdin_readonly", "mmap.mmap(0, 1, access=mmap.ACCESS_READ)"),
            ("stdin_default", "mmap.mmap(0, 1)"),
            ("anonymous_mapping", "mmap.mmap(-1, 4096)"),
        )
        before = self.fingerprint()
        for label, statement in attempts:
            with self.subTest(label=label):
                program = (
                    "import mmap\n"
                    "try:\n"
                    f"    {statement}\n"
                    "except BaseException:\n"
                    "    pass\n"
                    "print('FALSE_REVIEW_ONLY')\n"
                )
                proc = subprocess.run(
                    [sys.executable, "-B", "-c", program], cwd=self.root,
                    env=self.env, capture_output=True, check=False, timeout=15,
                )
                self.assertEqual(proc.returncode, 92, label)
                self.assertEqual(proc.stdout, b"")
                self.assertEqual(proc.stderr, b"")
                self.assertEqual(self.fingerprint(), before)


if __name__ == "__main__":
    unittest.main()
