#!/usr/bin/env python3
"""Compose original, unmodified offline remediation suite + PRIVATE recovery companion."""
from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import stat
import subprocess
import tempfile
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
# When this companion is copied into an installed standalone PRIVATE suite,
# its original integrated native installer lives in the sibling original-suite.
# Never silently replace it with an external tool or skip original admission.
def native_installer():
    candidates = (
        ROOT / "remediation-integrated-workspace" / "install.py",
        ROOT / "original-suite" / "remediation-integrated-workspace" / "install.py",
    )
    for candidate in candidates:
        if candidate.is_file() and not candidate.is_symlink():
            return candidate
    raise Hold("original native installer not present in this source/installed bundle")
COMPANION_FILES = (
    "vault.py", "browser.js", "index.html", "standalone.html",
    "build_browser.py", "integrate.py", "README.md",
)
MAX_ASSET = 512_000
FLAGS = {"consent_verified": False, "authorized": False,
         "remediation_verified": False, "release_approved": False}
WARNING = ("PRIVATE HUMAN-only original LightUp offline remediation + recovery software. "
           "INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD. No verified evidence, "
           "client/operator consent, grant, remediation, release or HUMAN GO.")

class Hold(Exception):
    pass

def insist(value, message):
    if not value:
        raise Hold(message)

def sha(data: bytes):
    return hashlib.sha256(data).hexdigest()

def local_html_integrity(html: bytes, js: bytes):
    """The shipped one-file browser must include *exact* source bytes and matching CSP."""
    import base64
    try:
        decoded = html.decode("utf-8", "strict")
        script = js.decode("utf-8", "strict")
    except UnicodeError as error:
        raise Hold("invalid shipped browser encoding") from error
    digest = base64.b64encode(hashlib.sha256(js).digest()).decode("ascii")
    expected_script = "<script>" + script + "</script>"
    insist(decoded.count(expected_script) == 1,
           "portable PRIVATE browser does not match exact independently shipped JS")
    insist(decoded.count("script-src 'sha256-" + digest + "'") == 1,
           "portable PRIVATE browser CSP source digest does not match")
    insist('connect-src \'none\'' in decoded and
           '<script src="./browser.js"' not in decoded,
           "portable PRIVATE browser requires scriptless external dependency policy")

def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")

def private_directory(folder: Path):
    insist(folder.is_absolute() and not folder.is_symlink() and folder.is_dir(),
           "parent must be existing absolute ordinary directory")
    info = folder.stat(follow_symlinks=False)
    insist(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077,
           "parent must be owner-private 0700")
    insist(folder == folder.resolve(strict=True), "parent symlinks are not accepted")

def read_asset(name):
    original = HERE / name
    # Read the file descriptor itself, not a pathname after a separate lstat:
    # replacing a source between admission and copy must never silently succeed.
    descriptor = os.open(original, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        before = os.fstat(descriptor)
        insist(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
               and before.st_size <= MAX_ASSET,
               "original companion source missing or unsafe")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_ASSET + 1)
        after = os.fstat(descriptor)
        insist((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) ==
               (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
               and len(raw) == before.st_size, "companion source changed during copy")
        return raw
    finally:
        os.close(descriptor)

def private_file(destination: Path, data: bytes):
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                         getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
    finally:
        os.close(descriptor)

def publish_new(source: Path, destination: Path):
    try:
        function = ctypes.CDLL(None, use_errno=True).renameat2
    except (OSError, AttributeError) as error:
        raise Hold("Linux atomic no-replace publication not supported") from error
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                         ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(-100, os.fsencode(source), -100, os.fsencode(destination), 1):
        issue = ctypes.get_errno()
        if issue in (errno.EEXIST, errno.ENOTEMPTY):
            raise Hold("output appeared concurrently; never overwrite")
        raise Hold("atomic private suite publication rejected")

def portal():
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp · PRIVATE offline HUMAN launch · DRAFT/HOLD</title>
<style>body{background:#101d2c;color:#f1f6fd;font:1rem system-ui;max-width:760px;margin:3rem auto;padding:1rem}
a{color:#a0ddff}section{border:1px solid #50637b;border-radius:10px;padding:1.3rem;margin:1rem 0}
h1{font-size:1.6rem}p{line-height:1.55}.hold{color:#ffd99e;font-weight:bold}</style></head><body>
<h1>LightUp · PRIVATE offline HUMAN suite</h1>
<p class="hold">INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Neither application authenticates source authority, consent, permissions, release or verified remediation.</p>
<section><h2>Original integrated evidence-remediation workroom</h2>
<p>Source-owned offline evidence and HUMAN-only workspaces, installed unmodified with the original native LightUp source-lock.</p>
<p><a href="./original-suite/index.html">Open original integrated PRIVATE suite</a></p></section>
<section><h2>PRIVATE encrypted recovery desk</h2>
<p>Independently decrypt and compare selected local HUMAN backups, preview and explicitly recover minimum-necessary files or encrypt a fresh selected subset.</p>
<p><a href="./private-recovery/standalone.html">Open private recovery desk</a></p></section>
<p>Both apps are local only. Select PRIVATELY owned file material on a trusted device; no network and no automated transfers. Do not copy original evidence to recipients without separate valid disclosure authorization.</p>
</body></html>""").encode("utf-8")

def create(dest: Path):
    insist(dest.is_absolute() and not dest.exists() and not dest.is_symlink(),
           "choose a new absolute suite destination")
    private_directory(dest.parent)
    insist(ROOT not in dest.parents and dest != ROOT,
           "suite destination must be outside the checkout")
    original_installer = native_installer()
    stage = dest.parent / (".lightup-composed-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        native_destination = stage / "original-suite"
        run = subprocess.run([sys.executable, str(original_installer), "build",
                              "--output-dir", str(native_destination)],
                             cwd=str(ROOT), shell=False, timeout=180,
                             stdin=subprocess.DEVNULL, capture_output=True, text=True)
        insist(run.returncode == 2 and native_destination.is_dir(),
               "original pinned native source-only installation HOLD; no fallback or bypass")
        recovery = stage / "private-recovery"
        recovery.mkdir(mode=0o700)
        sources = {name: read_asset(name) for name in COMPANION_FILES}
        local_html_integrity(sources["standalone.html"], sources["browser.js"])
        inventory = {}
        for name in COMPANION_FILES:
            source = sources[name]
            private_file(recovery / name, source)
            inventory["private-recovery/" + name] = {"bytes": len(source), "sha256": sha(source)}
        for relative in ("source-lock.json", "manifest.json"):
            native = native_destination / relative
            if native.exists() and native.is_file():
                raw = native.read_bytes()
                inventory["original-suite/" + relative] = {
                    "bytes": len(raw), "sha256": sha(raw)}
        home = portal()
        private_file(stage / "START-HERE.html", home)
        inventory["START-HERE.html"] = {"bytes": len(home), "sha256": sha(home)}
        receipt = canonical({"kind": "lightup.private_human_recovery_companion_v1",
                             "authority": FLAGS, "warning": WARNING, "files": inventory})
        private_file(stage / "HOLD-SOURCE-INVENTORY.json", receipt)
        publish_new(stage, dest)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    print(f"REVIEW_ONLY: complete original + PRIVATE recovery portal built in {dest}")
    print(f"Open locally: {dest / 'START-HERE.html'}")
    print("Original native source-owner workroom untouched. No permission, source proof or release.")
    return 2

def read_private_asset(path: Path, max_bytes: int = MAX_ASSET):
    """No symlink/hardlink/foreign-readable input during PRIVATE local reopening."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        st = os.fstat(fd)
        insist(stat.S_ISREG(st.st_mode) and st.st_nlink == 1
               and st.st_uid == os.getuid() and not st.st_mode & 0o077
               and st.st_size <= max_bytes, "installed asset is not an owner-private single-link file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(max_bytes + 1)
        insist(len(data) == st.st_size, "installed asset size changed")
        return data
    finally:
        os.close(fd)


def parse_inventory(raw: bytes):
    def unique(pairs):
        obj = {}
        for key, value in pairs:
            insist(key not in obj, "duplicate PRIVATE inventory keys")
            obj[key] = value
        return obj
    try:
        obj = json.loads(raw.decode("ascii", "strict"), object_pairs_hook=unique,
                         parse_constant=lambda _: (_ for _ in ()).throw(Hold("invalid number")))
    except (ValueError, UnicodeError, TypeError) as error:
        raise Hold("PRIVATE installed source inventory could not be decoded") from error
    insist(type(obj) is dict and canonical(obj) == raw
           and set(obj) == {"kind", "authority", "warning", "files"}
           and obj["kind"] == "lightup.private_human_recovery_companion_v1"
           and obj["authority"] == FLAGS and obj["warning"] == WARNING,
           "PRIVATE inventory is noncanonical or claims unsupported authority")
    files = obj["files"]
    expected = {"private-recovery/" + name for name in COMPANION_FILES}
    expected.add("START-HERE.html")
    optional = {"original-suite/source-lock.json", "original-suite/manifest.json"}
    insist(type(files) is dict and expected.issubset(files)
           and set(files).issubset(expected | optional), "unexpected or missing inventory entries")
    for key, digest in files.items():
        insist(type(digest) is dict and set(digest) == {"bytes", "sha256"}
               and type(digest["bytes"]) is int and 0 <= digest["bytes"] <= MAX_ASSET
               and type(digest["sha256"]) is str and len(digest["sha256"]) == 64
               and all(ch in "0123456789abcdef" for ch in digest["sha256"]),
               "malformed PRIVATE source digest entry")
    return files


def native_inspect_installed(workspace: Path):
    """Recreate ONLY original owner source layout for exact native inspector.

    The original unmodified install.py expects source-lock.json next to its
    sources, whereas its installed release stores that lock at suite root.
    Copy installed source-only software to disposable owner-private space,
    never modifying the original installed package or its source code.
    """
    original = workspace / "original-suite"
    private_directory(original)
    module = original / "remediation-integrated-workspace"
    private_directory(module)
    with tempfile.TemporaryDirectory(prefix=".lightup-original-inspect-", dir=workspace.parent) as staged:
        root = Path(staged) / "read-only-original-source"
        root.mkdir(mode=0o700)
        dest = root / "remediation-integrated-workspace"
        dest.mkdir(mode=0o700)
        children = list(module.iterdir())
        insist(1 <= len(children) <= 64, "original native inspector source module count invalid")
        original_names = set()
        for member in children:
            insist(member.name not in (".", "..") and not member.name.startswith(".")
                   and len(member.name) <= 160 and
                   member.suffix in (".py", ".md", ".html", ".js", ".css"),
                   "unknown original inspector source module path")
            private_file(dest / member.name, read_private_asset(member, max_bytes=4_000_000))
            original_names.add(member.name)
        insist({"install.py", "operator_console.py", "landing.py"}.issubset(original_names),
               "missing original native inspector or renderer")
        # Exactly the original package's own manifest-bound source lock is used:
        # no custom lock, no synthetic trusted digest or runtime code patch.
        original_lock = read_private_asset(original / "source-lock.json")
        private_file(dest / "source-lock.json", original_lock)
        run = subprocess.run(
            [sys.executable, str(dest / "install.py"), "inspect", "--workspace", str(original)],
            cwd=str(root), shell=False, timeout=180, stdin=subprocess.DEVNULL,
            capture_output=True, text=True)
        insist(run.returncode == 2,
               "the unchanged original native source-owner inspector rejected the installed workroom")


def inspect(workspace: Path):
    private_directory(workspace)
    insist(set(p.name for p in workspace.iterdir()) ==
           {"original-suite", "private-recovery", "START-HERE.html", "HOLD-SOURCE-INVENTORY.json"},
           "unexpected top-level installed software member")
    recovery = workspace / "private-recovery"
    private_directory(recovery)
    insist(set(p.name for p in recovery.iterdir()) == set(COMPANION_FILES),
           "installed private recovery software member drift")
    record = parse_inventory(read_private_asset(workspace / "HOLD-SOURCE-INVENTORY.json"))
    for relative, declared in record.items():
        path = workspace.joinpath(*relative.split("/"))
        raw = read_private_asset(path)
        insist(len(raw) == declared["bytes"] and sha(raw) == declared["sha256"],
               "installed source byte identity does not match PRIVATE inventory")
    insist(read_private_asset(workspace / "START-HERE.html") == portal(),
           "scriptless local launcher differs from original fixed template")
    local_html_integrity(read_private_asset(recovery / "standalone.html"),
                         read_private_asset(recovery / "browser.js"))
    # Execute the ORIGINAL unchanged native inspector from installed original
    # software with its exact original source lock, even after safe offline relocation.
    # Failure is always HOLD: local recovery manifests cannot override source owner.
    native_inspect_installed(workspace)
    print("REVIEW_ONLY: installed original native suite and encrypted recovery software agree")
    print("Local unsigned file digests do not prove sender, source consent, remediation or release.")
    return 2


def main():
    parser = argparse.ArgumentParser(
        description="Build/reopen original+PRIVATE recovery software with unchanged original source lock; DRAFT/HOLD")
    parser.add_argument("command", nargs="?", choices=["build", "inspect"], default="build")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--workspace", type=Path)
    args = parser.parse_args()
    if args.command == "inspect" and (args.workspace is None or args.output_dir is not None):
        parser.error("inspect requires --workspace only")
    if args.command == "build" and (args.output_dir is None or args.workspace is not None):
        parser.error("build requires --output-dir only")
    try:
        return inspect(args.workspace) if args.command == "inspect" else create(args.output_dir)
    except (Hold, OSError, ValueError, subprocess.TimeoutExpired) as err:
        print("HOLD:", str(err), file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
