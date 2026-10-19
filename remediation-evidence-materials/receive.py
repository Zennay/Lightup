#!/usr/bin/env python3
"""One-command PRIVATE material receipt plus encrypted HUMAN return.

Both actions use ONE authentic original-current READ, ONE matching encrypted
HUMAN source and ONE original encrypted material transfer. No executable
evidence, target, scan, grant, consent, retest or original app Apply.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import reply
import transfer


def main(argv: list[str] | None = None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("db","email","client-id","engagement-id"):
        p.add_argument("--"+name,required=True)
    p.add_argument("--human",type=Path,required=True,
                   help="Current original encrypted Unified HUMAN .ltv source")
    p.add_argument("--transfer",type=Path,required=True,
                   help="Original PRIVATE encrypted evidence material transfer .ltv")
    p.add_argument("--output-dir",type=Path,required=True,
                   help="NEW owner-private 0700 directory for neutral local files")
    p.add_argument("--reply-output",type=Path,required=True,
                   help="NEW 0600 encrypted PRIVATE HUMAN status return .ltv")
    p.add_argument("--ack-private-material",action="store_true")
    opts=p.parse_args(argv)
    created_reply=None
    try:
        if not opts.ack_private_material or not sys.stdin.isatty():
            raise ValueError("Interactive HUMAN agreement and private terminal required.")
        folder=opts.output_dir.expanduser().absolute()
        reply_path=opts.reply_output.expanduser().absolute()
        if (reply_path.suffix.lower() != ".ltv"
                or reply_path.parent == folder
                or reply_path in {opts.human.expanduser().absolute(),
                                  opts.transfer.expanduser().absolute()}):
            raise ValueError("NEW separate PRIVATE reply outside extracted material folder required.")
        vault=transfer.ORIGINAL._vault()
        envelope,packet,indexed,original_key_hash=reply._source(opts,vault)
        plain,files,material_password=reply._transfer(opts,vault,envelope,packet)
        # No changes yet. All private bytes, native source identities and HUMAN
        # item bounds have been fully admitted from the existing original.
        dest=transfer.private_directory(folder)
        # Capture explicit HUMAN choices before creating any private output.
        rows=reply._human_rows(files)
        reply.seal_reply(reply_path,vault,envelope,packet,plain,files,
                         material_password,original_key_hash,rows)
        created_reply=reply_path
        try:
            # Original exclusive 0600 publication with its own all-or-nothing
            # cleanup; material names are neutral, never untrusted source paths.
            transfer.unpack_parsed(dest,vault,packet,files)
        except BaseException:
            # The reply is new to this invocation; never leave a misleading
            # "received" encrypted ack when local extraction was not published.
            created_reply.unlink(missing_ok=True)
            created_reply=None
            raise
        created_reply=None
        print("PRIVATE one-command receipt completed: encrypted HUMAN reply and NEW 0700 material folder.")
        print("Both outputs are owner-private; no plaintext selector or intermediary stored.")
        print("No original HUMAN Apply, verified remediation, retest, assessment consent or grant.")
        return 0
    except Exception:
        print("HUMAN HOLD: One-command PRIVATE receipt did not complete. "
              "Previously existing original vault and evidence are unchanged.",file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
