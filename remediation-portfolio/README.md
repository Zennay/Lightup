# PRIVATE HUMAN workload portfolio

LightUp · INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.

This independent, offline add-only product brings 1–12 existing native PRIVATE HUMAN anonymous-count exports into one human-readable packet-level workload view. It never reads real evidence, original files, client names, hashes, dates, owner names, or secrets. The output is PRIVATE and makes no claim of unique cases, remediation, assessment authority, or source authenticity.

## Compatible original producers

The contract comes from [original held PR #1662](https://github.com/Zennay/Lightup/pull/1662) at inspected original HEAD 2d537024ae2c7347578e570a79abc7dd92153731 (the original owner can change independently). Run the original source-owner's inbox.py export-counts or workroom_control.py export-counts first. Those original tools verify their OWN native private workroom and export count JSON. This standalone portfolio imports ONLY those count files; it has no access to the original HMAC key and does not reproduce original source verification.

Native formats: lightup.anonymous_human_inbox_counts_only v1 and lightup.private_human_workroom_anonymous_counts v1. Strict exact schema, 12 all-false authority flags, 1–12 original source-free slots, bounded counts, stage accounting, no extra or duplicate JSON keys. Any rejected input HOLDS the entire collection.

## Offline operator workflow

Linux/Python 3.11+, no external packages or network required. Make an owner-private 0700 absolute directory. The original counts files must be 0600 owner-only inside 0700 parent directories. The destination must NOT exist:

    mkdir -m 700 /home/operator/private-lightup
    python3 remediation-portfolio/portfolio.py \
      --input /home/operator/private-lightup/counts-01.json \
      --input /home/operator/private-lightup/counts-02.json \
      --output-dir /home/operator/private-lightup/portfolio-20261019

The CLI validates **all inputs before writing**, creates an owner-private staging folder and publishes a new directory exclusively through Linux renameat2 no-replace. Outputs: index.html, summary.json, counts.csv, all 0600 within 0700 directory. Open index.html locally: scriptless, static, offline CSP-pinned dashboard with packet workload and per-stage HUMAN planning. No JS, fetch, scripts, remote assets or paths.

Inboxes have no HUMAN planning stage data. Their stage cells are blank (“not provided”), not zero. Summations are **packet appearances**, never unique findings or clients: two files may describe exactly the same material, and local HUMAN “answered” never means a verified fix. A file can be syntactically admitted yet factually false or deceptive; there is NO cryptographic source truth asserted.

Even aggregate small-cell counts might identify people; outputs stay PRIVATE. A human operator must decide on any separate onward disclosure.

## Original owner and release boundaries

This PR does not modify actively owned original remediation, source, domain, auth, consent, scanner, CI or grant paths. There is no merge to main or deployment in INCUBATE DRAFT/HOLD. Original hosted and permanent named VPS exact-head CI, independent source-owner/security/privacy/browser review, #177/#182/#829, authentic current separate client and operator consent including action-time revocation, and explicit HUMAN GO remain mandatory. No new QA, testsuites or regression runs.
