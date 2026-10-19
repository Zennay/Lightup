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

### One-command private packet folder

Instead of repeating 12 input flags, create a dedicated 0700 owner-private folder containing **only** consecutively named native exporter files packet-01.json, packet-02.json, ... packet-12.json (no gaps, symlinks, extra hidden files, or any other directory contents). Every member must still be an authentic original-export-shaped 0600 counts-only JSON, not a client evidence file.

    mkdir -m 700 /home/operator/private-lightup/native-count-packets
    # Place the existing original native counts exports at packet-01.json, etc.
    python3 remediation-portfolio/portfolio.py \
      --packet-dir /home/operator/private-lightup/native-count-packets \
      --output-dir /home/operator/private-lightup/complete-human-portfolio

This path is purely **local**, does no file discovery outside the explicitly selected directory, reads all native counters, rejects an unexpected name before creating the output, and inherits whole-batch all-or-nothing admission. It never asks for or opens an original encrypted source key.

The CLI validates **all inputs before writing**, creates an owner-private staging folder and publishes a new directory exclusively through Linux renameat2 no-replace. Outputs: index.html, summary.json, counts.csv and human-followup.txt, all 0600 within a 0700 directory. The standalone HUMAN follow-up brief prioritises pending source-owner questions, unassigned planning slots and dated reviews without revealing their identities. Open index.html locally: scriptless, static, offline CSP-pinned dashboard with packet workload and per-stage HUMAN planning. No JS, fetch, scripts, remote assets or private source paths. The browser also shows the HUMAN follow-up recommendations; it does not perform or authorize any action.

Inboxes have no HUMAN planning stage data. Their stage cells are blank (“not provided”), not zero. Summations are **packet appearances**, never unique findings or clients: two files may describe exactly the same material, and local HUMAN “answered” never means a verified fix. A file can be syntactically admitted yet factually false or deceptive; there is NO cryptographic source truth asserted.

Even aggregate small-cell counts might identify people; outputs stay PRIVATE. A human operator must decide on any separate onward disclosure.

## Original owner and release boundaries

This PR does not modify actively owned original remediation, source, domain, auth, consent, scanner, CI or grant paths. There is no merge to main or deployment in INCUBATE DRAFT/HOLD. Original hosted and permanent named VPS exact-head CI, independent source-owner/security/privacy/browser review, #177/#182/#829, authentic current separate client and operator consent including action-time revocation, and explicit HUMAN GO remain mandatory. No new QA, testsuites or regression runs.

## New: source-free two-snapshot HUMAN comparison

Compare any two **complete** private portfolio folders created by portfolio.py. Both complete folders are independently re-admitted: the comparison reconstructs the original source-free count and HUMAN summary, byte-exact static HTML, counts CSV and HUMAN follow-up brief. A tampered or partial input folder HOLDS the whole comparison before any new output. It does not re-open original evidence or assert authentic source ownership.

    python3 remediation-portfolio/compare.py \
      --earlier /home/operator/private-lightup/portfolio-previous \
      --later /home/operator/private-lightup/portfolio-current \
      --output-dir /home/operator/private-lightup/comparison-new

A fresh exclusive 0700 directory contains 0600 index.html, comparison.csv, comparison.json and human-interpretation.txt, all identity-free numeric packet appearances. The scriptless static browser displays the left/right count difference and explicitly warns that different sets of packets, missing inputs and duplicate source-free workrooms **make any apparent decrease ambiguous**. There is deliberately no case matching, remediation-success claim, auth, target action or network request. Counts-only comparison is useful for local HUMAN workload discussion, not outcome measurement.
