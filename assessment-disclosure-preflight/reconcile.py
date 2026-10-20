"""Offline PRIVATE two-reviewer HUMAN reconciliation for an unsigned LightUp receipt.

New-only product companion. No evidence re-interpretation, grant, scan, target
network, consent, identity proof, automatic agreement or release authority.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import hmac
import html
import io
import os
import sys

from human_review import (
    FIELDS, Hold, admitted_answers, human_counts, publish, publish_many, receipt_content, require, safe_note,
    source_bytes,
)

CHOICES = ("HOLD", "A", "B")
DECISION_FIELDS = (
    "receipt_sha256", "review_a_sha256", "review_b_sha256",
    "ordinal", "source_kind", "choice", "human_reason",
)
DECISIONS = "PRIVATE-reconcile-decisions.csv"
INTERACTIVE_DECISIONS = "PRIVATE-reconcile-interactive-decisions.csv"
COMPARISON = "PRIVATE-reconcile-comparison.html"
RECONCILED = "PRIVATE-reconciled-human.csv"
OUTCOME = "PRIVATE-reconciled-report.html"
COUNTS = "PRIVATE-reconciled-counts.csv"
SEALED_RESULT = "PRIVATE-reconciled-human.luhb"


def load_review(args: argparse.Namespace, role: str, raw_receipt: bytes,
                digest: str, originals: list[dict]) -> tuple[bytes, list[dict]]:
    """Both encrypted forms decrypt strictly in memory, never publish plaintext."""
    csv_path = getattr(args, role + "_csv")
    vault_path = getattr(args, role + "_vault")
    bundle_path = getattr(args, role + "_bundle")
    if csv_path is not None:
        raw = source_bytes(csv_path)
    else:
        try:
            from vault_native import VaultHold, decrypt_bundle, decrypt_vault
            if vault_path is not None:
                raw = decrypt_vault(vault_path, digest)
            else:
                bundled_receipt, raw = decrypt_bundle(bundle_path)
                require(hmac.compare_digest(bundled_receipt, raw_receipt))
        except (ImportError, VaultHold):
            raise Hold("HOLD: PRIVATE encrypted HUMAN review rejected") from None
    require(type(raw) is bytes and 0 < len(raw) <= 256 * 1024)
    admitted = admitted_answers(raw, digest, originals)
    return raw, admitted


def load_context(args: argparse.Namespace) -> tuple[bytes, str, list[dict], str, list[dict], str, list[dict]]:
    original_bytes = source_bytes(args.receipt)
    digest, originals = receipt_content(original_bytes)
    a_raw, a = load_review(args, "a", original_bytes, digest, originals)
    b_raw, b = load_review(args, "b", original_bytes, digest, originals)
    # Bind choices to actual independently submitted plaintext CSV content,
    # regardless of whether a reviewer supplied ciphertext or a plaintext file.
    a_sha = hashlib.sha256(a_raw).hexdigest()
    b_sha = hashlib.sha256(b_raw).hexdigest()
    return original_bytes, digest, originals, a_sha, a, b_sha, b


def decision_template(digest: str, originals: list[dict], a_sha: str, b_sha: str) -> str:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(DECISION_FIELDS)
    for item in originals:
        writer.writerow((digest, a_sha, b_sha, item["ordinal"], item["kind"], "HOLD", ""))
    return stream.getvalue()


def interactive_decisions(digest: str, originals: list[dict],
                          a_sha: str, a: list[dict],
                          b_sha: str, b: list[dict]) -> str:
    """HUMAN-only trusted terminal decision entry; never select automatically."""
    require(sys.stdin.isatty() and sys.stdout.isatty())
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(DECISION_FIELDS)
    print("PRIVATE HUMAN review only. Use a trusted terminal without recording.")
    print("Open the PRIVATE comparison HTML locally before selecting. No grant/GO.")
    for original, left, right in zip(originals, a, b):
        changed = any(left[key] != right[key] for key in
                      ("stage", "question", "next_action"))
        print(f"Ordinal {original['ordinal']}: {original['kind']}")
        print(f"A HUMAN stage: {left['stage']} | B HUMAN stage: {right['stage']}")
        print("HUMAN text differs" if changed else
              "Same HUMAN text (NOT authenticated or verified)")
        try:
            choice = input("Choose HOLD (default), A or B; Q cancels entire desk: ").strip().upper()
            if choice == "Q":
                raise Hold("HOLD: HUMAN cancelled")
            choice = choice or "HOLD"
            require(choice in CHOICES)
            reason = input("PRIVATE HUMAN reason for selecting reviewer (blank for HOLD): ") if choice != "HOLD" else ""
        except (EOFError, KeyboardInterrupt):
            raise Hold("HOLD: HUMAN entry cancelled") from None
        reason = safe_note(reason)
        require(choice == "HOLD" or bool(reason.strip()))
        writer.writerow((digest, a_sha, b_sha, original["ordinal"],
                         original["kind"], choice, reason))
    return stream.getvalue()


def read_decisions(path: str, digest: str, originals: list[dict],
                   a_sha: str, b_sha: str) -> list[dict]:
    try:
        value = source_bytes(path).decode("utf-8-sig")
        reader = csv.DictReader(io.StringIO(value, newline=""), strict=True)
        require(tuple(reader.fieldnames or ()) == DECISION_FIELDS)
        decisions = list(reader)
    except (UnicodeError, csv.Error, ValueError):
        raise Hold("HOLD: explicit HUMAN decisions rejected") from None
    require(len(decisions) == len(originals))
    final = []
    for index, (decision, original) in enumerate(zip(decisions, originals), 1):
        require(type(decision) is dict and set(decision) == set(DECISION_FIELDS))
        require(decision["receipt_sha256"] == digest and
                decision["review_a_sha256"] == a_sha and
                decision["review_b_sha256"] == b_sha and
                decision["ordinal"] == str(index) and
                decision["source_kind"] == original["kind"])
        choice = decision["choice"]
        require(choice in CHOICES)
        reason = safe_note(decision["human_reason"])
        require(choice == "HOLD" or bool(reason.strip()))
        final.append({"choice": choice, "reason": reason})
    return final


def resulting_csv(digest: str, originals: list[dict], a: list[dict],
                  b: list[dict], decisions: list[dict]) -> tuple[str, list[dict]]:
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(FIELDS)
    final = []
    for original, left, right, decision in zip(originals, a, b, decisions):
        selected = (left if decision["choice"] == "A" else
                    right if decision["choice"] == "B" else None)
        result = {
            "ordinal": original["ordinal"], "kind": original["kind"],
            "stage": selected["stage"] if selected else "unreviewed",
            "question": selected["question"] if selected else "",
            "next_action": selected["next_action"] if selected else "",
        }
        writer.writerow((digest, result["ordinal"], result["kind"], result["stage"],
                         result["question"], result["next_action"]))
        final.append(result)
    completed = out.getvalue()
    # Original HUMAN importer remains the final admission authority for its format.
    admitted_answers(completed.encode("utf-8"), digest, originals)
    return completed, final


def comparison_html(originals: list[dict], a: list[dict], b: list[dict],
                    decisions: list[dict] | None = None) -> str:
    """PRIVATE scriptless report, never anonymous or safe to distribute by default."""
    rows = []
    for index, (original, left, right) in enumerate(zip(originals, a, b)):
        choice = decisions[index]["choice"] if decisions else "HOLD"
        reason = decisions[index]["reason"] if decisions else ""
        different = any(left[key] != right[key] for key in ("stage", "question", "next_action"))
        columns = [
            str(original["ordinal"]), original["kind"],
            "DIFFERENT" if different else "SAME HUMAN TEXT (not independently verified)",
            left["stage"], left["question"], left["next_action"],
            right["stage"], right["question"], right["next_action"],
            choice, reason,
        ]
        rows.append("<tr>" + "".join("<td>" + html.escape(text) + "</td>"
                                     for text in columns) + "</tr>")
    headings = ("Ordinal", "Original declared kind", "HUMAN comparison",
                "A stage", "A PRIVATE question", "A PRIVATE action",
                "B stage", "B PRIVATE question", "B PRIVATE action",
                "Explicit choice", "HUMAN reason")
    return """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LightUp PRIVATE HUMAN reconciliation</title>
<style>body{font:15px/1.5 system-ui;max-width:1200px;margin:2rem auto;padding:1rem}
table{border-collapse:collapse;width:100%;overflow-wrap:anywhere}td,th{padding:.6rem;border:1px solid #aaa;text-align:left;vertical-align:top}
.warning{padding:1rem;border:2px solid #922;background:#faf4f4}
@media print{body{margin:0}}</style></head><body>
<h1>PRIVATE HUMAN reviewer reconciliation · REVIEW_ONLY/HOLD</h1>
<p class="warning">These are PRIVATE HUMAN notes, not safe for public distribution.
Two unsigned reviews were bound to the SAME exact unsigned, source-free receipt
bytes. This is NOT original finding provenance, sender identity, client/operator
consent, a verified fix, authorization, an approved disclosure, or a release.
Even identical HUMAN text is not security agreement. No source targets, scanning,
network, automated decision, or authorization action is performed.</p>
<p>All rows are HOLD until a human separately chooses A or B and writes a reason.
An unselected row becomes unreviewed with empty notes; no prior decision is
silently inherited. Human consent/approval must happen independently.</p>
<table><thead><tr>""" + "".join("<th scope='col'>" + html.escape(value) + "</th>"
                                  for value in headings) + "</tr></thead><tbody>" + "".join(rows) + """</tbody></table>
<p>No original lab source bytes or target identifiers are rendered unless typed
into HUMAN free-text by a reviewer. Keep the entire document owner-PRIVATE.</p>
</body></html>
"""



def reopen_published(args: argparse.Namespace, original_bytes: bytes, digest: str,
                     originals: list[dict], a_sha: str, a: list[dict],
                     b_sha: str, b: list[dict]) -> None:
    """Re-admit complete native HUMAN handoff against unchanged private sources.

    Reopening is read-only: it does not promote a HUMAN decision to approval.
    Plaintext final files must match native byte-for-byte reconstruction;
    ciphertext must decrypt to the same native receipt and HUMAN CSV.
    """
    decisions = read_decisions(args.decisions, digest, originals, a_sha, b_sha)
    expected_csv, final_rows = resulting_csv(digest, originals, a, b, decisions)
    expected_counts = human_counts(final_rows, args.minimum_cohort)
    browser_input = args.received_bundle is not None or args.received_csv is not None
    if browser_input:
        require(args.received_counts is not None and
                (args.received_bundle is None) != (args.received_csv is None))
    else:
        require(args.received_counts is None)
    if args.received_csv is not None:
        require(not args.encrypt_result)
        # Only a PRIVATE, owner-owned regular 0600 file is accepted. Its native
        # ordinal, receipt SHA, original kind and every selected HUMAN value
        # must exactly agree with the independently re-admitted sources.
        imported = admitted_answers(source_bytes(args.received_csv), digest, originals)
        require(imported == final_rows)
    elif args.encrypt_result:
        try:
            from vault_native import VaultHold, decrypt_bundle
            received_receipt, received_human_csv = decrypt_bundle(
                args.received_bundle or os.path.join(args.private_output_dir, SEALED_RESULT))
        except (ImportError, VaultHold):
            raise Hold("HOLD: encrypted PRIVATE HUMAN handoff cannot be reopened") from None
        require(hmac.compare_digest(original_bytes, received_receipt))
        if args.received_bundle:
            # The standalone quotes every field, while the original native
            # writer quotes only when needed. Check the entire admitted HUMAN
            # row set, not a lossy summary or an unsigned receipt hash.
            require(admitted_answers(received_human_csv, digest, originals) == final_rows)
        else:
            require(hmac.compare_digest(expected_csv.encode("utf-8"), received_human_csv))
    else:
        for name, content in (
            (RECONCILED, expected_csv),
            (OUTCOME, comparison_html(originals, a, b, decisions)),
        ):
            received = source_bytes(os.path.join(args.private_output_dir, name))
            require(hmac.compare_digest(received, content.encode("utf-8")))
    received_counts = source_bytes(args.received_counts or
                                   os.path.join(args.private_output_dir, COUNTS))
    if browser_input:
        # Only alternative CSV quoting is accepted. Every expected field,
        # suppression choice, declared authority flag and order must match.
        def literal_pairs(raw: bytes) -> list[list[str]]:
            try:
                reader = csv.reader(io.StringIO(raw.decode("utf-8-sig"), newline=""),
                                    strict=True)
                items = list(reader)
            except (UnicodeError, csv.Error, ValueError):
                raise Hold("HOLD: PRIVATE counts handoff rejected") from None
            require(10 <= len(items) <= 20 and
                    all(len(pair) == 2 and all(isinstance(v, str) for v in pair)
                        for pair in items))
            return items
        require(literal_pairs(received_counts) ==
                literal_pairs(expected_counts.encode("utf-8")))
    else:
        require(hmac.compare_digest(received_counts, expected_counts.encode("utf-8")))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PRIVATE HUMAN two-reviewer desk; never release authority")
    parser.add_argument("action", choices=("prepare", "decide", "finalize", "reopen"))
    parser.add_argument("--receipt", required=True, help="exact original unsigned PRIVATE receipt")
    parser.add_argument("--private-output-dir", required=True, help="existing owner-only 0700 directory")
    for role in ("a", "b"):
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument("--" + role + "-csv", help="PRIVATE reviewed CSV")
        group.add_argument("--" + role + "-vault", help="encrypted HUMAN vault .luhd")
        group.add_argument("--" + role + "-bundle", help="encrypted receipt + HUMAN bundle .luhb")
    parser.add_argument("--decisions", help="human-edited exact receipt + reviewer-bound decision CSV")
    parser.add_argument("--encrypt-result", action="store_true",
                        help="finalize or reopen: encrypted original receipt + chosen HUMAN CSV, without plaintext output")
    received = parser.add_mutually_exclusive_group()
    received.add_argument("--received-bundle",
                          help="reopen only: saved native-compatible browser .luhb PRIVATE handoff")
    received.add_argument("--received-csv",
                          help="reopen only: saved complete browser/native PRIVATE HUMAN CSV")
    parser.add_argument("--received-counts",
                        help="reopen only: saved original suppressed browser counts CSV")
    parser.add_argument("--minimum-cohort", type=int, default=5,
                        help="privacy floor 5-12 for separate source-free aggregate HUMAN counts")
    args = parser.parse_args(argv)
    try:
        require((args.action in ("prepare", "decide") and args.decisions is None) or
                (args.action in ("finalize", "reopen") and args.decisions is not None))
        require(not args.encrypt_result or args.action in ("finalize", "reopen"))
        require((args.received_bundle is None and args.received_csv is None and
                 args.received_counts is None) or
                (args.action == "reopen" and args.received_counts is not None and
                 ((args.received_bundle is not None and args.encrypt_result) or
                  (args.received_csv is not None and not args.encrypt_result))))
        original_bytes, digest, originals, a_sha, a, b_sha, b = load_context(args)
        if args.action == "reopen":
            reopen_published(args, original_bytes, digest, originals, a_sha, a, b_sha, b)
            print("REVIEW_ONLY: complete original PRIVATE HUMAN handoff re-admitted; NOT approval")
            return 2
        if args.action == "decide":
            publish(args.private_output_dir, INTERACTIVE_DECISIONS,
                    interactive_decisions(digest, originals, a_sha, a, b_sha, b))
            print("REVIEW_ONLY: explicit PRIVATE interactive decisions saved; no release")
            return 2
        if args.action == "prepare":
            decisions = None
            first_name = DECISIONS
            first_content = decision_template(digest, originals, a_sha, b_sha)
            second_name = COMPARISON
            second_content = comparison_html(originals, a, b)
        else:
            decisions = read_decisions(args.decisions, digest, originals, a_sha, b_sha)
            first_name = RECONCILED
            first_content, final_rows = resulting_csv(digest, originals, a, b, decisions)
            counts_content = human_counts(final_rows, args.minimum_cohort)
            second_name = OUTCOME
            second_content = comparison_html(originals, a, b, decisions)
            if args.encrypt_result:
                try:
                    from vault_native import VaultHold, encrypt_bundle
                    first_content = encrypt_bundle(original_bytes, first_content.encode("utf-8"))
                except (ImportError, VaultHold):
                    raise Hold("HOLD: encrypted reconciled HUMAN result refused") from None
                first_name = SEALED_RESULT
                second_name = COUNTS
                second_content = counts_content
        # Prepare every PRIVATE output before exposing the first final name.
        # Ordinary failure rolls back all new names; a crash is not a filesystem
        # transaction and no output grants source/recipient authority.
        artifacts = [(first_name, first_content), (second_name, second_content)]
        if args.action == "finalize" and not args.encrypt_result:
            artifacts.append((COUNTS, counts_content))
        publish_many(args.private_output_dir, artifacts)
    except (Hold, OSError, TypeError, ValueError, MemoryError):
        print("HOLD: PRIVATE HUMAN reconciliation not completed; no authority", file=sys.stderr)
        return 3
    print("REVIEW_ONLY: new PRIVATE HUMAN artifacts prepared; no release")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
