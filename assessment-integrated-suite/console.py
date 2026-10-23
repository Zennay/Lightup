#!/usr/bin/env python3
"""Foreground local PRIVATE lab review coordination. No network, scanner or launch."""
from __future__ import annotations
from dataclasses import dataclass
import human_console
import remediation_console
import remediation_team_console
import evidence_console
import evidence_dialogue_console
import disclosure_console
import retention_console
import session_console
import route_console
import route_queue_console
import route_team_console
import route_queue_history_console
import saved_queue_console
import human_priorities_console
import human_workpack_console
import saved_workpack_console
import workpack_progress_console
import workpack_continue_console
import operator_navigation
import lab_plans_console
import lab_plan_portfolio_console
import lab_plan_review_console
import lab_review_history_console
import lab_review_team_console
import lab_review_team_return_console
import lab_review_team_batch_console
import lab_review_team_batch_reopen_console
import lab_review_team_batch_history_console
import lab_review_team_continue_console
import lab_review_team_continue_reopen_console
import lab_review_team_continuation_history_console
import lab_review_conflict_console
import lab_conflict_followup_console
import lab_route_handoff_console
import attention_receipt_console
import attention_history_console
import attention_decision_console
import private_session
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
SCRIPTS = {
    "prepare": ROOT / "suite.py",
    "curation": ROOT / "curation.py",
    "dossier": ROOT / "publish.py",
    "drift": ROOT / "drift.py",
    "archive": ROOT / "archive_room.py",
    "portfolio": ROOT / "portfolio_room.py",
    "benchmark": ROOT / "benchmark_room.py",
    "trajectory": ROOT / "trajectory.py",
    "reviewers": ROOT / "reviewer_room.py",
}
MAX_REPLY = 8192


@dataclass
class Session:
    parent: str = ""
    original: str = ""
    initial_kit: str = ""
    curation_kit: str = ""
    selected_kit: str = ""
    drift_kit: str = ""
    archive_kit: str = ""
    portfolio_kit: str = ""
    benchmark_kit: str = ""
    trajectory_kit: str = ""
    reviewer_kit: str = ""
    ledger_kit: str = ""
    notes_kit: str = ""
    remediation_kit: str = ""
    original_comparison: str = ""
    findings_csv: str = ""
    remediation_links: str = ""
    team_kit: str = ""
    evidence_source: str = ""
    evidence_manifest: str = ""
    evidence_worksheet: str = ""
    evidence_preparation: str = ""
    evidence_selection: str = ""
    evidence_dossier: str = ""
    recipient_preparation: str = ""
    recipient_reply: str = ""
    sender_preparation: str = ""
    sender_triage: str = ""
    disclosure_workroom: str = ""
    disclosure_review: str = ""
    retention_last_plan: str = ""
    retention_workroom: str = ""
    saved_session: str = ""
    session_history: str = ""


def ask(label: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    answer = input(f"{label}{suffix}: ").strip()
    return answer if answer else default


def path_prompt(label: str, default: str = "") -> str:
    text = ask(label, default)
    if not text or len(text) > 4096 or any(c in text for c in "\x00\r\n"):
        raise ValueError("HOLD: a required local file path is missing or malformed")
    return text



def admit_original_native_entry(path_text: str, flags: list[str]) -> Path | None:
    """Require an actual 0600 original entry in a direct 0700 output kit.

    Native stdout is a private local *claim*, not authority. Verify the
    promised file cannot redirect an operator outside the explicitly selected
    private parent, or via a symlink/unowned/public HTML path.
    """
    if not path_text or len(path_text) > 4096:
        return None
    try:
        parent_flag = flags.index("--private-parent")
        chosen = Path(flags[parent_flag + 1]).absolute()
        entry = Path(path_text)
        if (not entry.is_absolute() or entry.name != "OPEN-PRIVATE.html"
                or chosen == private_session.ROOT
                or private_session.ROOT in chosen.parents
                or not private_session.private(chosen, True)
                or entry.parent.parent != chosen
                or not private_session.private(entry.parent, True)):
            return None
        # Existing original PRIVATE page admission rejects symlink, public
        # mode, hardlink, wrong owner, empty or oversized HTML.
        checked = private_session.original_page(str(entry.parent),
                                                ("OPEN-PRIVATE.html",))
        if checked != entry or entry.resolve(strict=True) != entry:
            return None
        return entry
    except (OSError, ValueError, IndexError):
        return None


def run_native(script: str, flags: list[str]) -> tuple[bool, str]:
    path = SCRIPTS[script]
    if not path.is_file():
        print("HOLD: the native original-source component is not installed.")
        return False, ""
    try:
        result = subprocess.run(
            [sys.executable, "-P", str(path), *flags],
            cwd=str(ROOT.parent),
            capture_output=True,
            timeout=240,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        print("HOLD: offline native stage did not finish; inspect private workspace locally.")
        return False, ""
    # A complete, source-admitted benchmark regression is HOLD (exit 3),
    # but still has a useful original PRIVATE HUMAN comparison to inspect.
    answer = result.stdout.decode("utf-8", errors="replace")
    adverse = (result.returncode == 3 and (
        (script == "benchmark" and answer.startswith("ORIGINAL DECLARATION: HOLD;"))
        or (script == "trajectory" and answer.startswith("ORIGINAL TRAJECTORY: HOLD;"))
        or (script == "reviewers" and answer.startswith("ORIGINAL HUMAN CONSENSUS: HOLD;"))
    ))
    if result.returncode != 2 and not adverse:
        # Never echo native stderr or private source details.
        print("HOLD: original private admission refused; existing source remains unchanged.")
        return False, ""
    marker = "OPEN LOCALLY: "
    path_text = next((line[len(marker):].strip() for line in answer.splitlines()
                      if line.startswith(marker)), "")
    admitted = admit_original_native_entry(path_text, flags)
    if admitted is None:
        print("HOLD: original stage did not return an owner-private,")
        print("direct-child 0600 offline entry under the selected 0700 parent.")
        return False, ""
    print("HOLD — source-declared adverse benchmark requires HUMAN review."
          if adverse else "REVIEW_ONLY: PRIVATE local package prepared.")
    print("Open on a trusted offline device: " + str(admitted))
    return True, str(admitted.parent)


def prepare(session: Session) -> None:
    parent = path_prompt("Existing owner-only 0700 PRIVATE parent directory", session.parent)
    original = path_prompt("First already-produced ORIGINAL PRIVATE lab JSON", session.original)
    sources = [original]
    while len(sources) < 12:
        extra = ask("Optional next ORIGINAL PRIVATE lab JSON (empty to finish)")
        if not extra:
            break
        if len(extra) > 4096:
            raise ValueError("HOLD: source path exceeds local length bound")
        sources.append(extra)
    detail = ask("Include original PRIVATE full findings and HUMAN worksheet? (yes/no)", "yes").lower()
    if detail not in ("yes", "no"):
        raise ValueError("HOLD: choose yes or no explicitly")
    flags = sum((["--source", name] for name in sources), [])
    flags.extend(["--private-parent", parent])
    if detail == "yes":
        flags.append("--brief")
    ok, kit = run_native("prepare", ["prepare", *flags])
    if ok:
        session.parent = parent
        session.original = original
        session.initial_kit = kit if detail == "yes" else ""
        session.curation_kit = ""
        session.selected_kit = ""
        print("To prepare selected original finding questions, choose menu option 2.")


def curate(session: Session) -> None:
    parent = path_prompt("Existing owner-only 0700 PRIVATE parent", session.parent)
    original = path_prompt("Exact SAME original PRIVATE lab JSON", session.original)
    kit = path_prompt("Original PRIVATE full briefing kit", session.initial_kit)
    ok, next_kit = run_native("curation", [
        "--source", original, "--original-kit", kit, "--private-parent", parent,
    ])
    if ok:
        session.parent = parent
        session.original = original
        session.initial_kit = kit
        session.curation_kit = next_kit
        session.selected_kit = ""
        print("Edit the original selection CSV in the private HUMAN studio before option 3.")


def dossier(session: Session) -> None:
    parent = path_prompt("Existing owner-only 0700 PRIVATE parent", session.parent)
    original = path_prompt("Exact SAME original PRIVATE lab JSON", session.original)
    initial = path_prompt("Original PRIVATE full briefing kit", session.initial_kit)
    selection_kit = path_prompt("Existing PRIVATE HUMAN curation kit", session.curation_kit)
    selection = path_prompt("HUMAN completed original source-bound PRIVATE selection CSV")
    ok, next_kit = run_native("dossier", [
        "--source", original, "--original-kit", initial,
        "--curation-kit", selection_kit, "--selection", selection,
        "--private-parent", parent,
    ])
    if ok:
        session.parent, session.original = parent, original
        session.initial_kit, session.curation_kit = initial, selection_kit
        session.selected_kit = next_kit
        print("Nothing has been externally distributed. Dossier and minimized handoff remain PRIVATE.")


def drift(session: Session) -> None:
    parent = path_prompt("Existing owner-only 0700 PRIVATE parent", session.parent)
    before = path_prompt("Original PRIVATE lab JSON before", session.original)
    after = path_prompt("Different separately-produced ORIGINAL PRIVATE lab JSON after")
    ok, result = run_native("drift", [
        "--before", before, "--after", after, "--private-parent", parent,
    ])
    if ok:
        session.parent, session.drift_kit = parent, result
        print("Only literal source-declared changes are shown, never proven fixes.")


def archive(session: Session) -> None:
    parent = path_prompt("Existing owner-only 0700 PRIVATE parent", session.parent)
    sources = [path_prompt("Original already-produced PRIVATE artifact A"),
               path_prompt("Original already-produced PRIVATE artifact B")]
    while len(sources) < 64:
        next_file = ask("Further original PRIVATE artifact (empty to finish)")
        if not next_file:
            break
        if len(next_file) > 4096:
            raise ValueError("HOLD: artifact path too long")
        sources.append(next_file)
    args = sum((["--source", item] for item in sources), [])
    ok, kit = run_native("archive", [*args, "--private-parent", parent])
    if ok:
        session.parent, session.archive_kit = parent, kit
        print("Original PRIVATE archive identity is an unsigned source claim, not verification.")


def portfolio(session: Session) -> None:
    parent = path_prompt("Existing owner-only 0700 PRIVATE parent", session.parent)
    agendas = [path_prompt("Original already-produced PRIVATE HUMAN agenda")]
    while len(agendas) < 12:
        next_agenda = ask("Further original PRIVATE HUMAN agenda (empty to finish)")
        if not next_agenda:
            break
        if len(next_agenda) > 4096:
            raise ValueError("HOLD: agenda path too long")
        agendas.append(next_agenda)
    day = path_prompt("Human-declared shared planning date YYYY-MM-DD")
    args = sum((["--agenda", item] for item in agendas), [])
    ok, kit = run_native("portfolio", [
        *args, "--as-of", day, "--private-parent", parent,
    ])
    if ok:
        session.parent, session.portfolio_kit = parent, kit
        print("Original HUMAN proposals are not scheduled events or customer instructions.")


def benchmark(session: Session) -> None:
    parent = path_prompt("Existing owner-only 0700 PRIVATE parent", session.parent)
    choice = ask("Original comparison: single / cohort / scored", "cohort").lower()
    if choice not in ("single", "cohort", "scored"):
        raise ValueError("HOLD: comparison kind must be single, cohort or scored")
    before = path_prompt("Already-produced original PRIVATE baseline JSON")
    after = path_prompt("Separately-produced original PRIVATE candidate JSON")
    ok, kit = run_native("benchmark", [
        "--kind", choice, "--before", before, "--after", after,
        "--private-parent", parent,
    ])
    if ok:
        session.parent = parent
        session.benchmark_kit = kit
        print("The original comparison can be HOLD even when its PRIVATE report is readable.")
        print("A source-declared no-regression result is REVIEW_ONLY, not PASS.")


def trajectory(session: Session) -> None:
    parent = path_prompt("Existing owner-only 0700 PRIVATE parent", session.parent)
    kind = ask("Original cohort type: cohort / scored", "cohort").lower()
    if kind not in ("cohort", "scored"):
        raise ValueError("HOLD: choose cohort or scored")
    baseline = path_prompt("Original already-produced PRIVATE baseline cohort")
    candidates = [path_prompt(f"Original PRIVATE candidate cohort {n}") for n in range(1, 4)]
    while len(candidates) < 12:
        next_source = ask("Further original cohort (empty to finish)")
        if not next_source:
            break
        if len(next_source) > 4096:
            raise ValueError("HOLD: source path exceeds bounded length")
        candidates.append(next_source)
    flags = sum((["--candidate", name] for name in candidates), [])
    ok, kit = run_native("trajectory", [
        "--kind", kind, "--baseline", baseline,
        *flags, "--private-parent", parent,
    ])
    if ok:
        session.parent, session.trajectory_kit = parent, kit
        print("Open the private cohort series locally in the original Trend and Candidate Studios.")
        print("Selection order is HUMAN-only, not verified assessment chronology.")


def reviewers(session: Session) -> None:
    parent = path_prompt("Existing owner-only 0700 PRIVATE parent", session.parent)
    plans = [path_prompt(f"Original PRIVATE HUMAN reviewer plan {n}") for n in range(1, 3)]
    while len(plans) < 8:
        extra = ask("Further original PRIVATE reviewer plan (empty to finish)")
        if not extra:
            break
        if len(extra) > 4096:
            raise ValueError("HOLD: plan path exceeds length bound")
        plans.append(extra)
    resolutions = ask("Optional existing completed PRIVATE conflict resolution JSON")
    flags = sum((["--plan", name] for name in plans), [])
    if resolutions:
        flags.extend(["--resolutions", resolutions])
    ok, kit = run_native("reviewers", [*flags, "--private-parent", parent])
    if ok:
        session.parent, session.reviewer_kit = parent, kit
        print("Original HUMAN proposal, not authenticated review or consent.")


def last_packages(session: Session) -> None:
    for label, value in (
        ("PRIVATE full briefing", session.initial_kit),
        ("Original HUMAN selection", session.curation_kit),
        ("Selected PRIVATE dossier", session.selected_kit),
        ("Original PRIVATE source A/B drift", session.drift_kit),
        ("Original PRIVATE source archive", session.archive_kit),
        ("Original HUMAN agenda portfolio", session.portfolio_kit),
        ("Original PRIVATE lab benchmark comparison", session.benchmark_kit),
        ("Original PRIVATE lab cohort trajectory", session.trajectory_kit),
        ("Original PRIVATE multi-reviewer HUMAN workroom", session.reviewer_kit),
        ("Original PRIVATE workspace ledger", session.ledger_kit),
        ("Original PRIVATE credential-masked HUMAN notes", session.notes_kit),
        ("Original canonical lab-to-client HUMAN follow-up", session.remediation_kit),
        ("Original source-bound PRIVATE team collaboration", session.team_kit),
        ("Original PRIVATE evidence selection", session.evidence_preparation),
        ("Original PRIVATE evidence selected-only HUMAN dossier", session.evidence_dossier),
        ("Original PRIVATE disclosure preflight + HUMAN workroom", session.disclosure_workroom),
        ("Original source-free PRIVATE HUMAN disclosure report", session.disclosure_review),
        ("Original PRIVATE HUMAN retention history/drift", session.retention_workroom),
        ("Owner-private restorable local operator session", session.saved_session),
        ("PRIVATE operator workspace continuity", session.session_history),
    ):
        print(f"{label}: {value or 'not prepared this session'}")
    print("REVIEW_ONLY. Package directories are not customer permission, approval or security proof.")


def main() -> int:
    if not sys.stdin.isatty():
        print("HOLD: this operator console requires a foreground interactive terminal.")
        return 3
    session = Session()
    print("LightUp original PRIVATE assessment console")
    print("INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD")
    print("No scan, model, network, grant, deletion, retest, source verification or release.")
    menu = {
        "1": prepare, "2": curate, "3": dossier, "4": drift, "5": last_packages,
        "6": archive, "7": portfolio, "8": benchmark, "9": trajectory,
        "10": reviewers,
        "11": lambda x: human_console.ledger_capture(x, path_prompt, ask),
        "12": lambda x: human_console.ledger_reopen(x, path_prompt, ask),
        "13": lambda x: human_console.ledger_finalize(x, path_prompt, ask),
        "14": lambda x: human_console.notes_prepare(x, path_prompt, ask),
        "15": lambda x: human_console.notes_finalize(x, path_prompt, ask),
        "16": lambda x: remediation_console.prepare(x, path_prompt, ask),
        "17": lambda x: remediation_console.prepare(x, path_prompt, ask, cohorts=True),
        "18": lambda x: remediation_team_console.prepare(x, path_prompt, ask),
        "19": lambda x: remediation_team_console.receive(x, path_prompt, ask),
        "20": lambda x: remediation_team_console.reconcile(x, path_prompt, ask),
        "21": lambda x: remediation_console.prepare_casebook(x, path_prompt, ask),
        "22": lambda x: remediation_console.prepare_casebook(x, path_prompt, ask, cohorts=True),
        "23": lambda x: evidence_console.prepare(x, path_prompt, ask, "prepare"),
        "24": lambda x: evidence_console.prepare(x, path_prompt, ask, "publish"),
        "25": lambda x: evidence_console.prepare(x, path_prompt, ask, "history"),
        "26": lambda x: evidence_console.prepare(x, path_prompt, ask, "overview"),
        "27": lambda x: evidence_dialogue_console.execute(x, path_prompt, ask, "recipient-prepare"),
        "28": lambda x: evidence_dialogue_console.execute(x, path_prompt, ask, "recipient-return"),
        "29": lambda x: evidence_dialogue_console.execute(x, path_prompt, ask, "sender-prepare"),
        "30": lambda x: evidence_dialogue_console.execute(x, path_prompt, ask, "sender-return"),
        "31": lambda x: evidence_dialogue_console.execute(x, path_prompt, ask, "next-round"),
        "32": lambda x: disclosure_console.original(x, ask, path_prompt, "prepare"),
        "33": lambda x: disclosure_console.original(x, ask, path_prompt, "render"),
        "34": lambda x: disclosure_console.original(x, ask, path_prompt, "summarize"),
        "35": lambda x: retention_console.prepare(x, path_prompt, ask, "history"),
        "36": lambda x: retention_console.prepare(x, path_prompt, ask, "drift"),
        "37": lambda x: session_console.save(x, path_prompt, ask),
        "38": lambda x: session_console.reopen(x, path_prompt, ask),
        "39": lambda x: session_console.history(x, path_prompt, ask),
        "40": lambda x: route_console.prepare(x, path_prompt, ask),
        "41": lambda x: route_console.saved(x, path_prompt, ask),
        "42": lambda x: route_queue_console.create(x, path_prompt, ask),
        "43": lambda x: route_queue_console.reopen(x, path_prompt, ask),
        "44": lambda x: route_team_console.prepare(x, path_prompt, ask),
        "45": lambda x: route_queue_history_console.prepare(x, path_prompt, ask),
        "46": lambda x: saved_queue_console.prepare(x, path_prompt, ask),
        "47": lambda x: human_priorities_console.prepare(x, path_prompt, ask),
        "48": lambda x: human_workpack_console.prepare(x, path_prompt, ask),
        "49": lambda x: saved_workpack_console.prepare(x, path_prompt, ask),
        "50": lambda x: workpack_progress_console.prepare(x, path_prompt, ask),
        "51": lambda x: workpack_continue_console.prepare(x, path_prompt, ask),
        "52": lambda x: lab_plans_console.prepare(x, path_prompt, ask),
        "53": lambda x: lab_plans_console.reopen(x, path_prompt, ask),
        "54": lambda x: lab_plans_console.compare(x, path_prompt, ask),
        "55": lambda x: lab_plan_portfolio_console.prepare(x, path_prompt, ask),
        "56": lambda x: lab_plan_review_console.prepare(x, path_prompt, ask),
        "57": lambda x: lab_plan_review_console.finalize(x, path_prompt, ask),
        "58": lambda x: lab_plan_review_console.resume(x, path_prompt, ask),
        "59": lambda x: lab_review_history_console.prepare(x, path_prompt, ask),
        "60": lambda x: lab_review_team_console.prepare(x, path_prompt, ask),
        "61": lambda x: lab_review_team_return_console.prepare(x, path_prompt, ask),
        "62": lambda x: lab_review_team_batch_console.prepare(x, path_prompt, ask),
        "63": lambda x: lab_review_team_batch_reopen_console.prepare(x, path_prompt, ask),
        "64": lambda x: lab_review_team_batch_history_console.prepare(x, path_prompt, ask),
        "65": lambda x: lab_review_team_continue_console.prepare(x, path_prompt, ask),
        "66": lambda x: lab_review_team_continue_reopen_console.prepare(x, path_prompt, ask),
        "67": lambda x: lab_review_team_continuation_history_console.prepare(x, path_prompt, ask),
        "68": lambda x: lab_review_conflict_console.prepare(x, path_prompt, ask),
        "69": lambda x: lab_review_conflict_console.prepare(x, path_prompt, ask, publish=True),
        "70": lambda x: lab_conflict_followup_console.prepare(x, path_prompt, ask),
        "71": lambda x: lab_conflict_followup_console.prepare(x, path_prompt, ask, open_original_studio=True),
        "72": lambda x: lab_route_handoff_console.run(x, path_prompt, ask, "receive"),
        "73": lambda x: lab_route_handoff_console.run(x, path_prompt, ask, "reopen"),
        "74": lambda x: lab_route_handoff_console.run(x, path_prompt, ask, "history"),
        "75": lambda x: lab_route_handoff_console.run(x, path_prompt, ask, "reopen_history"),
        "76": lambda x: attention_receipt_console.run(x, path_prompt, ask, "receive"),
        "77": lambda x: attention_receipt_console.run(x, path_prompt, ask, "reopen"),
        "78": lambda x: attention_history_console.run(x, path_prompt, ask, "create"),
        "79": lambda x: attention_history_console.run(x, path_prompt, ask, "reopen"),
        "80": lambda x: attention_decision_console.run(x, path_prompt, ask, "create"),
        "81": lambda x: attention_decision_console.run(x, path_prompt, ask, "reopen"),
    }
    while True:
        operator_navigation.overview()
        try:
            choice = ask("Choice", "0")
            if choice.casefold() == "all":
                operator_navigation.all_actions()
                choice = ask("Listed action number (blank returns to overview)")
                if not choice:
                    continue
            elif choice.startswith("?"):
                matching = operator_navigation.search(choice[1:])
                if not matching:
                    continue
                choice = ask("Matching action number (blank returns)")
                if not choice:
                    continue
                if choice not in matching:
                    print("HOLD: choose only one of the matching action numbers.")
                    continue
            elif choice.casefold() == "lab":
                operator_navigation.lab_guide()
                continue
            elif choice.casefold() == "help":
                operator_navigation.help_flow()
                continue
            if choice == "0":
                print("Exited. No external tasks were scheduled or executed.")
                return 0
            if choice not in menu:
                print("Choose a number from 0 to 81.")
                continue
            menu[choice](session)
        except (KeyboardInterrupt, EOFError):
            print("\nExited; no external work scheduled.")
            return 0
        except (ValueError, OSError) as exc:
            # No arbitrary exception data or PRIVATE input values printed.
            print(str(exc) if isinstance(exc, ValueError) and str(exc).startswith("HOLD:")
                  else "HOLD: local input could not be admitted; no other workflow affected.")


if __name__ == "__main__":
    raise SystemExit(main())
