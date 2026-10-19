"""Bounded historical source comparison; original labels are never verified fixes."""
from __future__ import annotations

FIELDS = ("title","severity","retest_status","remediation")
SEVERITY_ORDER = ("critical","high","medium","low","info")
MAX = 12

def review(snapshots):
    """Ordered snapshots are (metadata, original findings rows), latest is current."""
    if not 2 <= len(snapshots) <= MAX+1:
        raise ValueError("Expected 1-12 historical sources and one current source")
    sequence=[]
    seen=set()
    absent_since=set()
    reappeared=set()
    for metadata,rows in snapshots:
        if type(metadata) is not dict or type(rows) is not list or not 1<=len(rows)<=350:
            raise ValueError("Malformed source sequence")
        mapping={}
        for item in rows:
            if type(item) is not dict or set(item)!={"finding_id","title","severity","retest_status","remediation"}:
                raise ValueError("Malformed source finding")
            if any(type(v) is not str for v in item.values()) or item["finding_id"] in mapping:
                raise ValueError("Noncanonical original ID or value")
            mapping[item["finding_id"]]=item
        if sequence:
            previous=sequence[-1]
            absent_since.update(previous.keys()-mapping.keys())
            reappeared.update(mapping.keys() & absent_since)
        seen.update(mapping)
        sequence.append(mapping)
    transitions=[]
    for index in range(1,len(sequence)):
        before,after=sequence[index-1],sequence[index]
        common=before.keys() & after.keys()
        changed={key: tuple(field for field in FIELDS if before[key][field]!=after[key][field])
                 for key in common if before[key]!=after[key]}
        fixed={key for key in common if before[key]["retest_status"]!=after[key]["retest_status"]
               and after[key]["retest_status"]=="fixed"}
        escalated=sorted(key for key in common
                         if before[key]["severity"] in SEVERITY_ORDER
                         and after[key]["severity"] in SEVERITY_ORDER
                         and SEVERITY_ORDER.index(after[key]["severity"]) <
                         SEVERITY_ORDER.index(before[key]["severity"]))
        regressions=sorted(key for key in common
                           if before[key]["retest_status"]!="regression"
                           and after[key]["retest_status"]=="regression")
        transitions.append(dict(index=index,added=sorted(after.keys()-before.keys()),
                                absent=sorted(before.keys()-after.keys()),changed=changed,
                                unchanged=len(common)-len(changed),unverified_fixed=sorted(fixed),
                                source_severity_escalations=escalated,
                                source_retest_regressions=regressions))
    # The focus inbox is a derived current-source view, not a durable verdict
    # or newly authenticated owner assignment. It never carries prior IDs
    # absent from the latest original source into a false current work order.
    escalated_ids={ident for t in transitions for ident in t["source_severity_escalations"]}
    regression_ids={ident for t in transitions for ident in t["source_retest_regressions"]}
    changed_last=set(transitions[-1]["changed"]) if transitions else set()
    present=sequence[-1]
    inbox=[]
    for ident,item in present.items():
        attention=[]
        if item["severity"] in ("critical","high"):
            attention.append("current_original_high_severity_label")
        if ident in escalated_ids:
            attention.append("historical_original_severity_escalation")
        if ident in regression_ids:
            attention.append("historical_original_regression_label")
        if ident in reappeared:
            attention.append("original_id_reappeared_after_absence")
        if ident in changed_last:
            attention.append("original_record_changed_in_latest_transition")
        if attention:
            inbox.append(dict(original_id=ident,
                              original_severity=item["severity"],
                              original_retest=item["retest_status"],
                              attention=tuple(attention)))
    inbox.sort(key=lambda entry: (
        SEVERITY_ORDER.index(entry["original_severity"]),-len(entry["attention"]),
        entry["original_id"],
    ))
    return dict(snapshots=sequence,transitions=transitions,
                historical=len(sequence)-1,source_ids=len(seen),
                current=len(sequence[-1]),currently_absent=sorted(seen-sequence[-1].keys()),
                reappeared=sorted(reappeared),current_human_focus=inbox,
                source_escalation_events=sum(len(t["source_severity_escalations"]) for t in transitions),
                source_regression_label_events=sum(len(t["source_retest_regressions"]) for t in transitions))

def safe(value):
    if type(value) is not str:
        raise ValueError("Malformed source value")
    value=value.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    for char in ("\\","`","*","_","{","}","[","]","(",")","#","+","-",".","!","|","~"):
        value=value.replace(char,"\\"+char)
    return value.replace("\n"," ").replace("\r"," ")

def markdown(info):
    lines=[
        "# PRIVATE HUMAN original finding continuity", "",
        "DRAFT/HOLD. Only source text and source labels, not verified findings or fixes.",
        "Original sequence is supplied by the human operator, NOT authenticated timestamps.",
        "Disappearance, reappearance or original fixed label is never verified remediation.",
        "No grant, client/operator consent, scanning, retesting or production release.", "",
        "## Original source history", "",
        "- Previous encrypted source revisions: "+str(info["historical"]),
        "- Distinct original finding IDs: "+str(info["source_ids"]),
        "- Current freshly authorized original findings: "+str(info["current"]),
        "- Currently absent historically observed IDs: "+str(len(info["currently_absent"])),
        "- Original IDs that reappeared after absence: "+str(len(info["reappeared"])),
        "- Source-only severity escalation events (UNVERIFIED): "+str(info["source_escalation_events"]),
        "- Source-only new regression-label events (UNVERIFIED): "+str(info["source_regression_label_events"]),
        "- Current original finding IDs with HUMAN attention prompts: "+str(len(info["current_human_focus"])), "",
        "## Current source-only HUMAN follow-up inbox (UNVERIFIED)", "",
        "Entries derive from the current original source and prior source text only.",
        "A suggested attention flag is NOT an authenticated priority or evidence of risk.", "",
    ]
    for item in info["current_human_focus"]:
        lines.append("- "+safe(item["original_id"])+" · original "+safe(item["original_severity"])+
                     " / "+safe(item["original_retest"])+" · "+
                     ", ".join(safe(reason.replace("_"," ")) for reason in item["attention"]))
    if not info["current_human_focus"]:
        lines.append("- No source-label attention triggers in current original snapshot.")
    lines.append("")
    snapshots=info["snapshots"]
    for t in info["transitions"]:
        lines.extend([
            "## Original revision "+str(t["index"])+" to "+str(t["index"]+1), "",
            "- New original IDs: "+str(len(t["added"])),
            "- Absent original IDs (HOLD, not fixed): "+str(len(t["absent"])),
            "- Changed original records: "+str(len(t["changed"])),
            "- Unchanged common original records: "+str(t["unchanged"]),
            "- Source-only changes into fixed retest label (UNVERIFIED): "+str(len(t["unverified_fixed"])),
            "- Source-severity escalation to higher priority (UNVERIFIED): "+str(len(t["source_severity_escalations"])),
            "- New source-regression labels (UNVERIFIED): "+str(len(t["source_retest_regressions"])), "",
        ])
        if t["added"]:
            lines.extend(["### Newly present original IDs",""])
            lines.extend("- "+safe(x) for x in t["added"])
        if t["absent"]:
            lines.extend(["", "### Absent IDs — HUMAN HOLD",""])
            lines.extend("- "+safe(x) for x in t["absent"])
        if t["source_severity_escalations"]:
            lines.extend(["", "### HUMAN priority: original source severity escalations",""])
            previous=snapshots[t["index"]-1]
            current=snapshots[t["index"]]
            lines.extend("- "+safe(ident)+": "+safe(previous[ident]["severity"])+" to "+
                         safe(current[ident]["severity"])+" (source labels, not verified risk)"
                         for ident in t["source_severity_escalations"])
        if t["source_retest_regressions"]:
            lines.extend(["", "### HUMAN priority: new original regression labels",""])
            lines.extend("- "+safe(ident)+" — original source now reports regression; not independently confirmed."
                         for ident in t["source_retest_regressions"])
        if t["changed"]:
            lines.extend(["", "### Source field changes",""])
            before=snapshots[t["index"]-1]
            after=snapshots[t["index"]]
            for ident in sorted(t["changed"]):
                lines.append("- "+safe(ident)+": "+", ".join(t["changed"][ident]))
                for field in t["changed"][ident]:
                    lines.append("  - Previous "+field+": "+safe(before[ident][field]))
                    lines.append("  - Current "+field+": "+safe(after[ident][field]))
        lines.append("")
    lines.extend(["## HUMAN attention: original IDs that reappeared", ""])
    lines.extend("- "+safe(x)+" — source disappearance/reappearance needs independent review."
                 for x in info["reappeared"])
    if not info["reappeared"]: lines.append("- None in supplied sequence.")
    lines.extend(["", "## HUMAN attention: previously present, currently absent", ""])
    lines.extend("- "+safe(x)+" — absence is never verified repair."
                 for x in info["currently_absent"])
    if not info["currently_absent"]: lines.append("- None in supplied sequence.")
    lines.extend(["", "Human follow-up must independently confirm original source order, client",
                  "and engagement identity, obtain separate present consent and scope approval,",
                  "and review real evidence before any claimed remediation/retest.", ""])
    result="\n".join(lines)
    if len(result.encode("utf-8"))>4*1024*1024:
        raise ValueError("Private review text too large")
    return result

def anonymous_csv(info):
    lines=["source_from,source_to,added,absent,changed,unchanged,original_fixed_label_changes,source_severity_escalations,source_regression_label_changes"]
    for t in info["transitions"]:
        lines.append(",".join(map(str,(
            t["index"],t["index"]+1,len(t["added"]),len(t["absent"]),
            len(t["changed"]),t["unchanged"],len(t["unverified_fixed"]),
            len(t["source_severity_escalations"]),len(t["source_retest_regressions"])
        ))))
    return ("\r\n".join(lines)+"\r\n").encode("ascii")
