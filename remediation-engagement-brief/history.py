"""Bounded historical source comparison; original labels are never verified fixes."""
from __future__ import annotations

FIELDS = ("title","severity","retest_status","remediation")
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
        transitions.append(dict(index=index,added=sorted(after.keys()-before.keys()),
                                absent=sorted(before.keys()-after.keys()),changed=changed,
                                unchanged=len(common)-len(changed),unverified_fixed=sorted(fixed)))
    return dict(snapshots=sequence,transitions=transitions,
                historical=len(sequence)-1,source_ids=len(seen),
                current=len(sequence[-1]),currently_absent=sorted(seen-sequence[-1].keys()),
                reappeared=sorted(reappeared))

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
        "- Original IDs that reappeared after absence: "+str(len(info["reappeared"])), "",
    ]
    snapshots=info["snapshots"]
    for t in info["transitions"]:
        lines.extend([
            "## Original revision "+str(t["index"])+" to "+str(t["index"]+1), "",
            "- New original IDs: "+str(len(t["added"])),
            "- Absent original IDs (HOLD, not fixed): "+str(len(t["absent"])),
            "- Changed original records: "+str(len(t["changed"])),
            "- Unchanged common original records: "+str(t["unchanged"]),
            "- Source-only changes into fixed retest label (UNVERIFIED): "+str(len(t["unverified_fixed"])), "",
        ])
        if t["added"]:
            lines.extend(["### Newly present original IDs",""])
            lines.extend("- "+safe(x) for x in t["added"])
        if t["absent"]:
            lines.extend(["", "### Absent IDs — HUMAN HOLD",""])
            lines.extend("- "+safe(x) for x in t["absent"])
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
    lines=["source_from,source_to,added,absent,changed,unchanged,original_fixed_label_changes"]
    for t in info["transitions"]:
        lines.append(",".join(map(str,(
            t["index"],t["index"]+1,len(t["added"]),len(t["absent"]),
            len(t["changed"]),t["unchanged"],len(t["unverified_fixed"])
        ))))
    return ("\r\n".join(lines)+"\r\n").encode("ascii")
