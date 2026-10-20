"""Pre-merge change security review over a ChangeSet.

This is the first end-to-end Future Security product path that runs on any
repository without lab infrastructure:

    git range / GitHub compare
      -> ChangeSet (+ structured OpenAPI/Terraform deltas)
      -> deterministic change rules (inferred hypotheses)
      -> future Security Twin branch + subject candidates
      -> policy verdict (PASS / PASS_WITH_WARNING / REVIEW_REQUIRED / BLOCK)
      -> JSON, Markdown and SARIF reports

Every conclusion here is ``inferred``. The verdict is labelled
``basis=inferred`` so it can never be mistaken for the evidence-verified ST5
verdict (:mod:`lightup.future_security_ci_verdict`). It performs no target
interaction and grants no authorization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from .change_rules import RULES, ChangeHypothesis, ChangeRule, evaluate_patch
from .changes import (
    ChangeSet, ChangeSourceKind, SemanticSignalKind, derive_future_twin,
)
from .future_binding import bind_future_change_candidates
from .future_security_ci_verdict import SecurityCIVerdict
from .github_changes import classify_repository_path, github_compare_changeset
from .models import Severity
from .structured_changes import (
    StructuredDocumentDelta, enrich_changeset_with_structured_deltas,
)
from .twin import SecurityTwin

REVIEW_SCHEMA_VERSION = "lightup.change_review.v1"
POLICY_FILE = ".lightup-review.json"

_RANK = {
    SecurityCIVerdict.PASS: 0,
    SecurityCIVerdict.PASS_WITH_WARNING: 1,
    SecurityCIVerdict.REVIEW_REQUIRED: 2,
    SecurityCIVerdict.BLOCK: 3,
}
_CONCLUSION = {
    SecurityCIVerdict.PASS: "success",
    SecurityCIVerdict.PASS_WITH_WARNING: "neutral",
    SecurityCIVerdict.REVIEW_REQUIRED: "action_required",
    SecurityCIVerdict.BLOCK: "failure",
}
_SEVERITY_ORDER = {
    Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
    Severity.LOW: 3, Severity.INFO: 4,
}
_SARIF_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
    Severity.LOW: "note", Severity.INFO: "note",
}
_SARIF_SCORE = {
    Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0", Severity.INFO: "1.0",
}


@dataclass(frozen=True)
class ChangeReviewPolicy:
    """Maps inferred hypotheses and coverage gaps to a verdict."""

    severity_verdicts: Mapping[Severity, SecurityCIVerdict] = field(
        default_factory=lambda: {
            Severity.CRITICAL: SecurityCIVerdict.BLOCK,
            Severity.HIGH: SecurityCIVerdict.REVIEW_REQUIRED,
            Severity.MEDIUM: SecurityCIVerdict.PASS_WITH_WARNING,
            Severity.LOW: SecurityCIVerdict.PASS_WITH_WARNING,
            Severity.INFO: SecurityCIVerdict.PASS,
        }
    )
    surface_change_verdict: SecurityCIVerdict = SecurityCIVerdict.PASS_WITH_WARNING
    incomplete_coverage_verdict: SecurityCIVerdict = SecurityCIVerdict.PASS_WITH_WARNING
    ignore_rules: frozenset[str] = frozenset()
    ignore_paths: tuple[str, ...] = ()
    min_confidence: float = 0.0

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "ChangeReviewPolicy":
        allowed = {
            "severity_verdicts", "surface_change_verdict",
            "incomplete_coverage_verdict", "ignore_rules", "ignore_paths",
            "min_confidence",
        }
        unknown = set(raw) - allowed
        if unknown:
            raise ValueError(f"unknown change review policy keys: {sorted(unknown)}")
        policy = cls()
        verdicts = dict(policy.severity_verdicts)
        for severity, verdict in dict(raw.get("severity_verdicts", {})).items():
            verdicts[Severity(severity)] = SecurityCIVerdict(verdict)
        confidence = float(raw.get("min_confidence", 0.0))
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("min_confidence must be between 0 and 1")
        return cls(
            severity_verdicts=verdicts,
            surface_change_verdict=SecurityCIVerdict(
                raw.get("surface_change_verdict", policy.surface_change_verdict.value)
            ),
            incomplete_coverage_verdict=SecurityCIVerdict(
                raw.get("incomplete_coverage_verdict",
                        policy.incomplete_coverage_verdict.value)
            ),
            ignore_rules=frozenset(str(item) for item in raw.get("ignore_rules", ())),
            ignore_paths=tuple(str(item) for item in raw.get("ignore_paths", ())),
            min_confidence=confidence,
        )

    @classmethod
    def load(cls, path: str | Path) -> "ChangeReviewPolicy":
        return cls.from_mapping(json.loads(Path(path).read_text(encoding="utf-8")))

    def ignores(self, hypothesis: ChangeHypothesis) -> bool:
        if hypothesis.rule_id in self.ignore_rules:
            return True
        if hypothesis.confidence < self.min_confidence:
            return True
        return any(fnmatch(hypothesis.path, pattern) for pattern in self.ignore_paths)


@dataclass(frozen=True)
class VerdictReason:
    verdict: SecurityCIVerdict
    reason: str


@dataclass(frozen=True)
class ChangeReview:
    changeset: ChangeSet
    hypotheses: tuple[ChangeHypothesis, ...]
    suppressed: tuple[ChangeHypothesis, ...]
    verdict: SecurityCIVerdict
    reasons: tuple[VerdictReason, ...]
    future_twin: SecurityTwin
    candidate_bindings: int
    unanalyzed_paths: tuple[str, ...]

    @property
    def conclusion(self) -> str:
        return _CONCLUSION[self.verdict]

    def severity_counts(self) -> dict[str, int]:
        counts = {severity.value: 0 for severity in _SEVERITY_ORDER}
        for hypothesis in self.hypotheses:
            counts[hypothesis.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        changeset = self.changeset
        payload = {
            "schema": REVIEW_SCHEMA_VERSION,
            "verdict": self.verdict.value,
            "basis": "inferred",
            "ci_conclusion": self.conclusion,
            "not_authorization": True,
            "reasons": [
                {"verdict": reason.verdict.value, "reason": reason.reason}
                for reason in self.reasons
            ],
            "change": {
                "changeset_id": changeset.changeset_id,
                "changeset_sha256": changeset.stable_digest(),
                "repository": changeset.repository,
                "source_ref": changeset.source_ref,
                "base_revision": changeset.base_revision,
                "head_revision": changeset.head_revision,
                "files": len(changeset.objects),
                "files_by_kind": _files_by_kind(changeset),
                "additions": sum(obj.additions for obj in changeset.objects),
                "deletions": sum(obj.deletions for obj in changeset.objects),
            },
            "severity_counts": self.severity_counts(),
            "hypotheses": [item.to_dict() for item in self.hypotheses],
            "suppressed": [item.to_dict() for item in self.suppressed],
            "surface_signals": [
                {
                    "kind": signal.kind.value,
                    "direction": signal.direction.value,
                    "path": signal.object_path,
                    "summary": signal.summary,
                    "provenance": signal.provenance.value,
                }
                for signal in changeset.semantic_signals
            ],
            "coverage": {
                "unanalyzed_paths": list(self.unanalyzed_paths),
                "uncertainties": list(changeset.uncertainties),
            },
            "future_twin": {
                "twin_id": self.future_twin.twin_id,
                "change_nodes": int(dict(self.future_twin.metadata).get(
                    "future_change_node_count", "0")),
                "candidate_bindings": self.candidate_bindings,
                "future_semantics": dict(self.future_twin.metadata).get(
                    "future_semantics", "unresolved"),
            },
        }
        payload["review_sha256"] = sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        return payload


def _files_by_kind(changeset: ChangeSet) -> dict[str, int]:
    counts: dict[str, int] = {}
    for obj in changeset.objects:
        counts[obj.kind.value] = counts.get(obj.kind.value, 0) + 1
    return dict(sorted(counts.items()))


def _max(verdicts: Iterable[SecurityCIVerdict]) -> SecurityCIVerdict:
    return max(verdicts, key=_RANK.__getitem__, default=SecurityCIVerdict.PASS)


def review_change(
    *,
    client_id: str,
    repository: str,
    base_revision: str,
    head_revision: str,
    files: Iterable[Mapping[str, Any]],
    source_kind: ChangeSourceKind = ChangeSourceKind.LOCAL_GIT_RANGE,
    source_ref: str | None = None,
    structured_deltas: Mapping[str, StructuredDocumentDelta] | None = None,
    policy: ChangeReviewPolicy | None = None,
    current_twin: SecurityTwin | None = None,
    rules: tuple[ChangeRule, ...] = RULES,
) -> ChangeReview:
    """Review one proposed change and return an inferred, explainable verdict."""
    policy = policy or ChangeReviewPolicy()
    files = [dict(item) for item in files]
    source_ref = source_ref or f"git:{repository}:{base_revision}...{head_revision}"
    changeset = github_compare_changeset(
        client_id=client_id,
        repository=repository,
        base_revision=base_revision,
        head_revision=head_revision,
        files=files,
        source_kind=source_kind,
        source_ref=source_ref,
    )
    if structured_deltas:
        known = {obj.path for obj in changeset.objects}
        changeset = enrich_changeset_with_structured_deltas(
            changeset, {k: v for k, v in structured_deltas.items() if k in known}
        )

    hypotheses: list[ChangeHypothesis] = []
    suppressed: list[ChangeHypothesis] = []
    unanalyzed: list[str] = []
    for record in files:
        path = str(record.get("filename"))
        patch = record.get("patch")
        if not isinstance(patch, str):
            if record.get("status") != "removed":
                unanalyzed.append(path)
            continue
        if len(patch.encode("utf-8")) > 512 * 1024:
            unanalyzed.append(path)
            continue
        for hypothesis in evaluate_patch(
            path=path, kind=classify_repository_path(path), patch=patch, rules=rules,
        ):
            (suppressed if policy.ignores(hypothesis) else hypotheses).append(hypothesis)

    hypotheses.sort(key=lambda h: (_SEVERITY_ORDER[h.severity], h.path, h.line, h.rule_id))
    suppressed.sort(key=lambda h: (h.path, h.line, h.rule_id))

    reasons: list[VerdictReason] = []
    for severity in _SEVERITY_ORDER:
        matching = [h for h in hypotheses if h.severity is severity]
        if matching:
            rules_hit = sorted({h.rule_id for h in matching})
            reasons.append(VerdictReason(
                policy.severity_verdicts[severity],
                f"{len(matching)} {severity.value} hypothesis(es): {', '.join(rules_hit)}",
            ))
    sensitive_surface = [
        signal for signal in changeset.semantic_signals
        if signal.kind in {SemanticSignalKind.IAM_POLICY, SemanticSignalKind.NETWORK_BOUNDARY}
    ]
    if sensitive_surface:
        reasons.append(VerdictReason(
            policy.surface_change_verdict,
            f"{len(sensitive_surface)} IAM/network-boundary change signal(s) are unverified",
        ))
    if unanalyzed:
        reasons.append(VerdictReason(
            policy.incomplete_coverage_verdict,
            f"{len(unanalyzed)} changed file(s) could not be analyzed (binary or too large)",
        ))
    if any(obj.path == POLICY_FILE or obj.previous_path == POLICY_FILE
           for obj in changeset.objects):
        reasons.append(VerdictReason(
            SecurityCIVerdict.REVIEW_REQUIRED,
            f"this change edits {POLICY_FILE}; the policy change itself needs human review",
        ))
    if "github_compare_too_large" in changeset.uncertainties:
        reasons.append(VerdictReason(
            SecurityCIVerdict.REVIEW_REQUIRED, "change is too large to review completely",
        ))
    verdict = _max(reason.verdict for reason in reasons)
    if not reasons:
        reasons.append(VerdictReason(
            SecurityCIVerdict.PASS,
            "no rule matched; this is not a clean bill of health, only an absence of "
            "inferred signals",
        ))

    current = current_twin or SecurityTwin.current(client_id)
    future = derive_future_twin(current, changeset)
    future, bindings = bind_future_change_candidates(future, changeset)

    return ChangeReview(
        changeset=changeset,
        hypotheses=tuple(hypotheses),
        suppressed=tuple(suppressed),
        verdict=verdict,
        reasons=tuple(reasons),
        future_twin=future,
        candidate_bindings=sum(1 for b in bindings if b.status.value != "no_candidate"),
        unanalyzed_paths=tuple(sorted(unanalyzed)),
    )


_VERDICT_BADGE = {
    SecurityCIVerdict.PASS: "PASS",
    SecurityCIVerdict.PASS_WITH_WARNING: "PASS WITH WARNING",
    SecurityCIVerdict.REVIEW_REQUIRED: "REVIEW REQUIRED",
    SecurityCIVerdict.BLOCK: "BLOCK",
}


def render_markdown(review: ChangeReview, *, max_rows: int = 50) -> str:
    data = review.to_dict()
    change = data["change"]
    lines = [
        f"## LightUp change review: **{_VERDICT_BADGE[review.verdict]}**",
        "",
        f"`{change['repository']}` · `{change['base_revision'][:12]}...{change['head_revision'][:12]}`"
        f" · {change['files']} file(s), +{change['additions']}/-{change['deletions']}",
        "",
        "> Basis: **inferred** from the proposed diff. This verdict is not verified "
        "against a running system and is never authorization to deploy or scan.",
        "",
        "### Why",
        "",
    ]
    lines += [f"- **{r['verdict']}** — {r['reason']}" for r in data["reasons"]]
    counts = data["severity_counts"]
    lines += [
        "",
        "| Critical | High | Medium | Low | Info |",
        "|---:|---:|---:|---:|---:|",
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | {counts['low']} | {counts['info']} |",
        "",
    ]
    if review.hypotheses:
        lines += [
            "### Security hypotheses",
            "",
            "| Severity | Rule | Location | What to do |",
            "|---|---|---|---|",
        ]
        for item in review.hypotheses[:max_rows]:
            where = f"`{item.path}:{item.line}`" + (" (removed)" if item.side.value == "removed" else "")
            cwe = f" ({item.cwe})" if item.cwe else ""
            lines.append(
                f"| {item.severity.value} | {item.title}{cwe} | {where} | {item.remediation} |"
            )
        if len(review.hypotheses) > max_rows:
            lines.append(f"| … | {len(review.hypotheses) - max_rows} more | | |")
        lines.append("")
    if data["surface_signals"]:
        lines += ["### Security-relevant surface changes (unverified)", ""]
        for signal in data["surface_signals"][:max_rows]:
            lines.append(f"- `{signal['path']}` — {signal['kind']} {signal['direction']}: {signal['summary']}")
        lines.append("")
    if review.unanalyzed_paths:
        lines += ["### Coverage gaps", ""]
        lines += [f"- `{path}` was not analyzed" for path in review.unanalyzed_paths[:max_rows]]
        lines.append("")
    if review.suppressed:
        lines += [f"_{len(review.suppressed)} hypothesis(es) suppressed by policy._", ""]
    lines += [
        f"<sub>Future twin `{data['future_twin']['twin_id'][:8]}` · "
        f"{data['future_twin']['change_nodes']} change node(s) · "
        f"review `{data['review_sha256'][:16]}`</sub>",
    ]
    return "\n".join(lines) + "\n"


def render_sarif(review: ChangeReview) -> dict[str, Any]:
    """SARIF 2.1.0 for GitHub code scanning and other CI viewers."""
    used = {h.rule_id for h in review.hypotheses}
    rule_index = {}
    sarif_rules = []
    for rule in RULES:
        if rule.rule_id not in used:
            continue
        rule_index[rule.rule_id] = len(sarif_rules)
        sarif_rules.append({
            "id": rule.rule_id,
            "name": rule.rule_id.replace(".", "_").replace("-", "_"),
            "shortDescription": {"text": rule.title},
            "help": {"text": rule.remediation},
            "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
            "properties": {
                "security-severity": _SARIF_SCORE[rule.severity],
                "tags": ["security", rule.category] + ([rule.cwe] if rule.cwe else []),
                "precision": "high" if rule.confidence >= 0.8 else "medium",
            },
        })
    results = []
    for item in review.hypotheses:
        result = {
            "ruleId": item.rule_id,
            "level": _SARIF_LEVEL[item.severity],
            "message": {"text": f"{item.title}. {item.remediation} (basis: inferred)"},
            "partialFingerprints": {"lightupHypothesis/v1": item.hypothesis_id},
            "properties": {"side": item.side.value, "confidence": item.confidence},
        }
        if item.rule_id in rule_index:
            result["ruleIndex"] = rule_index[item.rule_id]
        if item.side.value == "added":
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": item.path},
                    "region": {"startLine": max(1, item.line)},
                }
            }]
        else:
            result["locations"] = [{
                "physicalLocation": {"artifactLocation": {"uri": item.path}},
            }]
        results.append(result)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "LightUp change review",
                "informationUri": "https://github.com/zennay/lightup",
                "rules": sarif_rules,
            }},
            "results": results,
            "properties": {"verdict": review.verdict.value, "basis": "inferred"},
        }],
    }
