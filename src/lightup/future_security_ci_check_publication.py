"""Fail-closed ST5 GitHub Check publication contract.

This module turns an already-proven, live-revalidated ST5 CI security verdict into
an immutable publication request. It deliberately does not contain a live GitHub
API adapter: publication remains reporting-only and cannot merge, deploy, widen
authorization, mutate attack paths, use credentials, or interact with targets.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from typing import Protocol

from .ai.orchestration import RunContext
from .future_attack_path_graph_diff_policy import (
    FutureAttackPathGraphDiffPolicyDecision,
)
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import (
    FutureAttackPathSecurityDeltaReport,
)
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import (
    FutureAttackPathTransitionResolution,
)
from .future_security_ci_verdict import (
    FutureSecurityCIVerdictDecision,
    FutureSecurityCIVerdictPolicy,
    decide_future_security_ci_verdict,
)
from .state import StateStore


PUBLICATION_SCHEMA_VERSION = "st5.github_check_publication.v1"
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class GitHubCheckPublicationAuthorization:
    """Exact reporting authority for one repository/source/verdict tuple."""

    client_id: str
    repository: str
    source_sha: str
    verdict_sha256: str
    reporting_allowed: bool
    merge_allowed: bool = False
    deployment_allowed: bool = False


@dataclass(frozen=True)
class GitHubCheckPublicationRequest:
    schema_version: str
    repository: str
    source_sha: str
    client_id: str
    current_twin_id: str
    current_twin_version: int
    twin_id: str
    twin_version: int
    changeset_id: str
    report_sha256: str
    policy_sha256: str
    verdict_sha256: str
    verdict: str
    conclusion: str
    check_name: str
    title: str
    summary: str
    external_id: str
    request_sha256: str
    merge_authorized: bool = False
    deployment_authorized: bool = False


@dataclass(frozen=True)
class GitHubCheckPublicationReceipt:
    schema_version: str
    repository: str
    source_sha: str
    verdict_sha256: str
    conclusion: str
    check_name: str
    external_id: str
    request_sha256: str
    provider_receipt_id: str
    publication_sha256: str
    merge_authorized: bool = False
    deployment_authorized: bool = False


class GitHubCheckPublisher(Protocol):
    """Adapter boundary. Implementations must publish once per external_id."""

    def publish_once(self, request: GitHubCheckPublicationRequest) -> str:
        """Return a stable provider receipt id for the deterministic request."""


def _require_nonempty_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty text")
    return value


def _require_exact_bool(name: str, value: object) -> bool:
    if type(value) is not bool:
        raise ValueError(f"{name} must be an exact bool")
    return value


def _canonical_digest(payload: dict) -> str:
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _validate_repository_and_source(repository: str, source_sha: str) -> None:
    if not isinstance(repository, str) or not _REPOSITORY_RE.fullmatch(repository):
        raise ValueError("repository must be exact owner/name text")
    if not isinstance(source_sha, str) or not _SHA40_RE.fullmatch(source_sha):
        raise ValueError("source_sha must be an exact lowercase 40-hex Git SHA")


def _validate_authorization(
    *,
    authorization: GitHubCheckPublicationAuthorization,
    decision: FutureSecurityCIVerdictDecision,
    repository: str,
    source_sha: str,
) -> None:
    if not isinstance(authorization, GitHubCheckPublicationAuthorization):
        raise ValueError(
            "authorization must be a GitHubCheckPublicationAuthorization"
        )
    _validate_repository_and_source(repository, source_sha)

    if authorization.client_id != decision.client_id:
        raise ValueError("authorization client does not match verdict client")
    if authorization.repository != repository:
        raise ValueError("authorization repository does not match requested repository")
    if authorization.source_sha != source_sha:
        raise ValueError("authorization source SHA does not match requested source")
    if authorization.verdict_sha256 != decision.verdict_sha256:
        raise ValueError("authorization verdict digest does not match supplied verdict")
    reporting_allowed = _require_exact_bool(
        "authorization.reporting_allowed",
        authorization.reporting_allowed,
    )
    merge_allowed = _require_exact_bool(
        "authorization.merge_allowed",
        authorization.merge_allowed,
    )
    deployment_allowed = _require_exact_bool(
        "authorization.deployment_allowed",
        authorization.deployment_allowed,
    )
    if reporting_allowed is not True:
        raise ValueError("GitHub Check reporting is not authorized")
    if merge_allowed is not False or deployment_allowed is not False:
        raise ValueError(
            "check-publication authorization must not grant merge or deployment"
        )

    verdict_deployment_authorized = _require_exact_bool(
        "decision.deployment_authorized",
        decision.deployment_authorized,
    )
    attack_path_mutation_allowed = _require_exact_bool(
        "decision.attack_path_mutation_allowed",
        decision.attack_path_mutation_allowed,
    )
    if verdict_deployment_authorized:
        raise ValueError("CI verdict must not authorize deployment")
    if attack_path_mutation_allowed:
        raise ValueError("CI verdict must not allow attack-path mutation")
    if decision.future_semantics != "unresolved":
        raise ValueError("CI verdict future_semantics must remain unresolved")
    if not _SHA256_RE.fullmatch(decision.verdict_sha256):
        raise ValueError("verdict_sha256 must be lowercase 64-hex text")


def _revalidate_supplied_decision(
    *,
    decision: FutureSecurityCIVerdictDecision,
    report: FutureAttackPathSecurityDeltaReport,
    graph_diff_policy_decision: FutureAttackPathGraphDiffPolicyDecision,
    policy: FutureSecurityCIVerdictPolicy,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> None:
    live = decide_future_security_ci_verdict(
        report,
        graph_diff_policy_decision,
        policy,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
    if decision != live:
        raise ValueError(
            "CI verdict is stale, tampered, cross-tenant, or lineage-drifted"
        )


def build_github_check_publication_request(
    *,
    decision: FutureSecurityCIVerdictDecision,
    report: FutureAttackPathSecurityDeltaReport,
    graph_diff_policy_decision: FutureAttackPathGraphDiffPolicyDecision,
    policy: FutureSecurityCIVerdictPolicy,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
    authorization: GitHubCheckPublicationAuthorization,
    repository: str,
    source_sha: str,
    check_name: str = "LightUp Security Twin",
) -> GitHubCheckPublicationRequest:
    """Build a deterministic reporting-only GitHub Check request."""

    _require_nonempty_text("check_name", check_name)
    _validate_authorization(
        authorization=authorization,
        decision=decision,
        repository=repository,
        source_sha=source_sha,
    )
    _revalidate_supplied_decision(
        decision=decision,
        report=report,
        graph_diff_policy_decision=graph_diff_policy_decision,
        policy=policy,
        preview=preview,
        proposal=proposal,
        resolutions=resolutions,
        contexts=contexts,
        state=state,
    )

    summary = "; ".join(decision.reason_codes)
    if not summary:
        summary = "No policy reason codes were emitted."

    payload = {
        "schema_version": PUBLICATION_SCHEMA_VERSION,
        "repository": repository,
        "source_sha": source_sha,
        "client_id": decision.client_id,
        "current_twin_id": decision.current_twin_id,
        "current_twin_version": decision.current_twin_version,
        "twin_id": decision.twin_id,
        "twin_version": decision.twin_version,
        "changeset_id": decision.changeset_id,
        "report_sha256": decision.report_sha256,
        "policy_sha256": decision.policy_sha256,
        "verdict_sha256": decision.verdict_sha256,
        "verdict": decision.verdict.value,
        "conclusion": decision.ci_conclusion,
        "check_name": check_name,
        "merge_authorized": False,
        "deployment_authorized": False,
    }
    request_sha256 = _canonical_digest(payload)

    return GitHubCheckPublicationRequest(
        schema_version=PUBLICATION_SCHEMA_VERSION,
        repository=repository,
        source_sha=source_sha,
        client_id=decision.client_id,
        current_twin_id=decision.current_twin_id,
        current_twin_version=decision.current_twin_version,
        twin_id=decision.twin_id,
        twin_version=decision.twin_version,
        changeset_id=decision.changeset_id,
        report_sha256=decision.report_sha256,
        policy_sha256=decision.policy_sha256,
        verdict_sha256=decision.verdict_sha256,
        verdict=decision.verdict.value,
        conclusion=decision.ci_conclusion,
        check_name=check_name,
        title=f"LightUp security verdict: {decision.verdict.value}",
        summary=summary,
        external_id=f"lightup:{request_sha256}",
        request_sha256=request_sha256,
    )


def publish_future_security_ci_verdict_check(
    *,
    publisher: GitHubCheckPublisher,
    decision: FutureSecurityCIVerdictDecision,
    report: FutureAttackPathSecurityDeltaReport,
    graph_diff_policy_decision: FutureAttackPathGraphDiffPolicyDecision,
    policy: FutureSecurityCIVerdictPolicy,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
    authorization: GitHubCheckPublicationAuthorization,
    repository: str,
    source_sha: str,
    check_name: str = "LightUp Security Twin",
) -> GitHubCheckPublicationReceipt:
    """Publish one exact revalidated verdict through an injected idempotent adapter."""

    if publisher is None or not callable(getattr(publisher, "publish_once", None)):
        raise ValueError("publisher must implement publish_once(request)")

    request = build_github_check_publication_request(
        decision=decision,
        report=report,
        graph_diff_policy_decision=graph_diff_policy_decision,
        policy=policy,
        preview=preview,
        proposal=proposal,
        resolutions=resolutions,
        contexts=contexts,
        state=state,
        authorization=authorization,
        repository=repository,
        source_sha=source_sha,
        check_name=check_name,
    )
    provider_receipt_id = publisher.publish_once(request)
    _require_nonempty_text("provider_receipt_id", provider_receipt_id)

    publication_sha256 = _canonical_digest(
        {
            "schema_version": PUBLICATION_SCHEMA_VERSION,
            "request_sha256": request.request_sha256,
            "provider_receipt_id": provider_receipt_id,
            "merge_authorized": False,
            "deployment_authorized": False,
        }
    )
    return GitHubCheckPublicationReceipt(
        schema_version=PUBLICATION_SCHEMA_VERSION,
        repository=request.repository,
        source_sha=request.source_sha,
        verdict_sha256=request.verdict_sha256,
        conclusion=request.conclusion,
        check_name=request.check_name,
        external_id=request.external_id,
        request_sha256=request.request_sha256,
        provider_receipt_id=provider_receipt_id,
        publication_sha256=publication_sha256,
    )
