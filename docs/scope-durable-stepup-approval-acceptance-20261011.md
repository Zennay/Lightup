# Durable operator approval: release acceptance (offline only)

Issue #1173 remains open. The opt-in lab step-up wrapper on parent PR #1172 does not prove durable operator issuance, revocation, physical lab isolation, or enforcement on the default ToolExecutor.

A valid release must authenticate a current persisted operator session, bind an approval to one exact run, tenant, engagement, lab asset, capability and tool, and reject expired, revoked, duplicated, transferred, or malformed approvals. Approval and isolation are independent checks. No prompt, model output, lab marker, or request argument is consent. Source-owner review, default-path integration, network egress isolation, and exact-head permanent self-hosted CI remain required.

This document is an acceptance note only: it issues no approvals and authorizes no target interaction.
