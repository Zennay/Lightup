# Scope authorization: exact parameter-kind metadata

Status: **RED reference only / DRAFT HOLD**. Offline, synthetic, no real target I/O.

## Boundary
`ToolParameter.kind` is currently a Python annotation, not a runtime validation boundary. A non-`ParamKind` object exposing an `accepts` method can be used as trusted schema metadata by `ToolDefinition.validate_arguments`. A raw `"string"` value is also not a canonical enum member and currently fails with an implementation exception instead of a controlled `OrchestrationError`.

## Owner-gated acceptance
- Registry admission rejects every kind whose `type(kind) is not ParamKind` before registration or executor dispatch.
- Call-site validation fails closed with a stable controlled error for malformed legacy registry metadata.
- All canonical kinds retain their existing positive and negative validation behavior.
- No handler or evidence writer is reached for malformed metadata.
- Independently verify hosted + permanent VPS CI on the exact final SHA before promoting out of draft.

## Ownership and safety
This PR adds only an offline regression contract. It intentionally leaves the production registry and executor unchanged, preserving #156 registry owner and #107 executor owner. The `expectedFailure` tests mark unmet requirements; an all-green suite containing XFAILs is **not** security acceptance. No authorization issuance, grant activation, network, scanning, merge, or deployment.
