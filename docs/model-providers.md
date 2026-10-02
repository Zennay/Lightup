# Model providers

The AI model gateway (`lightup.ai.gateway`) routes **roles** — planner, surface
analyst, security analyst, verifier, remediation advisor, report synthesizer —
to providers. *Which* model serves a role is configuration, never business
logic. This document describes how real providers are configured and how the
platform stays safe and offline by default.

## Default: offline and credential-free

With no configuration, `lightup.ai.config.build_gateway()` binds **every role**
to a deterministic `ScriptedProvider`. CI and lab evaluation run reproducibly
with no API keys and no network. The scripted provider echoes a role-tagged
response or replays a fixed script — it never touches a socket.

Inspect the active bindings at any time (offline, read-only):

```bash
PYTHONPATH=src python -m lightup.cli gateway-check
```

## Configuring real providers

Point `LIGHTUP_MODEL_CONFIG` at a JSON file. Credentials are resolved from the
environment at build time — the config file names the *environment variable*,
never the secret itself, so configuration can be committed and only the key
lives in the environment.

```bash
export LIGHTUP_ANTHROPIC_API_KEY=sk-...
export LIGHTUP_MODEL_CONFIG=/etc/lightup/models.json
PYTHONPATH=src python -m lightup.cli gateway-check   # shows the real bindings
```

See `config/models.example.json` for a complete example.

### Config schema

```json
{
  "providers": [
    {"id": "anthropic-main", "kind": "anthropic",
     "api_key_env": "LIGHTUP_ANTHROPIC_API_KEY",
     "endpoint": "https://api.anthropic.com/v1/messages",
     "timeout": 60.0}
  ],
  "roles": {
    "planner":             {"provider": "anthropic-main", "model": "claude-..."},
    "surface_analyst":     {"provider": "anthropic-main", "model": "claude-..."},
    "security_analyst":    {"provider": "anthropic-main", "model": "claude-..."},
    "verifier":            {"provider": "anthropic-main", "model": "claude-..."},
    "remediation_advisor": {"provider": "anthropic-main", "model": "claude-..."},
    "report_synthesizer":  {"provider": "anthropic-main", "model": "claude-..."}
  }
}
```

- `kind` is `scripted`, `anthropic`, or `openai`. The `openai` shape also fits
  many OpenAI-compatible local runtimes via an `endpoint` override.
- `endpoint` and `timeout` are optional per provider.
- Roles may point at different providers — e.g. a strong planner and a cheaper
  verifier — because routing is pure configuration.

## Provider neutrality

Vendor-specific request/response shapes live **only** in
`lightup.ai.providers` as `ProviderProfile` data (how to build the request
body, where the assistant text lives in the response, which auth header to
use). Adding a vendor is a new profile, not a new code path anywhere else.

## Fail-closed guarantees

The gateway is not a security boundary — scope, authorization and risk are
enforced by the execution policy and orchestration layer regardless of which
model produced a plan. But the provider layer still fails closed so bad
configuration can never silently degrade output:

1. A real provider with **no usable credential cannot be constructed**
   (`ProviderCredentialError`). The platform never falls back to a stub when a
   real provider was configured.
2. A **non-success HTTP status** or an unreachable endpoint raises
   (`ProviderRequestError`) — no fabricated or empty model output reaches the
   planner or pipeline.
3. A response we **cannot parse into non-empty text** raises
   (`ProviderResponseError`).
4. A config that leaves any **required role unbound** is rejected at build time
   (`GatewayConfigurationError`), not mid-run.
5. All provider I/O goes through an injectable transport, so tests never touch
   the network and a real call only happens when a real provider is both
   configured and invoked.

Configuring a real model provider does **not** enable real-target interaction.
Activation stays plan-only: there are still no real-target network adapters,
and the models only plan, analyse and write text behind the policy gate.
