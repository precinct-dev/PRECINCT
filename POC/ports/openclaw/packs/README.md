# OpenClaw Integration Pack

This pack records OpenClaw-specific adaptation metadata while preserving gateway core agnosticism.

Primary manifest:

- `pack.v1.json`

Adapter contract sections in `pack.v1.json`:

- `adapter_contract.model_routing`
- `adapter_contract.tool_registration`
- `adapter_contract.gateway_guardrails`
- `adapter_contract.runtime_profile_hints`

Validation:

- `bash tests/e2e/validate_app_integration_pack_model.sh`
