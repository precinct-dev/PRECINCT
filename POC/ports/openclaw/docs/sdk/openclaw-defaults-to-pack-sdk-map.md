# OpenClaw Defaults To Pack/SDK Map

This table captures OpenClaw-specific defaults that were previously implicit and where they now live.

| Previous Default / Assumption | New Pack Field | SDK Hook Surface | Why This Keeps Core Agnostic |
|---|---|---|---|
| Default LLM/provider selection assumed by app wiring | `adapter_contract.model_routing.*` | `call_model_chat` request shaping in SDK demos | Core only enforces policy; app-specific model choice is declarative in pack + set by SDK |
| Tool set expected by OpenClaw workflows | `adapter_contract.tool_registration.required_tools` | SDK tool call adapter layer (`client.call(...)`) | Core registry remains generic; app expectations live in pack metadata |
| Unregistered tool denial + hash verification expectations | `adapter_contract.tool_registration.hash_verification` | SDK-side onboarding checks and conformance tests | Core does not learn app names/flows; only generic registry controls |
| Prompt-injection guardrail posture (DLP + deep scan contract) | `adapter_contract.gateway_guardrails.*` | SDK path-specific assertions (case-26 and injection tests) | Guardrail mechanism stays core-generic; app interpretation is pack-defined |
| Timeout semantics for gateway-mediated model route in non-strict mode | `adapter_contract.gateway_guardrails.decision_contract.timeout_behavior_*` | SDK case-26 handling (Go/Python parity) | Core unchanged; SDK/pack encode app-level acceptance criteria |
| Runtime differences between Compose and K8s | `adapter_contract.runtime_profile_hints.compose|k8s` | SDK runtime test selection and strictness toggles | Core behavior is stable; runtime nuance is profile data in pack |
