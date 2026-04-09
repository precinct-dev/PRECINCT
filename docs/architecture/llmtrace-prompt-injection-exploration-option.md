# Optional LLMTrace Prompt-Injection Backend (Exploration Option)

## Intent
Evaluate LLMTrace strictly as an optional prompt-injection analysis backend for customers who do not want Groq in the hot path.

## Scope Boundaries
- In scope:
  - Prompt-injection/jailbreak scoring backend option for gateway guard checks.
  - Provider diversification for guard model calls.
  - Comparative evaluation versus current Groq + DLP posture.
- Out of scope:
  - Replacing gateway policy/identity/tool mediation authority.
  - Replacing Arize/Phoenix observability stack.
  - Replacing core app-agnostic integration model.

## Architecture Principle
Gateway remains the enforcement authority.
LLMTrace is a pluggable detector option, not the security control-plane owner.

## Candidate Operating Modes
1. Default mode (current): existing guard backend path + current DLP posture.
2. Optional mode: LLMTrace-backed prompt-injection scoring for step-up/deep-scan guard decisions.
3. Hybrid mode: dual scoring and calibration mode for tuning thresholds before promotion.

## Decision Criteria for Promotion
1. Security outcome parity or improvement on adversarial prompt-injection tests.
2. No regression in deterministic deny-path behavior for tool/policy bypass cases.
3. Explicit fail-closed behavior in strict profiles.
4. Compose and Kubernetes validation evidence exists.
5. No overlap-driven duplication with Arize/Phoenix responsibilities.

## Operational Notes
- Local (Mac/Windows/Linux): should remain optional and off by default.
- Kubernetes: treat as additive component with explicit SLOs and dependency budgets.

## Current Program Position
This remains a planning/exploration option only. No default runtime integration is part of the baseline architecture.
