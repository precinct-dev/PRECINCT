# Context Injection Policy - RFA-xwc
# Based on Reference Architecture Section 10.15.3
# Gates whether external context can be injected into the agent's request
# This is step 7 of the mandatory validation pipeline (Section 10.15.1)

package mcp.context

import rego.v1

# Default deny: external context injection is blocked unless all conditions pass
default allow_context := false

# Allow context injection when ALL of the following hold:
# 1. Content source is external (this policy only applies to external context)
# 2. Content has been validated (passed steps 1-6 of the pipeline)
# 3. Content is NOT classified as sensitive (DLP/PII check passed)
# 4. A valid content handle exists (UUID-based content_ref)
# 5. Session is NOT flagged as high-risk
allow_context if {
    input.context.source == "external"
    input.context.validated == true
    input.context.classification != "sensitive"
    input.context.handle != ""
    not session_is_high_risk
}

# Allow sensitive content with valid step-up authorization
# Per Section 10.15.3: sensitive content requires step-up gating
# Step-up token must be present AND session must NOT be high-risk
allow_context if {
    input.context.source == "external"
    input.context.validated == true
    input.context.classification == "sensitive"
    input.context.handle != ""
    not session_is_high_risk
    input.step_up_token != ""
}

# Check if session is flagged as high-risk
# Session flags is an object/set; "high_risk" being present means high-risk
session_is_high_risk if {
    input.session.flags["high_risk"]
}

# Denial reason helpers for structured error reporting
deny_reason := "content_not_external" if {
    input.context.source != "external"
}

deny_reason := "content_not_validated" if {
    input.context.source == "external"
    input.context.validated != true
}

deny_reason := "content_classified_sensitive" if {
    input.context.source == "external"
    input.context.validated == true
    input.context.classification == "sensitive"
    input.step_up_token == ""
}

deny_reason := "sensitive_requires_step_up_high_risk" if {
    input.context.source == "external"
    input.context.validated == true
    input.context.classification == "sensitive"
    input.step_up_token != ""
    session_is_high_risk
}

deny_reason := "missing_content_handle" if {
    input.context.source == "external"
    input.context.validated == true
    input.context.classification != "sensitive"
    input.context.handle == ""
}

deny_reason := "session_high_risk" if {
    input.context.source == "external"
    input.context.validated == true
    input.context.classification != "sensitive"
    input.context.handle != ""
    session_is_high_risk
}
