# POC OPA Policy
# This is a minimal placeholder policy for the POC setup
# Real policies will be implemented in later stories

package agentic.security

# Default deny
default allow = false

# Placeholder allow rule - will be replaced with real authz logic
allow {
    # TODO: Implement real authorization rules
    # For now, allow all for POC skeleton validation
    true
}
