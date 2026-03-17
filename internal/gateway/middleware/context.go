package middleware

import (
	"context"
)

// Context keys for request-scoped data
type contextKey string

const (
	contextKeySessionID                 contextKey = "session_id"
	contextKeyDecisionID                contextKey = "decision_id"
	contextKeyTraceID                   contextKey = "trace_id"
	contextKeyAuthMethod                contextKey = "auth_method"
	contextKeySPIFFEID                  contextKey = "spiffe_id"
	contextKeyRequestBody               contextKey = "request_body"
	contextKeyToolHashVerified          contextKey = "tool_hash_verified"
	contextKeyOAuthScopes               contextKey = "oauth_scopes"
	contextKeyOAuthIssuer               contextKey = "oauth_issuer"
	contextKeyOPADecisionID             contextKey = "opa_decision_id"
	contextKeySecurityFlags             contextKey = "security_flags"
	contextKeyFlagsCollector            contextKey = "flags_collector" // RFA-9i2: mutable collector for upstream propagation
	contextKeySessionContext            contextKey = "session_context_engine"
	contextKeyUIEnabled                 contextKey = "ui_enabled"        // RFA-j2d.7: MCP-UI enabled flag
	contextKeyUICallOrigin              contextKey = "ui_call_origin"    // RFA-j2d.7: "model" or "app"
	contextKeyUIAppToolCalls            contextKey = "ui_app_tool_calls" // RFA-j2d.7: app session tool call count
	contextKeyUIResourceURI             contextKey = "ui_resource_uri"   // RFA-j2d.7: ui:// resource URI
	contextKeyDLPRulesetVer             contextKey = "dlp_ruleset_version"
	contextKeyDLPRulesetDigest          contextKey = "dlp_ruleset_digest"
	contextKeyRuntimeSPIFFEMode         contextKey = "runtime_spiffe_mode"
	contextKeyRuntimeEnforcementProfile contextKey = "runtime_enforcement_profile"
	contextKeyPrincipalLevel            contextKey = "principal_level"          // OC-h4m7: principal trust level (0=system, 1=owner, 2=operator, 3=agent, 4=external)
	contextKeyPrincipalRole             contextKey = "principal_role"           // OC-t7go: resolved principal authority
	contextKeyPrincipalRoleCollector    contextKey = "principal_role_collector" // OC-t7go: mutable collector for upstream propagation
)

// SecurityFlagsCollector is a mutable container for security flags that
// propagates upstream through Go's immutable context chain. The audit
// middleware (step 4) creates a collector and puts a pointer in the context.
// Downstream middleware (DLP at step 7, deep scan at step 10) append flags
// to the collector. When control returns to the audit middleware, it reads
// the collected flags -- solving the Go context upstream-propagation problem.
// RFA-9i2: Without this, safezone_flags never appeared in audit logs because
// context.WithValue creates child contexts invisible to parent middleware.
type SecurityFlagsCollector struct {
	Flags []string
}

// Append adds a flag to the collector if not already present.
func (c *SecurityFlagsCollector) Append(flag string) {
	for _, f := range c.Flags {
		if f == flag {
			return
		}
	}
	c.Flags = append(c.Flags, flag)
}

// AppendAll adds multiple flags to the collector.
func (c *SecurityFlagsCollector) AppendAll(flags []string) {
	for _, f := range flags {
		c.Append(f)
	}
}

// GetSessionID retrieves session ID from context
func GetSessionID(ctx context.Context) string {
	if v := ctx.Value(contextKeySessionID); v != nil {
		return v.(string)
	}
	return ""
}

// WithSessionID adds session ID to context
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, contextKeySessionID, sessionID)
}

// GetDecisionID retrieves decision ID from context
func GetDecisionID(ctx context.Context) string {
	if v := ctx.Value(contextKeyDecisionID); v != nil {
		return v.(string)
	}
	return ""
}

// WithDecisionID adds decision ID to context
func WithDecisionID(ctx context.Context, decisionID string) context.Context {
	return context.WithValue(ctx, contextKeyDecisionID, decisionID)
}

// GetTraceID retrieves trace ID from context
func GetTraceID(ctx context.Context) string {
	if v := ctx.Value(contextKeyTraceID); v != nil {
		return v.(string)
	}
	return ""
}

// WithTraceID adds trace ID to context
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, contextKeyTraceID, traceID)
}

// GetAuthMethod retrieves the authentication method from context.
func GetAuthMethod(ctx context.Context) string {
	if v := ctx.Value(contextKeyAuthMethod); v != nil {
		return v.(string)
	}
	return ""
}

// WithAuthMethod stores the authentication method in context.
func WithAuthMethod(ctx context.Context, authMethod string) context.Context {
	return context.WithValue(ctx, contextKeyAuthMethod, authMethod)
}

// GetSPIFFEID retrieves SPIFFE ID from context
func GetSPIFFEID(ctx context.Context) string {
	if v := ctx.Value(contextKeySPIFFEID); v != nil {
		return v.(string)
	}
	return ""
}

// WithSPIFFEID adds SPIFFE ID to context
func WithSPIFFEID(ctx context.Context, spiffeID string) context.Context {
	return context.WithValue(ctx, contextKeySPIFFEID, spiffeID)
}

// GetOAuthScopes retrieves OAuth scopes from context.
func GetOAuthScopes(ctx context.Context) []string {
	if v := ctx.Value(contextKeyOAuthScopes); v != nil {
		return v.([]string)
	}
	return nil
}

// WithOAuthScopes stores OAuth scopes in context.
func WithOAuthScopes(ctx context.Context, scopes []string) context.Context {
	if scopes == nil {
		return context.WithValue(ctx, contextKeyOAuthScopes, nil)
	}
	cloned := make([]string, len(scopes))
	copy(cloned, scopes)
	return context.WithValue(ctx, contextKeyOAuthScopes, cloned)
}

// GetOAuthIssuer retrieves the OAuth issuer from context.
func GetOAuthIssuer(ctx context.Context) string {
	if v := ctx.Value(contextKeyOAuthIssuer); v != nil {
		return v.(string)
	}
	return ""
}

// WithOAuthIssuer stores the OAuth issuer in context.
func WithOAuthIssuer(ctx context.Context, issuer string) context.Context {
	return context.WithValue(ctx, contextKeyOAuthIssuer, issuer)
}

// GetRequestBody retrieves captured request body from context
func GetRequestBody(ctx context.Context) []byte {
	if v := ctx.Value(contextKeyRequestBody); v != nil {
		return v.([]byte)
	}
	return nil
}

// WithRequestBody adds request body to context
func WithRequestBody(ctx context.Context, body []byte) context.Context {
	return context.WithValue(ctx, contextKeyRequestBody, body)
}

// GetToolHashVerified retrieves tool hash verification status from context
func GetToolHashVerified(ctx context.Context) bool {
	if v := ctx.Value(contextKeyToolHashVerified); v != nil {
		return v.(bool)
	}
	return false
}

// WithToolHashVerified adds tool hash verification status to context
func WithToolHashVerified(ctx context.Context, verified bool) context.Context {
	return context.WithValue(ctx, contextKeyToolHashVerified, verified)
}

// GetOPADecisionID retrieves OPA decision ID from context
func GetOPADecisionID(ctx context.Context) string {
	if v := ctx.Value(contextKeyOPADecisionID); v != nil {
		return v.(string)
	}
	return ""
}

// WithOPADecisionID adds OPA decision ID to context
func WithOPADecisionID(ctx context.Context, decisionID string) context.Context {
	return context.WithValue(ctx, contextKeyOPADecisionID, decisionID)
}

// GetSecurityFlags retrieves security flags from context
func GetSecurityFlags(ctx context.Context) []string {
	if v := ctx.Value(contextKeySecurityFlags); v != nil {
		return v.([]string)
	}
	return nil
}

// WithSecurityFlags adds security flags to context.
// It also appends to the SecurityFlagsCollector if one exists in the context,
// ensuring flags propagate upstream to the audit middleware. RFA-9i2.
func WithSecurityFlags(ctx context.Context, flags []string) context.Context {
	// Propagate to collector for upstream visibility (audit middleware)
	if c := GetFlagsCollector(ctx); c != nil {
		c.AppendAll(flags)
	}
	return context.WithValue(ctx, contextKeySecurityFlags, flags)
}

// GetFlagsCollector retrieves the mutable security flags collector from context.
// RFA-9i2: Used by audit middleware to read flags set by downstream middleware.
func GetFlagsCollector(ctx context.Context) *SecurityFlagsCollector {
	if v := ctx.Value(contextKeyFlagsCollector); v != nil {
		return v.(*SecurityFlagsCollector)
	}
	return nil
}

// WithFlagsCollector adds a mutable security flags collector to context.
// RFA-9i2: Created by audit middleware, read by audit middleware after next.ServeHTTP.
func WithFlagsCollector(ctx context.Context, collector *SecurityFlagsCollector) context.Context {
	return context.WithValue(ctx, contextKeyFlagsCollector, collector)
}

// GetUIEnabled retrieves MCP-UI enabled flag from context (RFA-j2d.7)
func GetUIEnabled(ctx context.Context) bool {
	if v := ctx.Value(contextKeyUIEnabled); v != nil {
		return v.(bool)
	}
	return false
}

// WithUIEnabled adds MCP-UI enabled flag to context (RFA-j2d.7)
func WithUIEnabled(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, contextKeyUIEnabled, enabled)
}

// GetUICallOrigin retrieves the UI call origin from context (RFA-j2d.7)
func GetUICallOrigin(ctx context.Context) string {
	if v := ctx.Value(contextKeyUICallOrigin); v != nil {
		return v.(string)
	}
	return ""
}

// WithUICallOrigin adds UI call origin to context (RFA-j2d.7)
func WithUICallOrigin(ctx context.Context, origin string) context.Context {
	return context.WithValue(ctx, contextKeyUICallOrigin, origin)
}

// GetUIAppToolCalls retrieves the app session tool call count from context (RFA-j2d.7)
func GetUIAppToolCalls(ctx context.Context) int {
	if v := ctx.Value(contextKeyUIAppToolCalls); v != nil {
		return v.(int)
	}
	return 0
}

// WithUIAppToolCalls adds app session tool call count to context (RFA-j2d.7)
func WithUIAppToolCalls(ctx context.Context, count int) context.Context {
	return context.WithValue(ctx, contextKeyUIAppToolCalls, count)
}

// GetUIResourceURI retrieves the UI resource URI from context (RFA-j2d.7)
func GetUIResourceURI(ctx context.Context) string {
	if v := ctx.Value(contextKeyUIResourceURI); v != nil {
		return v.(string)
	}
	return ""
}

// WithUIResourceURI adds UI resource URI to context (RFA-j2d.7)
func WithUIResourceURI(ctx context.Context, uri string) context.Context {
	return context.WithValue(ctx, contextKeyUIResourceURI, uri)
}

// GetDLPRulesetVersion retrieves the active DLP ruleset version, if available.
func GetDLPRulesetVersion(ctx context.Context) string {
	if v := ctx.Value(contextKeyDLPRulesetVer); v != nil {
		return v.(string)
	}
	return ""
}

// GetDLPRulesetDigest retrieves the active DLP ruleset digest, if available.
func GetDLPRulesetDigest(ctx context.Context) string {
	if v := ctx.Value(contextKeyDLPRulesetDigest); v != nil {
		return v.(string)
	}
	return ""
}

// WithDLPRulesetMetadata stores DLP ruleset metadata on the request context so
// it can be picked up by audit logging and error responses.
func WithDLPRulesetMetadata(ctx context.Context, version, digest string) context.Context {
	ctx = context.WithValue(ctx, contextKeyDLPRulesetVer, version)
	ctx = context.WithValue(ctx, contextKeyDLPRulesetDigest, digest)
	return ctx
}

// WithRuntimeProfile adds runtime mode/profile metadata to context so downstream
// middleware can apply profile-aware enforcement (for example fail-open vs fail-closed).
func WithRuntimeProfile(ctx context.Context, spiffeMode, enforcementProfile string) context.Context {
	ctx = context.WithValue(ctx, contextKeyRuntimeSPIFFEMode, spiffeMode)
	ctx = context.WithValue(ctx, contextKeyRuntimeEnforcementProfile, enforcementProfile)
	return ctx
}

// GetRuntimeSPIFFEMode returns the SPIFFE mode bound to the request context.
func GetRuntimeSPIFFEMode(ctx context.Context) string {
	if v := ctx.Value(contextKeyRuntimeSPIFFEMode); v != nil {
		return v.(string)
	}
	return ""
}

// GetRuntimeEnforcementProfile returns the active enforcement profile bound to
// the request context.
func GetRuntimeEnforcementProfile(ctx context.Context) string {
	if v := ctx.Value(contextKeyRuntimeEnforcementProfile); v != nil {
		return v.(string)
	}
	return ""
}

// GetPrincipalLevel retrieves the principal trust level from context (OC-h4m7).
// Returns 0 (system/highest trust) if not set.
func GetPrincipalLevel(ctx context.Context) int {
	if v := ctx.Value(contextKeyPrincipalLevel); v != nil {
		return v.(int)
	}
	return 0
}

// WithPrincipalLevel adds principal trust level to context (OC-h4m7).
func WithPrincipalLevel(ctx context.Context, level int) context.Context {
	return context.WithValue(ctx, contextKeyPrincipalLevel, level)
}

// GetPrincipalRole retrieves the resolved PrincipalRole from context.
// Returns a zero-value PrincipalRole (level 0, empty strings) if not set.
// OC-t7go: Used by audit middleware and downstream handlers to access
// the authority metadata resolved by the PrincipalHeaders middleware.
func GetPrincipalRole(ctx context.Context) PrincipalRole {
	if v := ctx.Value(contextKeyPrincipalRole); v != nil {
		return v.(PrincipalRole)
	}
	return PrincipalRole{}
}

// WithPrincipalRole stores a resolved PrincipalRole in the request context.
// It also writes to the PrincipalRoleCollector if one exists, so that the
// audit middleware (which created the collector) can read the role from
// its own context scope after next.ServeHTTP returns.
// OC-t7go: Set by PrincipalHeaders middleware after SPIFFE identity resolution.
func WithPrincipalRole(ctx context.Context, role PrincipalRole) context.Context {
	if c := GetPrincipalRoleCollector(ctx); c != nil {
		c.Role = &role
	}
	return context.WithValue(ctx, contextKeyPrincipalRole, role)
}

// PrincipalRoleCollector is a mutable container that allows the PrincipalRole
// resolved by a downstream middleware to propagate back to the audit middleware.
// This follows the same pattern as SecurityFlagsCollector (RFA-9i2): Go's
// context.WithValue creates child contexts invisible to parent middleware,
// so we use a shared mutable pointer instead.
// OC-t7go.
type PrincipalRoleCollector struct {
	Role *PrincipalRole
}

// GetPrincipalRoleCollector retrieves the mutable PrincipalRole collector from context.
func GetPrincipalRoleCollector(ctx context.Context) *PrincipalRoleCollector {
	if v := ctx.Value(contextKeyPrincipalRoleCollector); v != nil {
		return v.(*PrincipalRoleCollector)
	}
	return nil
}

// WithPrincipalRoleCollector adds a mutable PrincipalRole collector to context.
// OC-t7go: Created by audit middleware, read after next.ServeHTTP returns.
func WithPrincipalRoleCollector(ctx context.Context, collector *PrincipalRoleCollector) context.Context {
	return context.WithValue(ctx, contextKeyPrincipalRoleCollector, collector)
}
