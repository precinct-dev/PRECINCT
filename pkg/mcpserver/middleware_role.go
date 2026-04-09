// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package mcpserver

import (
	"context"
	"fmt"
)

// roleContextKey is the context key for the caller's role, set by
// upstream authentication middleware or transport-level identity.
type roleContextKey struct{}

// WithRole returns a copy of ctx carrying the given role string.
// This is typically called by authentication middleware before the
// request enters the tool pipeline.
func WithRole(ctx context.Context, role string) context.Context {
	return context.WithValue(ctx, roleContextKey{}, role)
}

// Role extracts the caller's role from the context. Returns an empty
// string if no role was set.
func Role(ctx context.Context) string {
	v, _ := ctx.Value(roleContextKey{}).(string)
	return v
}

// newRoleVisibilityMiddleware returns a Middleware that checks whether the
// calling role has visibility to the requested tool. The filter function
// receives the context and tool name, returning true if the call is
// allowed. The filter can extract the caller's role from the context via
// Role(ctx). When no role is present in the context, the call is allowed
// (the filter is only enforced when a role is explicitly set).
func newRoleVisibilityMiddleware(filter func(ctx context.Context, toolName string) bool) Middleware {
	return func(next ToolHandler) ToolHandler {
		return func(ctx context.Context, args map[string]any) (any, error) {
			role := Role(ctx)
			if role == "" {
				return next(ctx, args)
			}
			toolName := ToolNameFromContext(ctx)
			if !filter(ctx, toolName) {
				return nil, fmt.Errorf("tool %q is not visible to role %q", toolName, role)
			}
			return next(ctx, args)
		}
	}
}
