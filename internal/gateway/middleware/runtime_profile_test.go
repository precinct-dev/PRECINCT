// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsStrictRuntimeProfile(t *testing.T) {
	tests := []struct {
		name    string
		mode    string
		profile string
		want    bool
	}{
		{name: "prod mode strict", mode: "prod", profile: "dev", want: true},
		{name: "prod standard strict", mode: "dev", profile: "prod_standard", want: true},
		{name: "prod hipaa strict", mode: "dev", profile: "prod_regulated_hipaa", want: true},
		{name: "dev non-strict", mode: "dev", profile: "dev", want: false},
		{name: "empty non-strict", mode: "", profile: "", want: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := WithRuntimeProfile(context.Background(), tc.mode, tc.profile)
			if got := IsStrictRuntimeProfile(ctx); got != tc.want {
				t.Fatalf("IsStrictRuntimeProfile(%q,%q)=%t want %t", tc.mode, tc.profile, got, tc.want)
			}
		})
	}
}

func TestRuntimeProfileMiddlewareAddsContext(t *testing.T) {
	var gotMode, gotProfile string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMode = GetRuntimeSPIFFEMode(r.Context())
		gotProfile = GetRuntimeEnforcementProfile(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := RuntimeProfile(next, "prod", "prod_standard")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if gotMode != "prod" || gotProfile != "prod_standard" {
		t.Fatalf("unexpected runtime profile context mode=%q profile=%q", gotMode, gotProfile)
	}
}
