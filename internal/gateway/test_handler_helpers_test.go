// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"strings"
)

func newPhase3CompositeHandler(gw *Gateway) http.Handler {
	controlHandler := gw.ControlHandler()
	dataHandler := gw.Handler()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/admin", strings.HasPrefix(r.URL.Path, "/admin/"), strings.HasPrefix(r.URL.Path, "/v1/connectors/"):
			controlHandler.ServeHTTP(w, r)
		default:
			dataHandler.ServeHTTP(w, r)
		}
	})
}
