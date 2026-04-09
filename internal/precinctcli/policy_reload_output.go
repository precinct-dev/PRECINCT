// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcli

import (
	"encoding/json"
	"fmt"
	"strings"
)

func RenderPolicyReloadJSON(out PolicyReloadOutput) ([]byte, error) {
	b, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func RenderPolicyReloadTable(out PolicyReloadOutput) (string, error) {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "Policy reload successful\n")
	if out.CosignVerified {
		_, _ = fmt.Fprintf(&b, "Tool registry: %d tools loaded (cosign verified)\n", out.RegistryTools)
	} else {
		_, _ = fmt.Fprintf(&b, "Tool registry: %d tools loaded (cosign not configured)\n", out.RegistryTools)
	}
	_, _ = fmt.Fprintf(&b, "OPA policies: %d policies loaded\n", out.OPAPolicies)
	if strings.TrimSpace(out.Timestamp) != "" {
		_, _ = fmt.Fprintf(&b, "Timestamp: %s\n", out.Timestamp)
	}
	return b.String(), nil
}
