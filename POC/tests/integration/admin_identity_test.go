package integration

import "os"

const defaultAdminSPIFFEID = "spiffe://poc.local/agents/mcp-client/dspy-researcher/dev"
const defaultNonAdminSPIFFEID = "spiffe://poc.local/agents/mcp-client/other/dev"

func adminSPIFFEIDForTest() string {
	if v := os.Getenv("ADMIN_SPIFFE_ID"); v != "" {
		return v
	}
	return defaultAdminSPIFFEID
}

func nonAdminSPIFFEIDForTest() string {
	return defaultNonAdminSPIFFEID
}
