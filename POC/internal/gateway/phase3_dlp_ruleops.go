package gateway

import (
	"fmt"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

// dlpRuleOpsManager is Phase 3 scaffolding for managing the DLP ruleset lifecycle
// (CRUD, versioning, auditability). The POC currently ships with an in-process,
// code-defined ruleset (middleware.BuiltInScanner).
//
// RFA-owgw.7: In production, this would be backed by a governed store (GitOps,
// signed bundles, or an internal service) and include change approvals and
// deployment-safe rollouts. Here, we expose only "introspection" to make the
// control plane story concrete without introducing brittle state.
type dlpRuleOpsManager struct {
	activeScanner middleware.DLPScanner
	version       string
	digest        string
}

func newDLPRuleOpsManager() (*dlpRuleOpsManager, middleware.DLPScanner, error) {
	scanner := middleware.NewBuiltInScanner()

	version, digest := "", ""
	if mp, ok := any(scanner).(middleware.DLPScannerMetadataProvider); ok {
		version, digest = mp.ActiveRulesetMetadata()
	}
	if version == "" {
		version = "builtin"
	}
	if digest == "" {
		// Digest is best-effort; absence should not break request handling.
		digest = "unknown"
	}

	mgr := &dlpRuleOpsManager{
		activeScanner: scanner,
		version:       version,
		digest:        digest,
	}

	// Basic sanity to prevent nil scanner wiring.
	if mgr.activeScanner == nil {
		return nil, nil, fmt.Errorf("dlp scanner is nil")
	}
	return mgr, scanner, nil
}

func (m *dlpRuleOpsManager) ActiveRuleset() (version string, digest string) {
	if m == nil {
		return "", ""
	}
	return m.version, m.digest
}
