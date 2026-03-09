package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/example/agentic-security-poc/internal/gateway/middleware"
)

const (
	dlpRulesetStateDraft    = "draft"
	dlpRulesetStateApproved = "approved"
	dlpRulesetStateActive   = "active"
)

type dlpRuleset struct {
	Version            string    `json:"version"`
	Digest             string    `json:"digest"`
	State              string    `json:"state"`
	CredentialPatterns []string  `json:"credential_patterns,omitempty"`
	PIIPatterns        []string  `json:"pii_patterns,omitempty"`
	SuspiciousPatterns []string  `json:"suspicious_patterns,omitempty"`
	Approved           bool      `json:"approved"`
	Signed             bool      `json:"signed"`
	Approver           string    `json:"approver,omitempty"`
	Signature          string    `json:"signature,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type dlpRulesetUpsertRequest struct {
	Version            string   `json:"version"`
	CredentialPatterns []string `json:"credential_patterns,omitempty"`
	PIIPatterns        []string `json:"pii_patterns,omitempty"`
	SuspiciousPatterns []string `json:"suspicious_patterns,omitempty"`
}

type dlpRulesetApproveRequest struct {
	Approver  string `json:"approver"`
	Signature string `json:"signature"`
}

type dlpRulesetRollbackRequest struct {
	TargetVersion string `json:"target_version,omitempty"`
}

type dlpRuleOpsManager struct {
	mu            sync.RWMutex
	rulesets      map[string]*dlpRuleset
	activeVersion string
	previous      string
	scanner       *managedDLPScanner
}

func newDLPRuleOpsManager() (*dlpRuleOpsManager, middleware.DLPScanner, error) {
	mgr := &dlpRuleOpsManager{
		rulesets: make(map[string]*dlpRuleset),
		scanner:  newManagedDLPScanner(),
	}

	// Baseline built-in ruleset is active and trusted by default.
	builtinReq := dlpRulesetUpsertRequest{
		Version:            "builtin-v1",
		CredentialPatterns: nil,
		PIIPatterns:        nil,
		SuspiciousPatterns: nil,
	}
	rs, _, err := mgr.upsertDraft(builtinReq, time.Now().UTC())
	if err != nil {
		return nil, nil, err
	}
	rs.Approved = true
	rs.Signed = true
	rs.Approver = "system-bootstrap"
	rs.Signature = "bootstrap"
	rs.State = dlpRulesetStateActive
	mgr.activeVersion = rs.Version
	mgr.previous = ""
	if err := mgr.scanner.setActiveRuleset(*rs); err != nil {
		return nil, nil, err
	}
	return mgr, mgr.scanner, nil
}

func (m *dlpRuleOpsManager) upsertDraft(req dlpRulesetUpsertRequest, now time.Time) (*dlpRuleset, bool, error) {
	version := strings.TrimSpace(req.Version)
	if version == "" {
		return nil, false, fmt.Errorf("version is required")
	}

	normalized := dlpRuleset{
		Version:            version,
		CredentialPatterns: dedupeAndSortPatterns(req.CredentialPatterns),
		PIIPatterns:        dedupeAndSortPatterns(req.PIIPatterns),
		SuspiciousPatterns: dedupeAndSortPatterns(req.SuspiciousPatterns),
	}
	digest, err := computeDLPRulesetDigest(normalized)
	if err != nil {
		return nil, false, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	rs, exists := m.rulesets[version]
	if !exists {
		rs = &dlpRuleset{
			Version:   version,
			CreatedAt: now,
		}
		m.rulesets[version] = rs
	}

	rs.CredentialPatterns = normalized.CredentialPatterns
	rs.PIIPatterns = normalized.PIIPatterns
	rs.SuspiciousPatterns = normalized.SuspiciousPatterns
	rs.Digest = digest
	rs.State = dlpRulesetStateDraft
	rs.Approved = false
	rs.Signed = false
	rs.Approver = ""
	rs.Signature = ""
	rs.UpdatedAt = now
	return cloneRuleset(rs), !exists, nil
}

func (m *dlpRuleOpsManager) approve(version, approver, signature string, now time.Time) (*dlpRuleset, error) {
	version = strings.TrimSpace(version)
	approver = strings.TrimSpace(approver)
	signature = strings.TrimSpace(signature)
	if version == "" {
		return nil, fmt.Errorf("version is required")
	}
	if approver == "" {
		return nil, fmt.Errorf("approver is required")
	}
	if signature == "" {
		return nil, fmt.Errorf("signature is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	rs, ok := m.rulesets[version]
	if !ok {
		return nil, fmt.Errorf("ruleset not found: %s", version)
	}
	rs.Approved = true
	rs.Signed = true
	rs.Approver = approver
	rs.Signature = signature
	if rs.State != dlpRulesetStateActive {
		rs.State = dlpRulesetStateApproved
	}
	rs.UpdatedAt = now
	return cloneRuleset(rs), nil
}

func (m *dlpRuleOpsManager) promote(version string, now time.Time) (*dlpRuleset, error) {
	version = strings.TrimSpace(version)
	if version == "" {
		return nil, fmt.Errorf("version is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	rs, ok := m.rulesets[version]
	if !ok {
		return nil, fmt.Errorf("ruleset not found: %s", version)
	}
	if !rs.Approved || !rs.Signed || strings.TrimSpace(rs.Signature) == "" {
		return nil, fmt.Errorf("ruleset %s is not approved/signed", version)
	}
	if err := m.scanner.setActiveRuleset(*rs); err != nil {
		return nil, err
	}

	if m.activeVersion != "" && m.activeVersion != version {
		if prev, ok := m.rulesets[m.activeVersion]; ok {
			prev.State = dlpRulesetStateApproved
			prev.UpdatedAt = now
		}
		m.previous = m.activeVersion
	}

	m.activeVersion = version
	rs.State = dlpRulesetStateActive
	rs.UpdatedAt = now
	return cloneRuleset(rs), nil
}

func (m *dlpRuleOpsManager) rollback(targetVersion string, now time.Time) (*dlpRuleset, error) {
	targetVersion = strings.TrimSpace(targetVersion)

	m.mu.Lock()
	defer m.mu.Unlock()

	if targetVersion == "" {
		targetVersion = m.previous
	}
	if targetVersion == "" {
		return nil, fmt.Errorf("no previous active ruleset available")
	}

	rs, ok := m.rulesets[targetVersion]
	if !ok {
		return nil, fmt.Errorf("ruleset not found: %s", targetVersion)
	}
	if !rs.Approved || !rs.Signed || strings.TrimSpace(rs.Signature) == "" {
		return nil, fmt.Errorf("ruleset %s is not approved/signed", targetVersion)
	}

	if err := m.scanner.setActiveRuleset(*rs); err != nil {
		return nil, err
	}

	if m.activeVersion != "" && m.activeVersion != targetVersion {
		if prev, ok := m.rulesets[m.activeVersion]; ok {
			prev.State = dlpRulesetStateApproved
			prev.UpdatedAt = now
		}
		m.previous = m.activeVersion
	}
	m.activeVersion = targetVersion
	rs.State = dlpRulesetStateActive
	rs.UpdatedAt = now
	return cloneRuleset(rs), nil
}

func (m *dlpRuleOpsManager) active() (*dlpRuleset, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.activeVersion == "" {
		return nil, false
	}
	rs, ok := m.rulesets[m.activeVersion]
	if !ok {
		return nil, false
	}
	return cloneRuleset(rs), true
}

func (m *dlpRuleOpsManager) list() []dlpRuleset {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]dlpRuleset, 0, len(m.rulesets))
	for _, rs := range m.rulesets {
		out = append(out, *cloneRuleset(rs))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out
}

type managedDLPScanner struct {
	base *middleware.BuiltInScanner

	mu                 sync.RWMutex
	activeVersion      string
	activeDigest       string
	credentialPatterns []*regexp.Regexp
	piiPatterns        []*regexp.Regexp
	suspiciousPatterns []*regexp.Regexp
}

func newManagedDLPScanner() *managedDLPScanner {
	return &managedDLPScanner{
		base:               middleware.NewBuiltInScanner(),
		credentialPatterns: make([]*regexp.Regexp, 0),
		piiPatterns:        make([]*regexp.Regexp, 0),
		suspiciousPatterns: make([]*regexp.Regexp, 0),
	}
}

func (s *managedDLPScanner) Scan(content string) middleware.ScanResult {
	result := s.base.Scan(content)

	s.mu.RLock()
	creds := append([]*regexp.Regexp(nil), s.credentialPatterns...)
	pii := append([]*regexp.Regexp(nil), s.piiPatterns...)
	susp := append([]*regexp.Regexp(nil), s.suspiciousPatterns...)
	s.mu.RUnlock()

	for _, p := range creds {
		if p.MatchString(content) {
			result.HasCredentials = true
			if !containsString(result.Flags, "blocked_content") {
				result.Flags = append(result.Flags, "blocked_content")
			}
			break
		}
	}
	for _, p := range pii {
		if p.MatchString(content) {
			result.HasPII = true
			if !containsString(result.Flags, "potential_pii") {
				result.Flags = append(result.Flags, "potential_pii")
			}
		}
	}
	for _, p := range susp {
		if p.MatchString(content) {
			result.HasSuspicious = true
			if !containsString(result.Flags, "potential_injection") {
				result.Flags = append(result.Flags, "potential_injection")
			}
		}
	}
	return result
}

func (s *managedDLPScanner) ActiveRulesetMetadata() (string, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeVersion, s.activeDigest
}

func (s *managedDLPScanner) setActiveRuleset(rs dlpRuleset) error {
	cred, err := compilePatterns(rs.CredentialPatterns)
	if err != nil {
		return fmt.Errorf("invalid credential pattern: %w", err)
	}
	pii, err := compilePatterns(rs.PIIPatterns)
	if err != nil {
		return fmt.Errorf("invalid pii pattern: %w", err)
	}
	susp, err := compilePatterns(rs.SuspiciousPatterns)
	if err != nil {
		return fmt.Errorf("invalid suspicious pattern: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.credentialPatterns = cred
	s.piiPatterns = pii
	s.suspiciousPatterns = susp
	s.activeVersion = rs.Version
	s.activeDigest = rs.Digest
	return nil
}

func compilePatterns(patterns []string) ([]*regexp.Regexp, error) {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		p := strings.TrimSpace(pattern)
		if p == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

func dedupeAndSortPatterns(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, pattern := range in {
		p := strings.TrimSpace(pattern)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func computeDLPRulesetDigest(rs dlpRuleset) (string, error) {
	canonical := map[string]any{
		"version":             rs.Version,
		"credential_patterns": rs.CredentialPatterns,
		"pii_patterns":        rs.PIIPatterns,
		"suspicious_patterns": rs.SuspiciousPatterns,
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshal ruleset for digest: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func cloneRuleset(rs *dlpRuleset) *dlpRuleset {
	if rs == nil {
		return nil
	}
	clone := *rs
	clone.CredentialPatterns = append([]string(nil), rs.CredentialPatterns...)
	clone.PIIPatterns = append([]string(nil), rs.PIIPatterns...)
	clone.SuspiciousPatterns = append([]string(nil), rs.SuspiciousPatterns...)
	return &clone
}

func containsString(in []string, item string) bool {
	for _, existing := range in {
		if existing == item {
			return true
		}
	}
	return false
}
