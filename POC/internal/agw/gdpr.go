package agw

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/redis/go-redis/v9"
)

type GDPRDeleteParams struct {
	SPIFFEID         string
	KeyDBURL         string
	AuditSource      string
	AuditLogPath     string
	AuditProjectRoot string
	ReportsDir       string
	Now              time.Time
}

type GDPRDeleteCategory struct {
	Category     string `json:"category"`
	ItemsDeleted int    `json:"items_deleted"`
	Status       string `json:"status"`
}

type GDPRDeleteReport struct {
	SPIFFEID            string               `json:"spiffe_id"`
	Timestamp           string               `json:"timestamp"`
	Categories          []GDPRDeleteCategory `json:"categories"`
	TotalItemsProcessed int                  `json:"total_items_processed"`
	DeletionCertificate string               `json:"deletion_certificate"`
	AuditMarkerPath     string               `json:"audit_marker_path"`
}

type GDPRAuditParams struct {
	SPIFFEID         string
	KeyDBURL         string
	AuditSource      string
	AuditLogPath     string
	AuditProjectRoot string
	ReportsDir       string
	OPAPolicyDir     string
	ToolRegistryPath string
	SPIREReader      gdprSPIREReader
	Now              time.Time
}

type DSARSessionData struct {
	SessionID  string         `json:"session_id"`
	RedisKey   string         `json:"redis_key"`
	TTLSeconds int            `json:"ttl_seconds"`
	Session    map[string]any `json:"session"`
	Actions    []any          `json:"actions"`
}

type DSARRateLimitData struct {
	SPIFFEID   string         `json:"spiffe_id"`
	Keys       map[string]any `json:"keys"`
	TTLSeconds map[string]int `json:"ttl_seconds"`
}

type DSARIdentityDetails struct {
	SPIFFEID     string       `json:"spiffe_id"`
	SPIREEntries []SPIREEntry `json:"spire_entries"`
}

type DSARSummary struct {
	SPIFFEID    string            `json:"spiffe_id"`
	GeneratedAt string            `json:"generated_at"`
	PackageDir  string            `json:"package_dir"`
	Files       map[string]string `json:"files"`
	Counts      map[string]int    `json:"counts"`
}

type DSARExportResult struct {
	SPIFFEID            string `json:"spiffe_id"`
	PackageDir          string `json:"package_dir"`
	SummaryPath         string `json:"summary_path"`
	AuditEntriesPath    string `json:"audit_entries_path"`
	SessionDataPath     string `json:"session_data_path"`
	RateLimitDataPath   string `json:"rate_limit_data_path"`
	IdentityDetailsPath string `json:"identity_details_path"`
	PolicyGrantsPath    string `json:"policy_grants_path"`
}

type gdprSPIREReader interface {
	ListEntries(ctx context.Context) ([]SPIREEntry, error)
}

func DeleteGDPRSubjectData(ctx context.Context, p GDPRDeleteParams) (GDPRDeleteReport, error) {
	spiffeID := strings.TrimSpace(p.SPIFFEID)
	if spiffeID == "" {
		return GDPRDeleteReport{}, errors.New("spiffe-id is empty")
	}
	keydbURL := strings.TrimSpace(p.KeyDBURL)
	if keydbURL == "" {
		return GDPRDeleteReport{}, errors.New("keydb URL is empty")
	}

	now := p.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	projectRoot := strings.TrimSpace(p.AuditProjectRoot)
	if projectRoot == "" {
		projectRoot = "."
	}

	reportsDir := strings.TrimSpace(p.ReportsDir)
	if reportsDir == "" {
		reportsDir = "reports"
	}

	client, err := NewKeyDBClient(keydbURL)
	if err != nil {
		return GDPRDeleteReport{}, err
	}
	defer func() {
		_ = client.Close()
	}()

	_, sessionKeys, err := DeleteSessionKeysForSPIFFEID(ctx, client, spiffeID)
	if err != nil {
		return GDPRDeleteReport{}, err
	}
	sessionsDeleted := countUniqueSessionsFromKeys(spiffeID, sessionKeys)

	rateLimitDeleted, _, err := DeleteRateLimitKeysForSPIFFEID(ctx, client, spiffeID)
	if err != nil {
		return GDPRDeleteReport{}, err
	}

	entries, err := LoadAuditEntries(ctx, p.AuditSource, projectRoot, p.AuditLogPath)
	if err != nil {
		return GDPRDeleteReport{}, fmt.Errorf("load audit entries: %w", err)
	}
	matchedAudit := filterAuditEntriesBySPIFFEID(entries, spiffeID)

	markerPath, markerCount, err := appendGDPRAuditMarkers(reportsDir, spiffeID, matchedAudit, now)
	if err != nil {
		return GDPRDeleteReport{}, err
	}

	categories := []GDPRDeleteCategory{
		{Category: "Sessions", ItemsDeleted: sessionsDeleted, Status: "deleted"},
		{Category: "Rate Limits", ItemsDeleted: int(rateLimitDeleted), Status: "deleted"},
		{Category: "Audit Entries", ItemsDeleted: markerCount, Status: "marked_deleted (preserved for audit trail)"},
	}

	report := GDPRDeleteReport{
		SPIFFEID:            spiffeID,
		Timestamp:           now.Format(time.RFC3339),
		Categories:          categories,
		TotalItemsProcessed: sessionsDeleted + int(rateLimitDeleted) + markerCount,
		AuditMarkerPath:     markerPath,
	}
	report.DeletionCertificate = computeDeletionCertificate(report)
	return report, nil
}

func ExportGDPRDSAR(ctx context.Context, p GDPRAuditParams) (DSARExportResult, error) {
	spiffeID := strings.TrimSpace(p.SPIFFEID)
	if spiffeID == "" {
		return DSARExportResult{}, errors.New("spiffe-id is empty")
	}
	keydbURL := strings.TrimSpace(p.KeyDBURL)
	if keydbURL == "" {
		return DSARExportResult{}, errors.New("keydb URL is empty")
	}

	reportsDir := strings.TrimSpace(p.ReportsDir)
	if reportsDir == "" {
		reportsDir = "reports"
	}
	projectRoot := strings.TrimSpace(p.AuditProjectRoot)
	if projectRoot == "" {
		projectRoot = "."
	}

	now := p.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	client, err := NewKeyDBClient(keydbURL)
	if err != nil {
		return DSARExportResult{}, err
	}
	defer func() {
		_ = client.Close()
	}()

	auditEntries, err := LoadAuditEntries(ctx, p.AuditSource, projectRoot, p.AuditLogPath)
	if err != nil {
		return DSARExportResult{}, fmt.Errorf("load audit entries: %w", err)
	}
	filteredAudit := filterAuditEntriesBySPIFFEID(auditEntries, spiffeID)

	sessions, err := collectDSARSessions(ctx, client, spiffeID)
	if err != nil {
		return DSARExportResult{}, err
	}
	rateLimitData, err := collectDSARRateLimitData(ctx, client, spiffeID)
	if err != nil {
		return DSARExportResult{}, err
	}

	spireReader := p.SPIREReader
	if spireReader == nil {
		spireReader = NewSPIRECLI()
	}
	spireEntries, err := spireReader.ListEntries(ctx)
	if err != nil {
		return DSARExportResult{}, fmt.Errorf("list SPIRE entries: %w", err)
	}
	identityDetails := DSARIdentityDetails{
		SPIFFEID:     spiffeID,
		SPIREEntries: filterSPIREEntriesBySPIFFEID(spireEntries, spiffeID),
	}

	policyGrants, err := ListPolicyGrants(p.OPAPolicyDir, p.ToolRegistryPath, spiffeID)
	if err != nil {
		return DSARExportResult{}, fmt.Errorf("list policy grants: %w", err)
	}

	packageDir := filepath.Join(
		reportsDir,
		fmt.Sprintf("gdpr-dsar-%s-%s", sanitizePathToken(spiffeID), now.Format("20060102-150405")),
	)
	if err := os.MkdirAll(packageDir, 0o755); err != nil {
		return DSARExportResult{}, fmt.Errorf("create DSAR directory: %w", err)
	}

	result := DSARExportResult{
		SPIFFEID:            spiffeID,
		PackageDir:          packageDir,
		SummaryPath:         filepath.Join(packageDir, "dsar-summary.json"),
		AuditEntriesPath:    filepath.Join(packageDir, "audit-entries.jsonl"),
		SessionDataPath:     filepath.Join(packageDir, "session-data.json"),
		RateLimitDataPath:   filepath.Join(packageDir, "rate-limit-data.json"),
		IdentityDetailsPath: filepath.Join(packageDir, "identity-details.json"),
		PolicyGrantsPath:    filepath.Join(packageDir, "policy-grants.json"),
	}

	if err := writeAuditJSONL(result.AuditEntriesPath, filteredAudit); err != nil {
		return DSARExportResult{}, err
	}
	if err := writePrettyJSON(result.SessionDataPath, sessions); err != nil {
		return DSARExportResult{}, err
	}
	if err := writePrettyJSON(result.RateLimitDataPath, rateLimitData); err != nil {
		return DSARExportResult{}, err
	}
	if err := writePrettyJSON(result.IdentityDetailsPath, identityDetails); err != nil {
		return DSARExportResult{}, err
	}
	if err := writePrettyJSON(result.PolicyGrantsPath, policyGrants); err != nil {
		return DSARExportResult{}, err
	}

	summary := DSARSummary{
		SPIFFEID:    spiffeID,
		GeneratedAt: now.Format(time.RFC3339),
		PackageDir:  packageDir,
		Files: map[string]string{
			"summary":          result.SummaryPath,
			"audit_entries":    result.AuditEntriesPath,
			"session_data":     result.SessionDataPath,
			"rate_limit_data":  result.RateLimitDataPath,
			"identity_details": result.IdentityDetailsPath,
			"policy_grants":    result.PolicyGrantsPath,
		},
		Counts: map[string]int{
			"audit_entries": len(filteredAudit),
			"sessions":      len(sessions),
			"spire_entries": len(identityDetails.SPIREEntries),
			"policy_grants": len(policyGrants.Grants),
		},
	}
	if err := writePrettyJSON(result.SummaryPath, summary); err != nil {
		return DSARExportResult{}, err
	}

	return result, nil
}

func RenderGDPRDeleteJSON(report GDPRDeleteReport) ([]byte, error) {
	b, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func RenderGDPRDeleteTable(report GDPRDeleteReport) (string, error) {
	var buf bytes.Buffer
	_, _ = fmt.Fprintln(&buf, "GDPR Right-to-Erasure Report")
	_, _ = fmt.Fprintf(&buf, "SPIFFE ID: %s\n", report.SPIFFEID)
	_, _ = fmt.Fprintf(&buf, "Timestamp: %s\n\n", report.Timestamp)

	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "CATEGORY\tITEMS DELETED\tSTATUS")
	for _, c := range report.Categories {
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%s\n", c.Category, c.ItemsDeleted, c.Status)
	}
	_ = tw.Flush()

	_, _ = fmt.Fprintf(&buf, "\nTotal items processed: %d\n", report.TotalItemsProcessed)
	_, _ = fmt.Fprintf(&buf, "Deletion certificate: %s\n", report.DeletionCertificate)
	return buf.String(), nil
}

func RenderDSARExportJSON(result DSARExportResult) ([]byte, error) {
	b, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func RenderDSARExportTable(result DSARExportResult) (string, error) {
	var buf bytes.Buffer
	_, _ = fmt.Fprintln(&buf, "GDPR Data Subject Access Request (DSAR) Package")
	_, _ = fmt.Fprintf(&buf, "SPIFFE ID: %s\n", result.SPIFFEID)
	_, _ = fmt.Fprintf(&buf, "Package: %s\n", result.PackageDir)
	_, _ = fmt.Fprintln(&buf, "FILES:")
	_, _ = fmt.Fprintf(&buf, "- %s\n", result.SummaryPath)
	_, _ = fmt.Fprintf(&buf, "- %s\n", result.AuditEntriesPath)
	_, _ = fmt.Fprintf(&buf, "- %s\n", result.SessionDataPath)
	_, _ = fmt.Fprintf(&buf, "- %s\n", result.RateLimitDataPath)
	_, _ = fmt.Fprintf(&buf, "- %s\n", result.IdentityDetailsPath)
	_, _ = fmt.Fprintf(&buf, "- %s\n", result.PolicyGrantsPath)
	return buf.String(), nil
}

func computeDeletionCertificate(report GDPRDeleteReport) string {
	type certPayload struct {
		SPIFFEID            string               `json:"spiffe_id"`
		Timestamp           string               `json:"timestamp"`
		Categories          []GDPRDeleteCategory `json:"categories"`
		TotalItemsProcessed int                  `json:"total_items_processed"`
		AuditMarkerPath     string               `json:"audit_marker_path"`
	}
	b, _ := json.Marshal(certPayload{
		SPIFFEID:            report.SPIFFEID,
		Timestamp:           report.Timestamp,
		Categories:          report.Categories,
		TotalItemsProcessed: report.TotalItemsProcessed,
		AuditMarkerPath:     report.AuditMarkerPath,
	})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func appendGDPRAuditMarkers(reportsDir, spiffeID string, entries []map[string]any, now time.Time) (string, int, error) {
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		return "", 0, fmt.Errorf("create reports dir: %w", err)
	}
	path := filepath.Join(reportsDir, "gdpr-audit-markers.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return "", 0, fmt.Errorf("open marker file: %w", err)
	}
	defer func() {
		_ = f.Close()
	}()

	sort.Slice(entries, func(i, j int) bool {
		ti := getString(entries[i], "timestamp")
		tj := getString(entries[j], "timestamp")
		if ti == tj {
			return getString(entries[i], "decision_id") < getString(entries[j], "decision_id")
		}
		return ti < tj
	})

	w := bufio.NewWriter(f)
	count := 0
	for _, entry := range entries {
		marker := map[string]any{
			"marker_type":      "gdpr_audit_entry_mark_deleted",
			"spiffe_id":        spiffeID,
			"decision_id":      getString(entry, "decision_id"),
			"timestamp":        getString(entry, "timestamp"),
			"tool":             getString(entry, "tool"),
			"result":           getString(entry, "result"),
			"gdpr_deleted":     true,
			"gdpr_deleted_at":  now.Format(time.RFC3339),
			"audit_preserved":  true,
			"source_status":    "preserved",
			"source_reference": "audit log entry retained, marker appended",
		}
		if code, ok := getInt(entry, "status_code"); ok {
			marker["status_code"] = code
		}
		line, err := json.Marshal(marker)
		if err != nil {
			return "", 0, fmt.Errorf("marshal marker: %w", err)
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			return "", 0, fmt.Errorf("write marker: %w", err)
		}
		count++
	}
	if err := w.Flush(); err != nil {
		return "", 0, fmt.Errorf("flush marker file: %w", err)
	}
	return path, count, nil
}

func filterAuditEntriesBySPIFFEID(entries []map[string]any, spiffeID string) []map[string]any {
	filtered := make([]map[string]any, 0, len(entries))
	for _, entry := range entries {
		if getString(entry, "spiffe_id") != spiffeID {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func countUniqueSessionsFromKeys(spiffeID string, keys []string) int {
	prefix := "session:" + spiffeID + ":"
	seen := make(map[string]struct{})
	for _, key := range keys {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		rest := strings.TrimPrefix(key, prefix)
		rest = strings.TrimSuffix(rest, ":actions")
		rest = strings.TrimSpace(rest)
		if rest == "" {
			continue
		}
		seen[rest] = struct{}{}
	}
	return len(seen)
}

func collectDSARSessions(ctx context.Context, client *redis.Client, spiffeID string) ([]DSARSessionData, error) {
	var cursor uint64
	out := make([]DSARSessionData, 0, 16)
	pattern := "session:" + spiffeID + ":*"
	for {
		keys, next, err := client.Scan(ctx, cursor, pattern, 200).Result()
		if err != nil {
			return nil, fmt.Errorf("scan session keys: %w", err)
		}
		for _, key := range keys {
			if strings.HasSuffix(key, ":actions") {
				continue
			}
			sessionRaw, err := client.Get(ctx, key).Bytes()
			if err != nil {
				if errors.Is(err, redis.Nil) {
					continue
				}
				return nil, fmt.Errorf("get session %s: %w", key, err)
			}

			sessionPayload := map[string]any{}
			if err := json.Unmarshal(sessionRaw, &sessionPayload); err != nil {
				sessionPayload = map[string]any{"raw": string(sessionRaw)}
			}

			actionsKey := key + ":actions"
			actionRows, err := client.LRange(ctx, actionsKey, 0, -1).Result()
			if err != nil && !errors.Is(err, redis.Nil) {
				return nil, fmt.Errorf("lrange %s: %w", actionsKey, err)
			}
			actions := make([]any, 0, len(actionRows))
			for _, row := range actionRows {
				var parsed any
				if err := json.Unmarshal([]byte(row), &parsed); err != nil {
					actions = append(actions, map[string]any{"raw": row})
					continue
				}
				actions = append(actions, parsed)
			}

			ttl, err := client.TTL(ctx, key).Result()
			if err != nil {
				return nil, fmt.Errorf("ttl %s: %w", key, err)
			}
			ttlSeconds := int(ttl.Seconds())
			if ttlSeconds < 0 {
				ttlSeconds = 0
			}

			out = append(out, DSARSessionData{
				SessionID:  parseSessionIDFromSessionKey(spiffeID, key),
				RedisKey:   key,
				TTLSeconds: ttlSeconds,
				Session:    sessionPayload,
				Actions:    actions,
			})
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].SessionID == out[j].SessionID {
			return out[i].RedisKey < out[j].RedisKey
		}
		return out[i].SessionID < out[j].SessionID
	})
	return out, nil
}

func collectDSARRateLimitData(ctx context.Context, client *redis.Client, spiffeID string) (DSARRateLimitData, error) {
	keys := []string{
		"ratelimit:" + spiffeID,
		"ratelimit:" + spiffeID + ":tokens",
		"ratelimit:" + spiffeID + ":last_fill",
	}
	out := DSARRateLimitData{
		SPIFFEID:   spiffeID,
		Keys:       make(map[string]any, len(keys)),
		TTLSeconds: make(map[string]int, len(keys)),
	}

	for _, key := range keys {
		val, err := client.Get(ctx, key).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				continue
			}
			return DSARRateLimitData{}, fmt.Errorf("get rate limit key %s: %w", key, err)
		}
		out.Keys[key] = val

		ttl, err := client.TTL(ctx, key).Result()
		if err != nil {
			return DSARRateLimitData{}, fmt.Errorf("ttl for rate limit key %s: %w", key, err)
		}
		ttlSeconds := int(ttl.Seconds())
		if ttlSeconds < 0 {
			ttlSeconds = 0
		}
		out.TTLSeconds[key] = ttlSeconds
	}

	return out, nil
}

func parseSessionIDFromSessionKey(spiffeID, key string) string {
	prefix := "session:" + spiffeID + ":"
	if !strings.HasPrefix(key, prefix) {
		return key
	}
	rest := strings.TrimPrefix(key, prefix)
	rest = strings.TrimSuffix(rest, ":actions")
	if strings.TrimSpace(rest) == "" {
		return key
	}
	return rest
}

func filterSPIREEntriesBySPIFFEID(entries []SPIREEntry, spiffeID string) []SPIREEntry {
	out := make([]SPIREEntry, 0, len(entries))
	for _, entry := range entries {
		if strings.TrimSpace(entry.SPIFFEID) != spiffeID {
			continue
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].EntryID < out[j].EntryID
	})
	return out
}

func writePrettyJSON(path string, payload any) error {
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal %s: %w", path, err)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func writeAuditJSONL(path string, entries []map[string]any) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		_ = f.Close()
	}()

	w := bufio.NewWriter(f)
	for _, entry := range entries {
		line, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("marshal audit entry: %w", err)
		}
		if _, err := w.Write(append(line, '\n')); err != nil {
			return fmt.Errorf("write audit entry: %w", err)
		}
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush %s: %w", path, err)
	}
	return nil
}

func sanitizePathToken(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "unknown"
	}

	var b strings.Builder
	prevDash := false
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			prevDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	if len(out) > 96 {
		return strings.TrimRight(out[:96], "-")
	}
	return out
}
