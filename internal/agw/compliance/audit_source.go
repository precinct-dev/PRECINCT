package compliance

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	defaultOpenSearchURL       = "https://opensearch.observability.svc.cluster.local:9200"
	defaultOpenSearchIndex     = "precinct-audit-*"
	defaultOpenSearchWindow    = "168h"
	defaultOpenSearchMaxResult = 5000
)

type AuditCollectionOptions struct {
	Source       string
	AuditLogPath string
	OpenSearch   OpenSearchAuditOptions
}

type OpenSearchAuditOptions struct {
	URL                string
	Index              string
	Username           string
	Password           string
	CACertPath         string
	ClientCertPath     string
	ClientKeyPath      string
	TimeWindow         string
	MaxEntries         int
	InsecureSkipVerify bool
}

func CollectAuditEntriesWithOptions(projectRoot string, opts AuditCollectionOptions) ([]map[string]any, string, error) {
	source := strings.ToLower(strings.TrimSpace(opts.Source))
	auditLogPath := defaultAuditLogPath(opts.AuditLogPath)

	switch source {
	case "", "auto":
		if _, err := os.Stat(auditLogPath); err == nil {
			entries, err := LoadAuditJSONLEntries(auditLogPath)
			return entries, auditLogPath, err
		}
		entries, err := LoadAuditFromDockerComposeLogs(projectRoot)
		if err != nil {
			return []map[string]any{}, "docker compose logs (unavailable)", nil
		}
		return entries, "docker compose logs", nil
	case "file":
		entries, err := LoadAuditJSONLEntries(auditLogPath)
		return entries, auditLogPath, err
	case "docker":
		entries, err := LoadAuditFromDockerComposeLogs(projectRoot)
		if err != nil {
			return []map[string]any{}, "docker compose logs (unavailable)", nil
		}
		return entries, "docker compose logs", nil
	case "opensearch":
		entries, src, err := LoadAuditFromOpenSearch(opts.OpenSearch)
		if err != nil {
			return nil, "", err
		}
		return entries, src, nil
	default:
		return nil, "", fmt.Errorf("invalid audit source %q (expected auto|file|docker|opensearch)", source)
	}
}

func LoadAuditFromOpenSearch(opts OpenSearchAuditOptions) ([]map[string]any, string, error) {
	baseURL := strings.TrimSpace(opts.URL)
	if baseURL == "" {
		baseURL = defaultOpenSearchURL
	}
	if !strings.HasPrefix(strings.ToLower(baseURL), "https://") {
		return nil, "", fmt.Errorf("OpenSearch URL must use https://")
	}

	index := strings.TrimSpace(opts.Index)
	if index == "" {
		index = defaultOpenSearchIndex
	}

	window := strings.TrimSpace(strings.ToLower(opts.TimeWindow))
	if window == "" {
		window = defaultOpenSearchWindow
	}
	if _, err := parseDurationOrDays(window); err != nil {
		return nil, "", fmt.Errorf("invalid OpenSearch time window %q: %w", window, err)
	}

	maxEntries := opts.MaxEntries
	if maxEntries <= 0 {
		maxEntries = defaultOpenSearchMaxResult
	}
	if maxEntries > 10000 {
		maxEntries = 10000
	}

	tlsConfig := &tls.Config{ //nolint:gosec // controlled by explicit CLI flags and secrets
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: opts.InsecureSkipVerify,
	}

	if caPath := strings.TrimSpace(opts.CACertPath); caPath != "" {
		caBytes, err := os.ReadFile(caPath)
		if err != nil {
			return nil, "", fmt.Errorf("read OpenSearch CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(caBytes); !ok {
			return nil, "", fmt.Errorf("parse OpenSearch CA cert: no PEM blocks")
		}
		tlsConfig.RootCAs = pool
	}

	clientCert := strings.TrimSpace(opts.ClientCertPath)
	clientKey := strings.TrimSpace(opts.ClientKeyPath)
	if (clientCert == "") != (clientKey == "") {
		return nil, "", fmt.Errorf("both OpenSearch client cert and key are required for mTLS")
	}
	if clientCert != "" {
		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			return nil, "", fmt.Errorf("load OpenSearch client certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	endpoint := strings.TrimRight(baseURL, "/") + "/" + path.Clean("/"+index+"/_search")
	query := map[string]any{
		"size": maxEntries,
		"sort": []map[string]any{
			{"timestamp": map[string]any{"order": "asc", "unmapped_type": "date"}},
			{"@timestamp": map[string]any{"order": "asc", "unmapped_type": "date"}},
		},
		"query": map[string]any{
			"bool": map[string]any{
				"should": []map[string]any{
					{"range": map[string]any{"timestamp": map[string]any{"gte": "now-" + window, "lte": "now"}}},
					{"range": map[string]any{"@timestamp": map[string]any{"gte": "now-" + window, "lte": "now"}}},
				},
				"minimum_should_match": 1,
			},
		},
	}

	body, err := json.Marshal(query)
	if err != nil {
		return nil, "", fmt.Errorf("marshal OpenSearch query: %w", err)
	}

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig, //nolint:gosec
		},
	}

	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("create OpenSearch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if user := strings.TrimSpace(opts.Username); user != "" {
		req.SetBasicAuth(user, opts.Password)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("OpenSearch query failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		payload, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, "", fmt.Errorf("OpenSearch query returned status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(payload)))
	}

	var parsed struct {
		Hits struct {
			Hits []struct {
				ID     string         `json:"_id"`
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, "", fmt.Errorf("decode OpenSearch response: %w", err)
	}

	entries := make([]map[string]any, 0, len(parsed.Hits.Hits))
	for _, h := range parsed.Hits.Hits {
		if h.Source == nil {
			continue
		}
		if _, exists := h.Source["_id"]; !exists && strings.TrimSpace(h.ID) != "" {
			h.Source["_id"] = h.ID
		}
		entries = append(entries, h.Source)
	}

	sourceDescriptor := fmt.Sprintf("opensearch:%s/%s", strings.TrimPrefix(baseURL, "https://"), index)
	return entries, sourceDescriptor, nil
}

func parseDurationOrDays(v string) (time.Duration, error) {
	s := strings.TrimSpace(strings.ToLower(v))
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("invalid day duration %q", v)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("invalid duration %q", v)
	}
	return d, nil
}
