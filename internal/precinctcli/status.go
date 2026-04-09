// Copyright 2024-2026 The PRECINCT Authors
// SPDX-License-Identifier: Apache-2.0

package precinctcli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

type Deps struct {
	HTTPClient *http.Client
	Docker     DockerLister
	Exec       ExecRunner
	ReadFile   func(path string) ([]byte, error)
	RedisDial  func(url string) (*redis.Client, error)
}

type Config struct {
	GatewayURL     string
	KeyDBURL       string
	PhoenixURL     string
	OtelHealthURL  string
	Component      string
	SpireConfPath  string
	DockerTimeout  time.Duration
	RequestTimeout time.Duration
}

func DefaultDeps() Deps {
	return Deps{
		HTTPClient: &http.Client{Timeout: 3 * time.Second},
		Docker:     ExecDockerLister{},
		Exec:       ExecRunnerFunc(runCombined),
		ReadFile:   defaultReadFile,
		RedisDial: func(url string) (*redis.Client, error) {
			opt, err := redis.ParseURL(url)
			if err != nil {
				return nil, err
			}
			return redis.NewClient(opt), nil
		},
	}
}

func DefaultConfig() Config {
	return Config{
		SpireConfPath:  filepath.Join("config", "spire", "server.conf"),
		DockerTimeout:  5 * time.Second,
		RequestTimeout: 5 * time.Second,
	}
}

func CollectStatus(ctx context.Context, cfg Config, deps Deps) (StatusOutput, bool, error) {
	if cfg.GatewayURL == "" {
		return StatusOutput{}, false, errors.New("gateway URL is empty")
	}
	if cfg.KeyDBURL == "" {
		cfg.KeyDBURL = "redis://localhost:6379"
	}
	if cfg.PhoenixURL == "" {
		cfg.PhoenixURL = "http://localhost:6006"
	}
	if cfg.OtelHealthURL == "" {
		cfg.OtelHealthURL = "http://localhost:13133"
	}
	if cfg.SpireConfPath == "" {
		cfg.SpireConfPath = DefaultConfig().SpireConfPath
	}

	checkAll := strings.TrimSpace(cfg.Component) == ""

	var out StatusOutput
	add := func(cs ComponentStatus) {
		out.Components = append(out.Components, cs)
	}

	okAll := true

	if checkAll || cfg.Component == "gateway" {
		cs := checkGateway(ctx, cfg, deps)
		add(cs)
		okAll = okAll && strings.EqualFold(cs.Status, "ok")
	}
	if checkAll || cfg.Component == "keydb" {
		cs := checkKeyDB(ctx, cfg, deps)
		add(cs)
		okAll = okAll && strings.EqualFold(cs.Status, "ok")
	}
	if checkAll || cfg.Component == "spire-server" {
		cs := checkSpireServer(ctx, cfg, deps)
		add(cs)
		okAll = okAll && strings.EqualFold(cs.Status, "ok")
	}
	if checkAll || cfg.Component == "spike-nexus" {
		cs := checkDockerServiceHealth(ctx, deps, "spike-nexus", map[string]any{"tls_port": 8443})
		add(cs)
		okAll = okAll && strings.EqualFold(cs.Status, "ok")
	}
	if checkAll || cfg.Component == "phoenix" {
		cs := checkHTTP(ctx, deps, "phoenix", cfg.PhoenixURL, map[string]any{"port": 6006})
		add(cs)
		okAll = okAll && strings.EqualFold(cs.Status, "ok")
	}
	if checkAll || cfg.Component == "otel-collector" {
		cs := checkHTTP(ctx, deps, "otel-collector", cfg.OtelHealthURL, map[string]any{"port": 13133})
		add(cs)
		okAll = okAll && strings.EqualFold(cs.Status, "ok")
	}

	// Validate component name when provided.
	if !checkAll {
		if len(out.Components) == 0 {
			return StatusOutput{}, false, fmt.Errorf("unknown --component %q", cfg.Component)
		}
	}

	return out, okAll, nil
}

func checkGateway(ctx context.Context, cfg Config, deps Deps) ComponentStatus {
	h, err := getGatewayHealth(ctx, deps.HTTPClient, strings.TrimRight(cfg.GatewayURL, "/")+"/health")
	if err != nil {
		return ComponentStatus{
			Name:   "gateway",
			Status: "fail",
			Details: map[string]any{
				"error": err.Error(),
			},
		}
	}

	details := map[string]any{
		"circuit_breaker_state": h.CircuitBreakerState,
		"middleware_chain":      "active",
		"middleware_count":      13,
	}
	return ComponentStatus{Name: "gateway", Status: strings.ToLower(h.Status), Details: details}
}

func checkKeyDB(ctx context.Context, cfg Config, deps Deps) ComponentStatus {
	client, err := deps.RedisDial(cfg.KeyDBURL)
	if err != nil {
		return ComponentStatus{Name: "keydb", Status: "fail", Details: map[string]any{"error": err.Error()}}
	}
	defer func() {
		_ = client.Close()
	}()

	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return ComponentStatus{Name: "keydb", Status: "fail", Details: map[string]any{"error": err.Error()}}
	}

	// Use INFO without section args for compatibility across Redis variants and miniredis in unit tests.
	info, err := client.Info(ctx).Result()
	if err != nil {
		return ComponentStatus{Name: "keydb", Status: "degraded", Details: map[string]any{"ping": "ok", "info_error": err.Error()}}
	}

	connected := parseRedisInfoValue(info, "connected_clients")
	mem := parseRedisInfoValue(info, "used_memory_human")
	keys, err := client.DBSize(ctx).Result()
	if err != nil {
		return ComponentStatus{Name: "keydb", Status: "degraded", Details: map[string]any{"ping": "ok", "connected_clients": connected, "memory": mem, "dbsize_error": err.Error()}}
	}

	return ComponentStatus{
		Name:   "keydb",
		Status: "ok",
		Details: map[string]any{
			"connected_clients": connected,
			"memory":            mem,
			"keys":              keys,
		},
	}
}

func checkSpireServer(ctx context.Context, cfg Config, deps Deps) ComponentStatus {
	cs := checkDockerServiceHealth(ctx, deps, "spire-server", nil)
	// Trust domain is static config; include even if degraded.
	if cs.Details == nil {
		cs.Details = map[string]any{}
	}
	if td, err := readSpireTrustDomain(deps.ReadFile, cfg.SpireConfPath); err == nil && td != "" {
		cs.Details["trust_domain"] = td
	}

	// Agent count via spire-server agent list.
	out, err := deps.Exec.Run(ctx, "docker", composeArgs("exec", "-T", "spire-server", "/opt/spire/bin/spire-server", "agent", "list")...)
	if err != nil {
		// If container is otherwise healthy but CLI query fails, treat as degraded.
		if strings.EqualFold(cs.Status, "ok") {
			cs.Status = "degraded"
		} else {
			cs.Status = "fail"
		}
		cs.Details["agent_list_error"] = err.Error()
		return cs
	}

	cs.Details["agent_count"] = countSPIFFEIDs(out)
	return cs
}

func checkDockerServiceHealth(ctx context.Context, deps Deps, service string, details map[string]any) ComponentStatus {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	containers, err := deps.Docker.PS(ctx)
	if err != nil {
		return ComponentStatus{Name: service, Status: "fail", Details: map[string]any{"error": err.Error()}}
	}

	c, ok := findService(containers, service)
	if !ok {
		return ComponentStatus{Name: service, Status: "fail", Details: map[string]any{"error": "container not found"}}
	}

	if details == nil {
		details = map[string]any{}
	}
	details["container_state"] = c.State
	if c.Health != "" {
		details["container_health"] = c.Health
	}

	state := strings.ToLower(strings.TrimSpace(c.State))
	health := strings.ToLower(strings.TrimSpace(c.Health))

	if state != "running" {
		details["error"] = "not running"
		return ComponentStatus{Name: service, Status: "fail", Details: details}
	}
	if health == "" {
		// No healthcheck defined; treat as degraded.
		return ComponentStatus{Name: service, Status: "degraded", Details: details}
	}
	if health != "healthy" {
		details["error"] = "unhealthy"
		return ComponentStatus{Name: service, Status: "fail", Details: details}
	}

	return ComponentStatus{Name: service, Status: "ok", Details: details}
}

func checkHTTP(ctx context.Context, deps Deps, name, url string, details map[string]any) ComponentStatus {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(url, "/")+"/", nil)
	if err != nil {
		return ComponentStatus{Name: name, Status: "fail", Details: map[string]any{"error": err.Error()}}
	}
	resp, err := deps.HTTPClient.Do(req)
	if err != nil {
		// Distinguish connection-refused from other issues to allow DEGRADED.
		status := "fail"
		if isConnRefused(err) {
			status = "degraded"
		}
		return ComponentStatus{Name: name, Status: status, Details: map[string]any{"error": err.Error()}}
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ComponentStatus{Name: name, Status: "fail", Details: map[string]any{"status_code": resp.StatusCode}}
	}
	if details == nil {
		details = map[string]any{}
	}
	return ComponentStatus{Name: name, Status: "ok", Details: details}
}

type GatewayHealth struct {
	Status              string
	CircuitBreakerState string
}

func getGatewayHealth(ctx context.Context, c *http.Client, url string) (*GatewayHealth, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway unhealthy: status_code=%d", resp.StatusCode)
	}
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, err
	}
	h := &GatewayHealth{Status: "unknown"}
	if v, ok := raw["status"].(string); ok && v != "" {
		h.Status = v
	}
	if cb, ok := raw["circuit_breaker"].(map[string]any); ok {
		if state, ok := cb["state"].(string); ok {
			h.CircuitBreakerState = state
		}
	}
	return h, nil
}

// DockerLister parses `docker compose ps --all --format json` output.
type DockerLister interface {
	PS(ctx context.Context) ([]DockerContainer, error)
}

type DockerContainer struct {
	Service string `json:"Service"`
	State   string `json:"State"`
	Health  string `json:"Health"`
	Status  string `json:"Status"`
}

type ExecDockerLister struct{}

func (ExecDockerLister) PS(ctx context.Context) ([]DockerContainer, error) {
	out, err := runCombined(ctx, "docker", composeArgs("ps", "--all", "--format", "json")...)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	containers := make([]DockerContainer, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var c DockerContainer
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			return nil, fmt.Errorf("parse docker compose ps json: %w", err)
		}
		containers = append(containers, c)
	}
	return containers, nil
}

func findService(containers []DockerContainer, service string) (DockerContainer, bool) {
	for _, c := range containers {
		if c.Service == service {
			return c, true
		}
	}
	return DockerContainer{}, false
}

type ExecRunner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type ExecRunnerFunc func(ctx context.Context, name string, args ...string) (string, error)

func (f ExecRunnerFunc) Run(ctx context.Context, name string, args ...string) (string, error) {
	return f(ctx, name, args...)
}

func runCombined(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	b, err := cmd.CombinedOutput()
	if err != nil {
		return string(b), fmt.Errorf("%s %s: %w (output=%q)", name, strings.Join(args, " "), err, string(b))
	}
	return string(b), nil
}

func defaultReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func readSpireTrustDomain(readFile func(string) ([]byte, error), path string) (string, error) {
	b, err := readFile(path)
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`trust_domain[[:space:]]*=[[:space:]]*"([^"]+)"`)
	m := re.FindStringSubmatch(string(b))
	if len(m) == 2 {
		return m[1], nil
	}
	return "", nil
}

func countSPIFFEIDs(s string) int {
	// SPIRE agent list includes SPIFFE IDs like spiffe://poc.local/...
	re := regexp.MustCompile(`spiffe://[a-zA-Z0-9._-]+/[^[:space:]]+`)
	return len(re.FindAllString(s, -1))
}

func parseRedisInfoValue(info, key string) string {
	for _, line := range strings.Split(info, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, key+":") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func isConnRefused(err error) bool {
	var ne *net.OpError
	if errors.As(err, &ne) {
		if se, ok := ne.Err.(*os.SyscallError); ok {
			return strings.Contains(strings.ToLower(se.Error()), "connection refused")
		}
		return strings.Contains(strings.ToLower(ne.Error()), "connection refused")
	}
	return strings.Contains(strings.ToLower(err.Error()), "connection refused")
}
