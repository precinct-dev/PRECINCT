package gateway

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

func normalizedSPIFFEMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), "prod") {
		return "prod"
	}
	return "dev"
}

func isLoopbackHost(host string) bool {
	value := strings.TrimSpace(host)
	if value == "" {
		return false
	}
	if strings.EqualFold(value, "localhost") {
		return true
	}
	value = strings.Trim(value, "[]")
	ip := net.ParseIP(value)
	return ip != nil && ip.IsLoopback()
}

// ValidateDevRuntimeGuardrails enforces explicit acknowledgement gates for
// insecure dev behavior.
func ValidateDevRuntimeGuardrails(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("config is required")
	}
	if normalizedSPIFFEMode(cfg.SPIFFEMode) == "prod" {
		return nil
	}
	if !cfg.AllowInsecureDevMode {
		return fmt.Errorf("SPIFFE_MODE=dev requires ALLOW_INSECURE_DEV_MODE=true")
	}
	host := strings.TrimSpace(cfg.DevListenHost)
	if host == "" {
		host = "127.0.0.1"
	}
	if !isLoopbackHost(host) && !cfg.AllowNonLoopbackDevBind {
		return fmt.Errorf("non-loopback dev bind host %q requires ALLOW_NON_LOOPBACK_DEV_BIND=true", host)
	}
	return nil
}

// ResolveDevListenAddr returns the host:port listen address for dev mode.
func ResolveDevListenAddr(cfg *Config) string {
	host := strings.TrimSpace(cfg.DevListenHost)
	if host == "" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(cfg.Port))
}
