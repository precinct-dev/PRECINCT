package mcpserver

import (
	"errors"
	"fmt"
	"os"
)

// validate checks the server configuration and returns a combined error
// containing all validation failures. This implements fail-fast batch
// validation: every issue is reported at once rather than one at a time.
func (s *Server) validate() error {
	var errs []error

	// Server name must be non-empty.
	if s.name == "" {
		errs = append(errs, fmt.Errorf("mcpserver: server name must not be empty"))
	}

	// Port must be in the valid TCP range. Port 0 is allowed as a special
	// value meaning "let the OS assign a random port" (standard for tests).
	if s.port < 0 || s.port > 65535 {
		errs = append(errs, fmt.Errorf("mcpserver: port %d is out of range 0-65535", s.port))
	}

	// At least one tool must be registered.
	s.mu.RLock()
	toolCount := len(s.tools)
	s.mu.RUnlock()
	if toolCount == 0 {
		errs = append(errs, fmt.Errorf("mcpserver: at least one tool must be registered"))
	}

	// If SPIRE is enabled, verify the socket path exists.
	socketPath := resolveSpireSocketPath(s)
	if socketPath != "" {
		cleanPath := socketPath
		if len(cleanPath) > 7 && cleanPath[:7] == "unix://" {
			cleanPath = cleanPath[7:]
		}
		if _, err := os.Stat(cleanPath); err != nil {
			errs = append(errs, fmt.Errorf("mcpserver: SPIRE socket not found at %s", cleanPath))
		}
	}

	// LOG_LEVEL must be a recognized value if set via option (env override
	// is validated separately in applyEnvOverrides, but the resulting
	// level is always valid because slog.Level is a typed value).

	if len(errs) == 0 {
		return nil
	}
	return errors.Join(errs...)
}

// validLogLevels is the set of recognized LOG_LEVEL strings.
var validLogLevels = map[string]bool{
	"debug": true,
	"info":  true,
	"warn":  true,
	"error": true,
}
