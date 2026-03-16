package compliance

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// LoadAuditJSONLEntries loads an audit JSONL file. Lines that are not valid JSON
// are skipped (e.g. docker-compose prefixes before the first '{').
func LoadAuditJSONLEntries(path string) ([]map[string]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()

	var entries []map[string]any
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if i := strings.IndexByte(line, '{'); i >= 0 {
			line = line[i:]
		} else {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		entries = append(entries, m)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func LoadAuditFromDockerComposeLogs(projectRoot string) ([]map[string]any, error) {
	cmd := exec.Command("docker", "compose", "logs", "--no-log-prefix", "precinct-gateway")
	cmd.Dir = projectRoot
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("docker compose logs failed: %w (output=%s)", err, string(out))
	}

	var entries []map[string]any
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if i := strings.IndexByte(line, '{'); i >= 0 {
			line = line[i:]
		} else {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			continue
		}
		entries = append(entries, m)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

func CollectAuditEntries(projectRoot, auditLogPath string) ([]map[string]any, string, error) {
	return CollectAuditEntriesWithOptions(projectRoot, AuditCollectionOptions{
		Source:       "auto",
		AuditLogPath: auditLogPath,
	})
}

func WriteAuditSnapshotJSONL(dstPath string, entries []map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(dstPath), 0o755); err != nil {
		return err
	}
	f, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer func() {
		_ = f.Close()
	}()

	w := bufio.NewWriter(f)
	for _, e := range entries {
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			return err
		}
	}
	return w.Flush()
}
