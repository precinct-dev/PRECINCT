package compliance

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Taxonomy struct {
	Controls []Control `yaml:"controls"`
}

type Control struct {
	ID           string              `yaml:"id"`
	Name         string              `yaml:"name"`
	Description  string              `yaml:"description"`
	Middleware   *string             `yaml:"middleware"`
	Step         *int                `yaml:"step"`
	Frameworks   map[string][]string `yaml:"frameworks"`
	EvidenceType string              `yaml:"evidence_type"`
	EvidenceQuery *string            `yaml:"evidence_query"`
}

func LoadTaxonomy(path string) (*Taxonomy, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Taxonomy
	if err := yaml.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("parse taxonomy YAML: %w", err)
	}
	if len(t.Controls) == 0 {
		return nil, fmt.Errorf("no controls found in %s", path)
	}
	return &t, nil
}

func FilterControlsByFramework(controls []Control, framework string) []Control {
	var out []Control
	for _, c := range controls {
		reqs := c.Frameworks[framework]
		if len(reqs) > 0 {
			out = append(out, c)
		}
	}
	return out
}

