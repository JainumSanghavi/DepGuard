package parser

import (
	"os"
	"testing"
)

func TestRequirementsParser(t *testing.T) {
	data, err := os.ReadFile("testdata/requirements.txt")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	p := &RequirementsParser{}
	deps, err := p.Parse(data, false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(deps) != 5 {
		t.Fatalf("expected 5 deps, got %d: %v", len(deps), deps)
	}
	byName := make(map[string]Dependency)
	for _, d := range deps {
		byName[d.Name] = d
	}
	cases := []struct {
		name    string
		version string
	}{
		{"requests", "2.31.0"},
		{"flask", "3.0.0"},
		{"sqlalchemy", "2.0.23"},
		{"pytest", "7.4.0"},
		{"urllib3", "2.1.0"},
	}
	for _, tc := range cases {
		d, ok := byName[tc.name]
		if !ok {
			t.Errorf("missing dep %q", tc.name)
			continue
		}
		if d.Version != tc.version {
			t.Errorf("%s: version = %q, want %q", tc.name, d.Version, tc.version)
		}
		if d.Ecosystem != "PyPI" {
			t.Errorf("%s: ecosystem = %q, want PyPI", tc.name, d.Ecosystem)
		}
	}
}
