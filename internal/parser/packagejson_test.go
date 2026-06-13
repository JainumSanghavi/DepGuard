package parser

import (
	"os"
	"testing"
)

func TestPackageJSONParser(t *testing.T) {
	data, err := os.ReadFile("testdata/package.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	p := &PackageJSONParser{}
	deps, err := p.Parse(data, false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(deps) != 6 {
		t.Fatalf("expected 6 deps, got %d", len(deps))
	}
	byName := make(map[string]Dependency)
	for _, d := range deps {
		byName[d.Name] = d
	}
	cases := []struct {
		name    string
		version string
	}{
		{"express", "4.18.2"},
		{"lodash", "4.17.21"},
		{"axios", "1.6.0"},
		{"react", "18.2.0"},
		{"jest", "29.7.0"},
		{"typescript", "5.2.2"},
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
		if d.Ecosystem != "npm" {
			t.Errorf("%s: ecosystem = %q, want npm", tc.name, d.Ecosystem)
		}
		if d.Indirect {
			t.Errorf("%s: should not be indirect", tc.name)
		}
	}
}
