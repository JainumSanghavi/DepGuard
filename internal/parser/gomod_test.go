package parser

import (
	"os"
	"testing"
)

func TestGoModParser_DirectOnly(t *testing.T) {
	data, err := os.ReadFile("testdata/go.mod")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	p := &GoModParser{}
	deps, err := p.Parse(data, false)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(deps) != 3 {
		t.Fatalf("expected 3 direct deps, got %d: %v", len(deps), deps)
	}
	want := []Dependency{
		{Name: "github.com/gin-gonic/gin", Version: "v1.9.1", Ecosystem: "Go"},
		{Name: "github.com/stretchr/testify", Version: "v1.8.4", Ecosystem: "Go"},
		{Name: "golang.org/x/net", Version: "v0.17.0", Ecosystem: "Go"},
	}
	for i, d := range deps {
		if d.Name != want[i].Name || d.Version != want[i].Version || d.Ecosystem != want[i].Ecosystem || d.Indirect {
			t.Errorf("dep[%d] = %+v, want %+v", i, d, want[i])
		}
	}
}

func TestGoModParser_IncludeIndirect(t *testing.T) {
	data, err := os.ReadFile("testdata/go.mod")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	p := &GoModParser{}
	deps, err := p.Parse(data, true)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(deps) != 5 {
		t.Fatalf("expected 5 deps (incl. indirect), got %d: %v", len(deps), deps)
	}
	if !deps[3].Indirect {
		t.Errorf("deps[3] should be indirect, got %+v", deps[3])
	}
	if !deps[4].Indirect {
		t.Errorf("deps[4] should be indirect, got %+v", deps[4])
	}
}
