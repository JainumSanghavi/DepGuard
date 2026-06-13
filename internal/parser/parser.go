package parser

import (
	"fmt"
	"path/filepath"
)

// Dependency represents a single declared dependency from a manifest file.
type Dependency struct {
	Name      string
	Version   string
	Ecosystem string
	Indirect  bool
}

// Parser parses a manifest file into a list of dependencies.
type Parser interface {
	Parse(data []byte, includeIndirect bool) ([]Dependency, error)
}

// Detect returns the appropriate Parser for the given manifest filename.
func Detect(filename string) (Parser, error) {
	switch filepath.Base(filename) {
	case "go.mod":
		return &GoModParser{}, nil
	case "package.json":
		return &PackageJSONParser{}, nil
	case "requirements.txt":
		return &RequirementsParser{}, nil
	default:
		return nil, fmt.Errorf("unsupported manifest: %q", filepath.Base(filename))
	}
}
