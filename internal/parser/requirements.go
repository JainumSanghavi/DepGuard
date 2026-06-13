package parser

import "fmt"

// RequirementsParser parses requirements.txt manifest files.
type RequirementsParser struct{}

func (p *RequirementsParser) Parse(data []byte, _ bool) ([]Dependency, error) {
	return nil, fmt.Errorf("not implemented")
}
