package parser

import "fmt"

// PackageJSONParser parses package.json manifest files.
type PackageJSONParser struct{}

func (p *PackageJSONParser) Parse(data []byte, _ bool) ([]Dependency, error) {
	return nil, fmt.Errorf("not implemented")
}
