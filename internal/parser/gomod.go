package parser

import (
	"bufio"
	"bytes"
	"strings"
)

// GoModParser parses go.mod manifest files.
type GoModParser struct{}

func (p *GoModParser) Parse(data []byte, includeIndirect bool) ([]Dependency, error) {
	var deps []Dependency
	scanner := bufio.NewScanner(bytes.NewReader(data))
	inBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "require (" {
			inBlock = true
			continue
		}
		if inBlock && line == ")" {
			inBlock = false
			continue
		}

		var entry string
		if inBlock {
			entry = line
		} else if strings.HasPrefix(line, "require ") {
			entry = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		} else {
			continue
		}

		if entry == "" {
			continue
		}

		indirect := strings.HasSuffix(entry, "// indirect")
		entry = strings.TrimSpace(strings.TrimSuffix(entry, "// indirect"))

		if indirect && !includeIndirect {
			continue
		}

		parts := strings.Fields(entry)
		if len(parts) < 2 {
			continue
		}

		deps = append(deps, Dependency{
			Name:      parts[0],
			Version:   parts[1],
			Ecosystem: "Go",
			Indirect:  indirect,
		})
	}

	return deps, scanner.Err()
}
