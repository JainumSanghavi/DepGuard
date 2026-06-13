package parser

import (
	"bufio"
	"bytes"
	"strings"
)

// RequirementsParser parses requirements.txt manifest files.
type RequirementsParser struct{}

// reqOperators lists version constraint operators in priority order.
// == is checked first so "requests==2.31.0" matches before >= could.
var reqOperators = []string{"==", ">=", "~="}

func (p *RequirementsParser) Parse(data []byte, _ bool) ([]Dependency, error) {
	var deps []Dependency
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Strip inline comments
		if idx := strings.Index(line, " #"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}

		name, version, ok := parseReqLine(line)
		if !ok {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "PyPI",
		})
	}

	return deps, scanner.Err()
}

func parseReqLine(line string) (name, version string, ok bool) {
	for _, op := range reqOperators {
		idx := strings.Index(line, op)
		if idx < 0 {
			continue
		}
		name = strings.TrimSpace(line[:idx])
		rest := strings.TrimSpace(line[idx+len(op):])
		// Take the first token (handles multi-constraint like >=2.0,<3.0)
		parts := strings.FieldsFunc(rest, func(r rune) bool { return r == ',' || r == ' ' })
		if len(parts) == 0 {
			continue
		}
		return name, parts[0], true
	}
	return "", "", false
}
