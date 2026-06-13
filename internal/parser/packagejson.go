package parser

import (
	"encoding/json"
	"strings"
)

// PackageJSONParser parses package.json manifest files.
type PackageJSONParser struct{}

type pkgJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func (p *PackageJSONParser) Parse(data []byte, _ bool) ([]Dependency, error) {
	var pkg pkgJSON
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, err
	}

	merged := make(map[string]string, len(pkg.Dependencies)+len(pkg.DevDependencies))
	for k, v := range pkg.Dependencies {
		merged[k] = v
	}
	for k, v := range pkg.DevDependencies {
		merged[k] = v
	}

	var deps []Dependency
	for name, raw := range merged {
		version := stripSemverPrefix(raw)
		if version == "" {
			continue
		}
		deps = append(deps, Dependency{
			Name:      name,
			Version:   version,
			Ecosystem: "npm",
		})
	}
	return deps, nil
}

// stripSemverPrefix removes leading semver range characters and returns the
// bare version string. Returns "" if the result is not a usable version.
func stripSemverPrefix(v string) string {
	v = strings.TrimLeft(v, "^~>=<= ")
	if v == "" || v == "latest" || v == "*" {
		return ""
	}
	return v
}
