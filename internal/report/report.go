package report

import (
	"math"
	"strconv"
	"strings"

	"github.com/JainumSanghavi/DepGuard/internal/osv"
	"github.com/JainumSanghavi/DepGuard/internal/parser"
)

// Finding is the result of a vulnerability check for one package+vuln pair.
type Finding struct {
	Package        string  `json:"package"`
	Version        string  `json:"version"`
	VulnID         string  `json:"vuln_id"`
	Severity       string  `json:"severity"` // low, medium, high, critical, unknown
	CVSSScore      float64 `json:"cvss_score"`
	PatchedVersion string  `json:"patched_version"`
}

var severityRank = map[string]int{
	"unknown":  0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// SeverityAtLeast reports whether severity a is >= b.
// Returns false when b is "unknown" (unknown is never a valid --fail-on threshold).
func SeverityAtLeast(a, b string) bool {
	bRank, ok := severityRank[b]
	if !ok || bRank == 0 {
		return false
	}
	return severityRank[a] >= bRank
}

// BuildFindings assembles a Finding for each (dep, vulnID) pair.
func BuildFindings(deps []parser.Dependency, vulnsByIdx map[int][]string, details map[string]*osv.VulnDetail) []Finding {
	var findings []Finding
	for i, dep := range deps {
		for _, id := range vulnsByIdx[i] {
			detail, ok := details[id]
			if !ok {
				continue
			}
			score, severity := extractCVSS(detail.Severity)
			findings = append(findings, Finding{
				Package:        dep.Name,
				Version:        dep.Version,
				VulnID:         id,
				Severity:       severity,
				CVSSScore:      score,
				PatchedVersion: extractPatchedVersion(detail),
			})
		}
	}
	return findings
}

func extractCVSS(severities []osv.Severity) (float64, string) {
	byType := make(map[string]string, len(severities))
	for _, s := range severities {
		byType[s.Type] = s.Score
	}
	// Prefer CVSS v3 over v2
	for _, t := range []string{"CVSS_V3", "CVSS_V2"} {
		vector, ok := byType[t]
		if !ok {
			continue
		}
		// OSV stores the CVSS vector string; compute the numeric base score.
		if score, ok := cvssV3BaseScore(vector); ok {
			return score, scoreToSeverity(score)
		}
		// Some databases embed a plain numeric score instead.
		if f, err := strconv.ParseFloat(strings.TrimSpace(vector), 64); err == nil {
			return f, scoreToSeverity(f)
		}
	}
	return 0, "unknown"
}

// cvssV3BaseScore computes the CVSS v3 base score from a vector string such as
// "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
// Returns (score, true) on success; (0, false) if the vector cannot be parsed.
func cvssV3BaseScore(vector string) (float64, bool) {
	idx := strings.Index(vector, "/")
	if idx < 0 {
		return 0, false
	}

	m := make(map[string]string, 8)
	for _, part := range strings.Split(vector[idx+1:], "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}

	avW := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
	acW := map[string]float64{"L": 0.77, "H": 0.44}
	prW := map[string]map[string]float64{
		"U": {"N": 0.85, "L": 0.62, "H": 0.27},
		"C": {"N": 0.85, "L": 0.68, "H": 0.5},
	}
	uiW  := map[string]float64{"N": 0.85, "R": 0.62}
	impW := map[string]float64{"N": 0, "L": 0.22, "H": 0.56}

	scope := m["S"]
	av, okAV     := avW[m["AV"]]
	ac, okAC     := acW[m["AC"]]
	prScope, okScope := prW[scope]
	pr, okPR     := prScope[m["PR"]]
	ui, okUI     := uiW[m["UI"]]
	c, okC       := impW[m["C"]]
	is, okI      := impW[m["I"]]
	a, okA       := impW[m["A"]]

	if !okAV || !okAC || !okScope || !okPR || !okUI || !okC || !okI || !okA {
		return 0, false
	}

	iscBase := 1 - (1-c)*(1-is)*(1-a)

	var impact float64
	if scope == "U" {
		impact = 6.42 * iscBase
	} else {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	}

	if impact <= 0 {
		return 0, true
	}

	exploit := 8.22 * av * ac * pr * ui

	var raw float64
	if scope == "U" {
		raw = math.Min(impact+exploit, 10)
	} else {
		raw = math.Min(1.08*(impact+exploit), 10)
	}

	return math.Ceil(raw*10) / 10, true
}

func scoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

func extractPatchedVersion(detail *osv.VulnDetail) string {
	for _, affected := range detail.Affected {
		for _, r := range affected.Ranges {
			for _, event := range r.Events {
				if event.Fixed != "" {
					return event.Fixed
				}
			}
		}
	}
	return ""
}
