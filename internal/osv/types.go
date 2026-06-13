package osv

// BatchQuery is the request body for POST /v1/querybatch.
type BatchQuery struct {
	Queries []Query `json:"queries"`
}

// Query is a single package+version query within a batch.
type Query struct {
	Package Package `json:"package"`
	Version string  `json:"version"`
}

// Package identifies a package by name and ecosystem.
type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// BatchResponse is the response from POST /v1/querybatch.
type BatchResponse struct {
	Results []QueryResult `json:"results"`
}

// QueryResult holds the vuln IDs for one query (index-aligned with the request).
type QueryResult struct {
	Vulns []VulnRef `json:"vulns"`
}

// VulnRef is a minimal vulnerability reference returned in batch results.
type VulnRef struct {
	ID string `json:"id"`
}

// VulnDetail is the full vulnerability record from GET /v1/vulns/{id}.
type VulnDetail struct {
	ID       string     `json:"id"`
	Severity []Severity `json:"severity"`
	Affected []Affected `json:"affected"`
}

// Severity holds a CVSS vector string for a specific CVSS version.
// OSV stores the vector string (e.g. "CVSS:3.1/AV:N/AC:L/...") in Score.
type Severity struct {
	Type  string `json:"type"`  // "CVSS_V2", "CVSS_V3"
	Score string `json:"score"` // CVSS vector string
}

// Affected describes the affected package version ranges.
type Affected struct {
	Package Package `json:"package"`
	Ranges  []Range `json:"ranges"`
}

// Range is a version range described by introduced/fixed events.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event marks an introduced or fixed version boundary.
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed       string `json:"fixed,omitempty"`
}
