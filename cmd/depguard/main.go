package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/depguard/depguard/internal/osv"
	"github.com/depguard/depguard/internal/parser"
	"github.com/depguard/depguard/internal/report"
)

func main() {
	includeIndirect := flag.Bool("include-indirect", false, "include indirect dependencies (go.mod only)")
	outputJSON      := flag.Bool("json", false, "output JSON instead of a table")
	failOn          := flag.String("fail-on", "", "exit 1 if any vuln is at or above this severity (low/medium/high/critical)")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: depguard [--include-indirect] [--json] [--fail-on=<level>] <manifest>")
		os.Exit(1)
	}

	if *failOn != "" {
		valid := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
		if !valid[*failOn] {
			fmt.Fprintf(os.Stderr, "error: --fail-on must be one of: low, medium, high, critical\n")
			os.Exit(1)
		}
	}

	manifestPath := flag.Arg(0)

	p, err := parser.Detect(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	data, err := os.ReadFile(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error reading %s: %v\n", manifestPath, err)
		os.Exit(1)
	}

	deps, err := p.Parse(data, *includeIndirect)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error parsing manifest: %v\n", err)
		os.Exit(1)
	}

	if len(deps) == 0 {
		fmt.Println("No dependencies found.")
		return
	}

	ctx := context.Background()
	client := osv.NewClient()

	vulnsByIdx, err := client.QueryBatch(ctx, deps)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error querying OSV: %v\n", err)
		os.Exit(1)
	}

	// Collect unique vuln IDs across all deps
	seen := make(map[string]bool)
	var ids []string
	for _, vulnIDs := range vulnsByIdx {
		for _, id := range vulnIDs {
			if !seen[id] {
				seen[id] = true
				ids = append(ids, id)
			}
		}
	}

	if len(ids) == 0 {
		fmt.Println("No vulnerabilities found.")
		return
	}

	details, err := client.FetchDetails(ctx, ids)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error fetching vuln details: %v\n", err)
		os.Exit(1)
	}

	findings := report.BuildFindings(deps, vulnsByIdx, details)

	if *outputJSON {
		if err := report.JSON(os.Stdout, findings); err != nil {
			fmt.Fprintf(os.Stderr, "error encoding JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		report.Table(os.Stdout, findings)
	}

	// --fail-on: exit 1 if any finding meets or exceeds the threshold
	if *failOn != "" {
		for _, f := range findings {
			if report.SeverityAtLeast(f.Severity, *failOn) {
				os.Exit(1)
			}
		}
	}
}
