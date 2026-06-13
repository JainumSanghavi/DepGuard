package report

import (
	"fmt"
	"io"
	"text/tabwriter"
)

// Table writes a human-readable tabular report of findings to w.
func Table(w io.Writer, findings []Finding) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PACKAGE\tVERSION\tVULN ID\tSEVERITY\tCVSS\tPATCHED")
	fmt.Fprintln(tw, "-------\t-------\t-------\t--------\t----\t-------")

	for _, f := range findings {
		cvss := "N/A"
		if f.CVSSScore > 0 {
			cvss = fmt.Sprintf("%.1f", f.CVSSScore)
		}
		patched := f.PatchedVersion
		if patched == "" {
			patched = "N/A"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			f.Package, f.Version, f.VulnID, f.Severity, cvss, patched)
	}
	tw.Flush()

	pkgs := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		pkgs[f.Package] = struct{}{}
	}

	vulnWord := "vulnerabilities"
	if len(findings) == 1 {
		vulnWord = "vulnerability"
	}
	pkgWord := "packages"
	if len(pkgs) == 1 {
		pkgWord = "package"
	}
	fmt.Fprintf(w, "\n%d %s found in %d %s.\n", len(findings), vulnWord, len(pkgs), pkgWord)
}
