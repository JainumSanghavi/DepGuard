# DepGuard

DepGuard scans dependency manifests for known vulnerabilities using the free [OSV.dev](https://osv.dev) API.
It supports `go.mod`, `package.json`, and `requirements.txt`, and works as a CI gate via `--fail-on`.

## Install

```bash
go install github.com/depguard/depguard/cmd/depguard@latest
```

## Usage

```
depguard [flags] <manifest-file>

Flags:
  --include-indirect    include indirect dependencies (go.mod only)
  --json                output JSON instead of a table
  --fail-on=<level>     exit 1 if any vuln is at or above: low, medium, high, critical
```

## Examples

```bash
# Scan a Go module (direct deps only)
depguard go.mod

# Include indirect dependencies
depguard --include-indirect go.mod

# Scan a Node.js project
depguard package.json

# Scan a Python project
depguard requirements.txt

# Output machine-readable JSON
depguard --json go.mod

# Exit non-zero on high or critical vulns (CI gate)
depguard --fail-on=high go.mod
```

## Sample Output

```
PACKAGE                    VERSION   VULN ID               SEVERITY  CVSS  PATCHED
-------                    -------   -------               --------  ----  -------
github.com/gin-gonic/gin   v1.9.1    GHSA-h395-qcrw-5vmf   high      7.5   v1.9.4
golang.org/x/net           v0.17.0   GO-2023-2153           medium    5.3   v0.20.0

2 vulnerabilities found in 2 packages.
```

## CI (GitHub Actions)

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'
      - name: Install DepGuard
        run: go install github.com/depguard/depguard/cmd/depguard@latest
      - name: Scan for vulnerabilities
        run: depguard --fail-on=high go.mod
        # Exit code 1 when any high or critical vulnerability is found,
        # which causes the workflow step to fail and blocks the PR.
```

## License

MIT
