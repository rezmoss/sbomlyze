# sbomlyze

[![GitHub Release][release-img]][release]
[![Go Report Card][go-report-img]][go-report]
[![License: Apache-2.0][license-img]][license]
[![Go version][gover-img]][gover]
<a href="https://github.com/rezmoss/sbomlyze" target="_blank"><img alt="GitHub go.mod Go version" src="https://img.shields.io/github/go-mod/go-version/rezmoss/sbomlyze.svg"></a>

A fast, reliable SBOM diff and analysis tool. Compare Software Bill of Materials across versions, detect changes, and enforce policies in CI/CD pipelines.

## Features

- **Multi-format support**: Syft, CycloneDX, SPDX (JSON)
- **Strong identity matching**: PURL → CPE → BOM-ref → namespace/name precedence
- **Drift detection**: Classify changes as version, integrity, or metadata drift
- **Dependency graph diff**: Track transitive dependencies and supply-chain depth
- **Statistics mode**: Analyze single SBOMs for license, dependency, and integrity metrics
- **Policy engine**: Enforce rules in CI pipelines
- **Duplicate detection**: Find multiple versions of the same package
- **Tolerant parsing**: Continue on errors with structured warnings

## Installation

### Installer Script (Recommended)

The installer script downloads the correct binary for your OS/architecture:

```bash
# Install to ./bin
curl -sSfL https://raw.githubusercontent.com/rezmoss/sbomlyze/main/install.sh | sh

# Install to /usr/local/bin (requires sudo)
curl -sSfL https://raw.githubusercontent.com/rezmoss/sbomlyze/main/install.sh | sudo sh -s -- -b /usr/local/bin

# Install specific version
curl -sSfL https://raw.githubusercontent.com/rezmoss/sbomlyze/main/install.sh | sh -s -- -v 0.2.0
```

**Installer options:**

| Option | Description |
|--------|-------------|
| `-b <dir>` | Installation directory (default: `./bin`) |
| `-d` | Enable debug output |
| `-v <ver>` | Install specific version (default: latest) |

### Debian / Ubuntu (apt)

```bash
# Add repository
echo "deb [trusted=yes] https://rezmoss.github.io/sbomlyze/deb stable main" | sudo tee /etc/apt/sources.list.d/sbomlyze.list

# Install
sudo apt update
sudo apt install sbomlyze
```

### RHEL / Fedora / CentOS (dnf/yum)

```bash
# Add repository
sudo tee /etc/yum.repos.d/sbomlyze.repo << 'EOF'
[sbomlyze]
name=sbomlyze
baseurl=https://rezmoss.github.io/sbomlyze/rpm/packages
enabled=1
gpgcheck=0
EOF

# Install
sudo dnf install sbomlyze   # or: sudo yum install sbomlyze
```

### Alpine (apk)

```bash
# Download and install
wget https://github.com/rezmoss/sbomlyze/releases/latest/download/sbomlyze_VERSION_linux_amd64.apk
sudo apk add --allow-untrusted sbomlyze_*_linux_amd64.apk
```

### Homebrew (macOS/Linux)

```bash
brew install rezmoss/sbomlyze/sbomlyze
```

### Go Install

```bash
go install github.com/rezmoss/sbomlyze/cmd/sbomlyze@latest
```

### From Binary Release

Download the latest binary from [GitHub Releases](https://github.com/rezmoss/sbomlyze/releases).

**macOS users:** Remove the quarantine flag after downloading:

```bash
xattr -d com.apple.quarantine ./sbomlyze
chmod +x ./sbomlyze
```

### Build from Source

```bash
git clone https://github.com/rezmoss/sbomlyze.git
cd sbomlyze
go build -o sbomlyze ./cmd/sbomlyze
```

## Quick Start

```bash
# Analyze a single SBOM
sbomlyze image.json

# Compare two SBOMs
sbomlyze before.json after.json

# JSON output for CI integration
sbomlyze before.json after.json --json

# Apply policy checks
sbomlyze before.json after.json --policy policy.json
```

## Usage

```
sbomlyze <sbom1> [sbom2] [options]

Modes:
  Single file:  sbomlyze <sbom>              Show statistics
  Two files:    sbomlyze <sbom1> <sbom2>     Show diff

Options:
  --json        Output in JSON format
  --policy      Policy file for CI checks
  --strict      Fail immediately on parse errors
  --tolerant    Continue on parse errors with warnings (default)
  --version     Show version information
  --help        Show help message
```

## Commands

### Statistics Mode (Single File)

Analyze an SBOM to get insights about components, licenses, and dependencies.

```bash
sbomlyze image.json
```

Output:
```
📦 SBOM Statistics
==================

Total Components: 71

By Package Type:
  apk          71

Licenses:
  With license:    71
  Without license: 0

  Top Licenses:
    MIT                            17
    BSD-3-Clause                   8
    GPL-2.0-only                   8

Integrity:
  With hashes:    0
  Without hashes: 71

Dependencies:
  Components with deps: 65
  Total dep relations:  176
```

### Diff Mode (Two Files)

Compare two SBOMs to see what changed between versions.

```bash
sbomlyze v1.0.json v2.0.json
```

Output:
```
📊 Drift Summary:
  📦 Version drift:   58 components
  ⚠️  Integrity drift: 1 component (hash changed without version change!)
  📝 Metadata drift:  2 components

+ Added (2):
  + libgcrypt 1.10.3-r0
  + libgpg-error 1.49-r0

- Removed (3):
  - libapk 3.0.3-r1
  - libgcc 15.2.0-r2
  - nghttp3 1.13.1-r0

~ Changed (58):
  ~ nginx
      version: 1.29.4-r1 -> 1.27.3-r1
  ~ suspicious-pkg ⚠️  [INTEGRITY]
      hash[SHA256]: abc123 -> def456

>> Added dependencies:
  pkg:apk/alpine/libxslt: +[so:libgcrypt.so.20]

<< Removed dependencies:
  pkg:apk/alpine/libcurl: -[so:libnghttp3.so.9]

🔗 New transitive dependencies (3):
  + pkg:npm/lodash (depth 2)
    via: [pkg:npm/my-app pkg:npm/express pkg:npm/lodash]
  + pkg:npm/underscore (depth 3)
    via: [pkg:npm/my-app pkg:npm/express pkg:npm/lodash pkg:npm/underscore]

📊 New deps by depth:
  Depth 2:              1
  Depth 3+ (risky):     2 ⚠️
```

## Dependency Graph Diff

sbomlyze goes beyond simple component list diffs to analyze the full dependency graph, detecting supply-chain risks introduced through transitive dependencies.

### Features

| Feature | Description |
|---------|-------------|
| **Edge diff** | Added/removed direct dependencies (A depends on B) |
| **Transitive reachability** | New indirect dependencies that appear through the graph |
| **Path tracking** | Shows exactly how each new transitive dep is reached |
| **Depth tracking** | How many hops away each new dep is from your code |
| **Risk summary** | Depth 3+ deps flagged as higher risk |

### Why Depth Matters

Dependencies introduced deeper in the graph are:
- Harder to audit and review
- Often pulled in without explicit approval  
- Common vectors for supply chain attacks (e.g., event-stream incident)

The depth summary helps prioritize review:

| Depth | Risk Level | Description |
|-------|------------|-------------|
| **1** | Low | Direct dependencies (you chose these) |
| **2** | Medium | Dependencies of your dependencies |
| **3+** | High ⚠️ | Deep transitive deps - review carefully |

### Example: Detecting Deep Transitive Dependencies

```bash
# Before: app -> express (simple, 1 dep)
# After:  app -> express -> lodash -> underscore -> deep-lib (chain of 4)

sbomlyze before.json after.json
```

Output:
```
🔗 New transitive dependencies (3):
  + lodash (depth 2)
    via: [app express lodash]
  + underscore (depth 3)
    via: [app express lodash underscore]
  + deep-lib (depth 4)
    via: [app express lodash underscore deep-lib]

📊 New deps by depth:
  Depth 2:              1
  Depth 3+ (risky):     2 ⚠️
```

### JSON Output for Dependency Graph

```json
{
  "dependencies": {
    "added_deps": {
      "pkg:npm/express": ["pkg:npm/lodash", "pkg:npm/body-parser"]
    },
    "removed_deps": {},
    "transitive_new": [
      {
        "target": "pkg:npm/underscore",
        "via": ["pkg:npm/my-app", "pkg:npm/express", "pkg:npm/lodash", "pkg:npm/underscore"],
        "depth": 3
      }
    ],
    "transitive_lost": [],
    "depth_summary": {
      "depth_1": 0,
      "depth_2": 2,
      "depth_3_plus": 2
    }
  }
}
```

## Drift Detection

sbomlyze classifies component changes into three drift types, helping you distinguish normal updates from potentially suspicious changes.

### Drift Types

| Type | Indicator | Description | Severity |
|------|-----------|-------------|----------|
| **Version** | 📦 | Version number changed | Normal |
| **Integrity** | ⚠️ | Hash changed WITHOUT version change | High - investigate! |
| **Metadata** | 📝 | Only metadata (licenses, etc.) changed | Low |

### Integrity Drift (Security Signal)

Integrity drift occurs when a component's hash changes but its version stays the same. This could indicate:

- **Supply chain attack**: Package was replaced with malicious version
- **Rebuild without version bump**: Legitimate but poor practice
- **Different build environment**: Reproducibility issues

```bash
# Example output with integrity drift
~ suspicious-pkg ⚠️  [INTEGRITY]
    hash[SHA256]: abc123 -> def456
```

**Recommendation**: Always investigate integrity drift. It may be benign, but it's a key signal for supply chain security.

### JSON Output for Drift

The drift summary is inside the `diff` object:

```json
{
  "diff": {
    "changed": [
      {
        "id": "pkg:npm/suspicious-pkg",
        "name": "suspicious-pkg",
        "changes": ["hash[SHA-256]: abc123 -> def456"],
        "drift": {
          "type": "integrity",
          "hash_changes": {
            "changed": {
              "SHA-256": {"before": "abc123", "after": "def456"}
            }
          }
        }
      }
    ],
    "drift_summary": {
      "version_drift": 55,
      "integrity_drift": 1,
      "metadata_drift": 2
    }
  }
}
```

**Extracting drift summary:**
```bash
# Get drift summary
sbomlyze before.json after.json --json | jq '.diff.drift_summary'

# Check for integrity drift in CI
sbomlyze before.json after.json --json | jq -e '.diff.drift_summary.integrity_drift > 0'
```

## Options

### `--json`

Output results in JSON format for programmatic consumption.

```bash
# Stats as JSON
sbomlyze image.json --json

# Diff as JSON
sbomlyze before.json after.json --json
```

**Stats JSON structure:**
```json
{
  "stats": {
    "total_components": 71,
    "by_type": {"apk": 71},
    "by_license": {"MIT": 17, "BSD-3-Clause": 8},
    "without_license": 0,
    "with_hashes": 0,
    "without_hashes": 71,
    "total_dependencies": 176,
    "with_dependencies": 65,
    "duplicate_count": 0
  },
  "warnings": []
}
```

### `--policy <file>`

Apply policy rules and fail CI if violated.

```bash
sbomlyze before.json after.json --policy policy.json
```

See [Policy Engine](#policy-engine) for details.

### `--strict`

Fail immediately on any parse error.

```bash
sbomlyze broken.json --strict
# Error parsing broken.json: unknown SBOM format
# exit status 1
```

### `--tolerant` (default)

Continue processing on errors, collect warnings.

```bash
sbomlyze broken.json --tolerant
# 📦 SBOM Statistics
# ==================
# Total Components: 0
# ...
# ⚠️  Parse Warnings (1):
#   [broken.json] unknown SBOM format
```

## Policy Engine

Create policies to enforce rules in CI/CD pipelines. sbomlyze exits with code 1 when violations occur.

### Policy File Format

```json
{
  "max_added": 10,
  "max_removed": 5,
  "max_changed": 100,
  "deny_licenses": ["GPL-3.0", "AGPL-3.0"],
  "require_licenses": true,
  "deny_duplicates": true
}
```

### Policy Rules

| Rule | Type | Description |
|------|------|-------------|
| `max_added` | int | Maximum new components allowed (0 = unlimited) |
| `max_removed` | int | Maximum removed components allowed (0 = unlimited) |
| `max_changed` | int | Maximum changed components allowed (0 = unlimited) |
| `deny_licenses` | []string | List of forbidden license identifiers |
| `require_licenses` | bool | Require all added components to have licenses |
| `deny_duplicates` | bool | Fail if duplicate packages exist in result |

### Example: Strict Policy

```json
{
  "max_added": 5,
  "max_removed": 3,
  "max_changed": 20,
  "deny_licenses": ["GPL-3.0", "AGPL-3.0", "SSPL-1.0"],
  "require_licenses": true,
  "deny_duplicates": true
}
```

### Policy Violations Output

```
!! Policy Violations (3):
  [max_added] too many components added: 10 > 5
  [max_removed] too many components removed: 7 > 3
  [deny_licenses] component foo has denied license: GPL-3.0
```

## Supported SBOM Formats

| Format | File Detection | Identifiers Extracted |
|--------|----------------|----------------------|
| Syft (native) | Contains `"artifacts"` | PURL, CPE, name |
| CycloneDX | Contains `"bomFormat"` | PURL, CPE, BOM-ref, group (namespace) |
| SPDX | Contains `"spdxVersion"` | PURL, CPE, SPDXID |

All formats must be JSON. XML support is not currently available.

### Cross-Format Comparison

sbomlyze can compare SBOMs in different formats:

```bash
# Compare Syft output with CycloneDX
sbomlyze syft-output.json cyclonedx-output.json

# Compare SPDX with Syft  
sbomlyze spdx-output.json syft-output.json
```

## Component Identity Matching

Components are matched using a precedence-based identity system:

| Priority | Identifier | Example | Description |
|----------|------------|---------|-------------|
| 1 | PURL | `pkg:npm/lodash` | Package URL (version stripped) |
| 2 | CPE | `cpe:vendor:product` | CPE vendor:product (version stripped) |
| 3 | BOM-ref / SPDXID | `ref:component-123` | CycloneDX bom-ref or SPDX identifier |
| 4 | Namespace + Name | `com.example/mypackage` | Group/namespace with name |
| 5 | Name | `simple-package` | Fallback to name only |

## CI/CD Integration

### GitHub Actions

```yaml
name: SBOM Check
on: [pull_request]

jobs:
  sbom-diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Generate SBOM
        run: syft . -o json > current.json
        
      - name: Download baseline SBOM
        run: curl -o baseline.json ${{ vars.BASELINE_SBOM_URL }}
        
      - name: Compare SBOMs
        run: |
          go install github.com/rezmoss/sbomlyze@latest
          sbomlyze baseline.json current.json --policy policy.json
```

### GitLab CI

```yaml
sbom-diff:
  stage: test
  script:
    - syft . -o json > current.json
    - sbomlyze baseline.json current.json --policy policy.json --json > sbom-report.json
  artifacts:
    paths:
      - sbom-report.json
    when: always
```

### Integrity Drift Alert

```bash
# Alert on any integrity drift (CI example)
if sbomlyze baseline.json current.json --json | jq -e '.diff.drift_summary.integrity_drift > 0' > /dev/null; then
  echo "⚠️  INTEGRITY DRIFT DETECTED - Investigate immediately!"
  exit 1
fi
```

### Deep Dependency Alert

```bash
# Alert on new deep transitive dependencies
if sbomlyze baseline.json current.json --json | jq -e '.diff.dependencies.depth_summary.depth_3_plus > 0' > /dev/null; then
  echo "⚠️  New deep transitive dependencies detected - Review required!"
fi
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success, no differences or violations |
| 1 | Differences found, policy violations, or errors |

## Examples

### Compare Docker Images

```bash
# Generate SBOMs
syft nginx:1.25-alpine -o json > nginx-125.json
syft nginx:1.26-alpine -o json > nginx-126.json

# Compare
sbomlyze nginx-125.json nginx-126.json
```

### License Audit

```bash
# Check for GPL licenses in new dependencies
cat > audit-policy.json << EOF
{
  "deny_licenses": ["GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0"],
  "require_licenses": true
}
EOF

sbomlyze old.json new.json --policy audit-policy.json
```

### Dependency Drift Detection

```bash
# Detect any changes (strict mode for no drift)
cat > no-drift.json << EOF
{
  "max_added": 0,
  "max_removed": 0,
  "max_changed": 0
}
EOF

sbomlyze baseline.json current.json --policy no-drift.json
```

## Development

### Run Tests

```bash
make test
# or
go test -v ./...
```

### Lint

```bash
make lint
# or
golangci-lint run ./...
```

### Build

```bash
make build-quick
# or
go build -o sbomlyze ./cmd/sbomlyze
```

### Make Commands

```bash
make all         # Run test, lint, and build
make test        # Run all tests
make lint        # Run golangci-lint
make build       # Build with goreleaser (snapshot)
make build-quick # Quick build for development
make clean       # Remove build artifacts
```


[release]: https://github.com/rezmoss/sbomlyze/releases
[release-img]: https://img.shields.io/github/v/release/rezmoss/sbomlyze
[go-report]: https://goreportcard.com/report/github.com/rezmoss/sbomlyze
[go-report-img]: https://goreportcard.com/badge/github.com/rezmoss/sbomlyze
[license]: https://github.com/rezmoss/sbomlyze/blob/main/LICENSE
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[gover]: https://github.com/rezmoss/sbomlyze
[gover-img]: https://img.shields.io/github/go-mod/go-version/rezmoss/sbomlyze.svg
