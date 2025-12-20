# sbomlyze

A fast, reliable SBOM diff and analysis tool. Compare Software Bill of Materials across versions, detect changes, and enforce policies in CI/CD pipelines.

## Features

- **Multi-format support**: Syft, CycloneDX, SPDX (JSON)
- **Strong identity matching**: PURL → CPE → BOM-ref → namespace/name precedence
- **Drift detection**: Classify changes as version, integrity, or metadata drift
- **Statistics mode**: Analyze single SBOMs for license, dependency, and integrity metrics
- **Policy engine**: Enforce rules in CI pipelines
- **Duplicate detection**: Find multiple versions of the same package
- **Dependency graph diff**: Track dependency relationship changes
- **Tolerant parsing**: Continue on errors with structured warnings

## Installation

```bash
go install github.com/rezmoss/sbomlyze@latest
```

Or build from source:

```bash
git clone https://github.com/rezmoss/sbomlyze.git
cd sbomlyze
go build -o sbomlyze .
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

### JSON Output

The drift information is included in JSON output:

```json
{
  "diff": {
    "changed": [
      {
        "id": "pkg:npm/lodash",
        "name": "lodash",
        "drift": {
          "type": "integrity",
          "hash_changes": {
            "changed": {
              "SHA256": {"before": "abc123", "after": "def456"}
            }
          }
        }
      }
    ]
  },
  "drift_summary": {
    "version_drift": 55,
    "integrity_drift": 1,
    "metadata_drift": 2
  }
}
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

**Diff JSON structure:**
```json
{
  "diff": {
    "added": [...],
    "removed": [...],
    "changed": [...],
    "duplicates": {...},
    "dependencies": {
      "added_deps": {...},
      "removed_deps": {...}
    }
  },
  "violations": [],
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

sbomlyze can compare SBOMs in different formats. The identity matching system ensures components are correctly matched even when formats use different identifier schemes:

```bash
# Compare Syft output with CycloneDX
sbomlyze syft-output.json cyclonedx-output.json

# Compare SPDX with Syft  
sbomlyze spdx-output.json syft-output.json
```

## Normalization

sbomlyze applies normalization to ensure reliable comparisons:

### Component Identity Matching

Components are matched using a precedence-based identity system. This prevents false diffs when tools rename fields, reorder entries, or use different identifier formats.

| Priority | Identifier | Example | Description |
|----------|------------|---------|-------------|
| 1 | PURL | `pkg:npm/lodash` | Package URL (version stripped) |
| 2 | CPE | `cpe:vendor:product` | CPE vendor:product (version stripped) |
| 3 | BOM-ref / SPDXID | `ref:component-123` | CycloneDX bom-ref or SPDX identifier |
| 4 | Namespace + Name | `com.example/mypackage` | Group/namespace with name |
| 5 | Name | `simple-package` | Fallback to name only |

This allows accurate matching even when:
- Different SBOM tools generate different identifiers
- Components are renamed but have the same PURL
- Cross-format comparisons (Syft vs CycloneDX vs SPDX)

### PURL Normalization

Package URLs are normalized by stripping version, qualifiers, and subpath:

```
Input:  pkg:apk/alpine/nginx@1.29.4-r1?arch=aarch64&distro=alpine-3.23.2
Output: pkg:apk/alpine/nginx
```

This allows detecting version changes rather than showing as added+removed.

### CPE Normalization

CPE strings are normalized to vendor:product only:

```
Input:  cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*
Output: cpe:apache:log4j
```

Both CPE 2.2 and CPE 2.3 formats are supported.

### String Normalization

- Component names: trimmed and lowercased
- Versions: trimmed (case preserved)
- Licenses: trimmed, `NOASSERTION`/`NONE`/`UNKNOWN` filtered out

### Order Independence

- License arrays compared after sorting
- Component lists compared by ID map lookup
- Results sorted alphabetically

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

### Cross-Format Comparison

```bash
# Generate different formats
syft image:tag -o json > syft.json
syft image:tag -o cyclonedx-json > cdx.json
syft image:tag -o spdx-json > spdx.json

# sbomlyze handles all formats
sbomlyze syft.json cdx.json
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

### Integrity Monitoring

```bash
# Compare SBOMs and check for integrity drift
sbomlyze baseline.json current.json --json | jq '.drift_summary'

# Output:
# {
#   "version_drift": 55,
#   "integrity_drift": 1,
#   "metadata_drift": 2
# }

# Alert on any integrity drift (CI example)
if sbomlyze baseline.json current.json --json | jq -e '.drift_summary.integrity_drift > 0' > /dev/null; then
  echo "⚠️  INTEGRITY DRIFT DETECTED - Investigate immediately!"
  exit 1
fi
```

## Development

### Run Tests

```bash
go test -v ./...
```

### Build

```bash
go build -o sbomlyze .
```
