# Diff JSON contract

`sbomlyze before.json after.json --json` prints `{overview, findings, diff, violations?, compliance?, warnings?}`.
This page documents the `diff` object for consumers that read it instead of re-implementing SBOM diffing.
Existing keys keep their names; everything below marked *new* was added after 0.6.0.

## Behavior change in what `integrity_drift` means

`drift_summary.integrity_drift` used to count any hash change without a version change, including CycloneDX
`type: file` entries (the SHA-256 of `/go.mod` or a workflow that Syft directory scans emit). It now counts only
**packages** with the same identity, the same non-empty version and the same location whose digest of the **same kind**
changed. File content changes are in `file_changes`. On 78 real Syft source SBOM pairs this moved 210 false
integrity-drift items (all `type: file`) to `file_changes`, leaving 0 integrity drift.

Other changes that affect existing values:

- Component IDs keep the PURL subpath: `pkg:github/anchore/go-make#.github/actions/setup`.
- Names keep their declared case: `github.com/Microsoft/go-winio`.
- A package that appears several times (two lockfiles, two versions) is never dropped; counts are per occurrence.
- Syft JSON rpm and Python packages no longer carry one of their files' digests as a package hash.

## Package changes

| Field | Meaning |
|---|---|
| `added[]`, `removed[]` | Components that appeared or disappeared; every occurrence, with `locations` |
| `changed[]` | Packages present on both sides that changed: `id`, `name`, `location` *(new)*, `before`, `after`, `changes`, `drift` |
| `changed[].drift.type` | `version`, `integrity` or `metadata` |
| `changed[].drift.direction` *(new)* | `upgrade`, `downgrade`, `none` (equal precedence, e.g. build metadata) or `unknown` |
| `changed[].drift.level` *(new)* | `major`, `minor`, `patch`, `prerelease`, `revision`, `none` or `unknown` |
| `changed[].drift.licenses_diff` | `+MIT`, `-Apache-2.0`; also on version changes |
| `changed[].drift.hash_changes` | Digest changes by kind (`SHA-256`, `go-h1`, `cargo-checksum`) |
| `changed[].drift.files` *(new)* | Owned-file counts for a version change: `modified`, `added`, `removed`, `unverified`, `unchanged`, `all_match` |
| `moved[]` *(new)* | Same identity and version at another location: `id`, `name`, `version`, `from`, `to` |
| `source_change` *(new)* | The scanned source kept its name but its version or digest changed (a re-pushed image tag): `name`, `from`, `to`. Counts as a change for the exit code |
| `version_set_changes[]` *(new)* | Several versions changing at one location with no justified pairing: `id`, `name`, `location`, `removed_versions`, `added_versions`. The occurrences are also in `added`/`removed` |

## File changes *(new)*

| Field | Meaning |
|---|---|
| `file_changes[]` | Files whose content changed: `path`, `hashes_before`, `hashes_after`, `owners` (`name@version`, when recorded) |
| `files_added[]`, `files_removed[]` | Inventory files (Syft JSON, SPDX) that appeared or disappeared: `path`, `hashes`, `owners` |
| `owned_file_drift[]` | Packages that kept their version while files they own changed: `id`, `name`, `version`, `location`, `files[]` (`path`, `change`, `config`, `hashes_before`, `hashes_after`) |
| `file_coverage` | `files_compared`, `files_unverified`, `ambiguous_paths`, `owned_files_after`, `unowned_files_after`, `config_unknown` |

CycloneDX `type: file` entries that appear or disappear stay in `added`/`removed`, as before.

The scanned image or directory is the source, not a component: an SPDX root package (`SPDXRef-DocumentRoot-*`, or a described `pkg:oci`/`pkg:docker` package) is no longer listed in `changed`, and a CycloneDX `operating-system` entry without a PURL or CPE is matched by name (id `os:<name>`), so a point release shows as one change instead of a removal plus an addition. OS entries are not counted in `drift_summary`.

## Summary and coverage

| Field | Meaning |
|---|---|
| `drift_summary.version_drift`, `integrity_drift`, `metadata_drift` | Occurrence counts per drift type |
| `drift_summary.upgrades`, `downgrades`, `unknown_direction` *(new)* | Version-change occurrences by direction |
| `drift_summary.distinct_version_changes` *(new)* | Distinct identity + from + to |
| `drift_summary.file_changes`, `license_changes` *(new)* | Counts of `file_changes` and of changed entries with a license difference |
| `drift_summary.owned_file_drift`, `owned_files_changed` *(new)* | Packages with owned-file drift; distinct files involved |
| `digest_coverage` *(new)* | Same-version package pairs that could be checked for integrity drift: `same_version_pairs`, `comparable`, `before_only`, `after_only`, `disjoint_kinds`, `by_kind`, `packages_total` |
| `overview.{before,after}.info.format`, `spec_version` *(new)* | `CycloneDX` / `SPDX` / `Syft JSON` and the spec or schema version |

## Gates

- Exit code 1 and the Action's `fail-on: any-change` trigger on any added, removed, changed or moved package, any file
  change, and any owned-file drift.
- `deny_integrity_drift` fires only on `integrity` drift. `deny_owned_file_drift` (opt-in) fires on owned-file drift,
  skipping dpkg config files unless `owned_file_drift_include_config` is set.
- `max_changed` counts `changed[]` (packages only).
