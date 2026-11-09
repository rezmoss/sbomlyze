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
| `os_change` *(new)* | The base OS release changed (`from`, `to`, e.g. `Debian GNU/Linux 12 (bookworm) 12.10` → `… 12.12`). Only when both SBOMs name the OS (Syft SPDX does not). Counts as a change for the exit code |
| `source_change` *(new)* | The scanned source kept its name but its version or digest changed (a re-pushed image tag): `name`, `from`, `to`. Counts as a change for the exit code |
| `version_set_changes[]` *(new)* | Several versions changing at one location with no justified pairing: `id`, `name`, `location`, `removed_versions`, `added_versions`. The occurrences are also in `added`/`removed` |

## File changes *(new)*

| Field | Meaning |
|---|---|
| `file_changes[]` | Files whose content changed: `path`, `hashes_before`, `hashes_after`, `owners` (`name@version`, when recorded) |
| `files_added[]`, `files_removed[]` | Inventory files (Syft JSON, SPDX, CycloneDX `type: file`) that appeared or disappeared: `path`, `hashes`, `owners` |
| `owned_file_drift[]` | Packages that kept their version while files they own changed: `id`, `name`, `version`, `location`, `files[]` (`path`, `change`, `config`, `hashes_before`, `hashes_after`) |
| `file_coverage` | `files_compared`, `files_unverified`, `ambiguous_paths`, `owned_files_after`, `unowned_files_after`, `config_unknown` |

### Same results across formats *(new)*

The same image scanned once and written as Syft JSON, CycloneDX and SPDX diffs to nothing, in any combination. To get there:

- CycloneDX `type: file` entries are the file inventory, like Syft JSON and SPDX `files`: they are reported in `file_changes`, `files_added` and `files_removed`, no longer in `added`/`removed`.
- `operating-system` entries without a PURL or CPE (Syft's) are not matched as packages; the release change is `os_change`. An OS entry with a PURL or CPE is matched like any package.
- Licenses are compared as a set of terms: `[A, B]` equals `A AND B`; outer parentheses, case and the `LicenseRef-`/`sha256:` prefixes are ignored. `OR` and `WITH` expressions keep their structure, so `LicenseRef-MIT-OR-Apache-2.0` is not `MIT OR Apache-2.0`. Free text and single ids match their SPDX `LicenseRef` folding (`Apache 2.0` = `LicenseRef-Apache-2.0`, `MIT/X11` = `MIT-X11`). An OSGi `Bundle-License` value `<url>;description=BUSL-1.1` is the id `BUSL-1.1`.
- Owned files are compared only when both inventories can record ownership (Syft JSON, SPDX; not CycloneDX).
- A file without a hash is not reported as added or removed when the other SBOM's inventory is CycloneDX file entries, which list hashed files only. Syft's all-zero SPDX placeholder checksum counts as no hash.
- Package locations come from Syft's CycloneDX `syft:location` properties (first = primary) and SPDX `sourceInfo`.

The scanned image or directory is the source, not a component: an SPDX root package (`SPDXRef-DocumentRoot-*`, or a described `pkg:oci`/`pkg:docker` package) is no longer listed in `changed`.

Syft JSON `dependency-of` relationships are read as Syft defines them: the parent is the dependency of the child. Earlier versions read them reversed.

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
- `deny_downgrades` *(new)* fires on each `downgrade` direction.
- `deny_licenses` checks added packages and licenses newly appearing on changed packages, matching ids inside `AND`/`OR`/`WITH` expressions.
- A policy file with an unknown key is an error.
