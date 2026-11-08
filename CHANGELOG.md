# Changelog

## Unreleased

### ⚠ Behavior change

* **`drift_summary.integrity_drift` now means "same-version package digest change".** It used to count any hash change without a version change, including `type: file` entries (manifest and workflow file hashes from Syft directory scans), so `deny_integrity_drift` failed ordinary pull requests. File entries are now reported in `diff.file_changes`; they never count as integrity drift but still count as a change for the exit code and the Action's `fail-on: any-change`.
* Component IDs keep the PURL subpath (`pkg:github/anchore/go-make#.github/actions/setup`); names keep their declared case (`github.com/Microsoft/go-winio`).

### Bug Fixes

* **diff:** compare versions with ecosystem rules (`golang.org/x/mod/semver` for Go and GitHub Actions, SemVer for npm/Cargo/Composer/gem/Swift/Hex/pub, PEP 440 for PyPI). `v`-prefixed versions no longer lose their major number and pseudo-versions sort before releases, so `v0.2.3→v1.0.0` and `v0.0.0-2023…→v1.0.0` are upgrades. Unsupported ecosystems and unparseable versions report direction `unknown`, never a downgrade. (Bug 1)
* **diff:** match packages as occurrences (identity, version, location) instead of keeping the first component per ID. Components sharing an ID are never dropped, leftovers are never paired across two live lockfiles, and results no longer depend on input order. New `moved` and `version_set_changes` lists. (Bug 2)
* **diff:** integrity drift only for packages with the same non-empty version and location and a different digest of the same kind; reads Syft's `syft:metadata:h1Digest` (`go-h1`) and Cargo checksums; adds `file_changes` and `digest_coverage`. (Bug 3)
* **findings:** "Core system packages stable … unchanged" only for types with no changed, added, removed or moved package; otherwise "golang: 342 packages before and after (N version changes)". (Bug 4)
* **html:** the Format row shows the document format (CycloneDX 1.6, SPDX 2.3, Syft JSON); a new Generator row shows the tool. `SBOMInfo` gains `format` and `spec_version`. (Bug 5)
* **cyclonedx:** keep `license.name` as a declared license; it is never counted as SPDX-valid in compliance. (Bug 6)
* **normalize:** stop lowercasing names; case folding applies only to npm and PyPI match keys. (Bug 7)
* **findings:** list version changes with unknown direction (e.g. `release/v1 → v1.14.3`). (Bug 8)
* **diff:** a digest added on one side no longer turns a license change into integrity drift. (Bug 9)
* **diff:** CycloneDX locations are read from `syft:location:N:path`, `sbomlyze:location` and `evidence.occurrences`; Syft JSON primary-evidence locations are used for matching.
* **diff:** dependency graphs merge components that share an ID, and duplicate groups, findings and ties are sorted deterministically.
* **output:** SARIF fingerprints and JSON Patch paths include the location, so one package in two lockfiles is two results; SARIF, text and policy messages show the location.

### JSON fields added

`diff.changed[].location`, `diff.changed[].drift.direction` (`upgrade|downgrade|none|unknown`), `diff.changed[].drift.level` (`major|minor|patch|prerelease|none|unknown`), `diff.moved[]` (`id, name, version, from, to`), `diff.version_set_changes[]` (`id, name, location, removed_versions, added_versions`), `diff.file_changes[]` (`path, hashes_before, hashes_after`), `diff.drift_summary.{upgrades, downgrades, unknown_direction, distinct_version_changes, file_changes, license_changes}`, `diff.digest_coverage.{same_version_pairs, comparable, before_only, after_only, disjoint_kinds, by_kind, packages_total}`, `overview.*.info.{format, spec_version}`, component `digests` (`go-h1`, `cargo-checksum`).

## [0.6.0](https://github.com/rezmoss/sbomlyze/compare/v0.5.4...v0.6.0) (2026-11-01)


### Bug Fixes

* **web:** bind to loopback, block DNS rebinding, cap uploads ([#73](https://github.com/rezmoss/sbomlyze/issues/73)) ([1b086c8](https://github.com/rezmoss/sbomlyze/commit/1b086c8eabaf6688500cc9009ec0f3d3691a0ee4))

## [0.5.4](https://github.com/rezmoss/sbomlyze/compare/v0.5.3...v0.5.4) (2026-10-01)


### Bug Fixes

* **deps:** ship Go 1.25.14 toolchain and cyclonedx-go v0.12.0 ([#61](https://github.com/rezmoss/sbomlyze/issues/61)) ([8f8c8a0](https://github.com/rezmoss/sbomlyze/commit/8f8c8a052332d7f03605d94086cca1b38a84c3c1))

## [0.5.3](https://github.com/rezmoss/sbomlyze/compare/v0.5.2...v0.5.3) (2026-08-29)


### Bug Fixes

* sync action version metadata to v0.5.2 ([#51](https://github.com/rezmoss/sbomlyze/issues/51)) ([9662e6b](https://github.com/rezmoss/sbomlyze/commit/9662e6b13f556ac0efe50e472b5af32dcfe00f9a))

## [0.5.2](https://github.com/rezmoss/sbomlyze/compare/v0.5.1...v0.5.2) (2026-08-28)


### Bug Fixes

* **sbom:** guard nil SPDX packages and external refs (crashes found by new fuzzer); upgrade golang.org/x/text to v0.39.0 for GO-2026-5970 ([#50](https://github.com/rezmoss/sbomlyze/issues/50)) ([fdb5e2b](https://github.com/rezmoss/sbomlyze/commit/fdb5e2b99b7d7d162a0c269c7cd6c2da2f48b9c7))

## [0.5.1](https://github.com/rezmoss/sbomlyze/compare/v0.5.0...v0.5.1) (2026-08-09)


### Bug Fixes

* **sarif:** prevent cross-PR alert collisions ([#47](https://github.com/rezmoss/sbomlyze/issues/47)) ([4ade8dd](https://github.com/rezmoss/sbomlyze/commit/4ade8ddd3302ea3e247282f4ce2239d6625b6e5d))

## [0.5.0](https://github.com/rezmoss/sbomlyze/compare/v0.4.0...v0.5.0) (2026-08-09)


### Features

* **action:** add generated SBOM baseline providers ([02b36c3](https://github.com/rezmoss/sbomlyze/commit/02b36c355ccc967caa8aec364172f4724e9e8df0))
* **action:** add generated SBOM baseline providers ([1fcf995](https://github.com/rezmoss/sbomlyze/commit/1fcf9956e881bce60f9870aa484973fc766210b1))


### Bug Fixes

* **action:** correct Syft artifact baseline workflow ([3910c02](https://github.com/rezmoss/sbomlyze/commit/3910c0226072bc9cfbd4694bfb512763d5e36edb))
* **action:** correct Syft artifact baseline workflow ([4f81bdf](https://github.com/rezmoss/sbomlyze/commit/4f81bdfca566d57448489b85dd58d3a2300487ff))

## [0.4.0](https://github.com/rezmoss/sbomlyze/compare/v0.3.7...v0.4.0) (2026-08-09)


### Features

* **action:** add secure SBOM diff GitHub Action MVP ([fc7cbf4](https://github.com/rezmoss/sbomlyze/commit/fc7cbf4284b9704d1691111946a86e5cec30d7ec))
* **action:** add secure SBOM diff GitHub Action MVP ([6f00ac9](https://github.com/rezmoss/sbomlyze/commit/6f00ac9029063e85ec795de2ff501a64b4a832b5))
