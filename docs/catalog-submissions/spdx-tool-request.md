# SPDX tool request: SBOMlyze

This document mirrors the fields in SPDX's `Add SPDX Tool` GitHub issue form.

## Tool or Product name

SBOMlyze

## Open Source or Proprietary

Open source

## Company or Organization name

SBOMlyze project

## Organization or Company Logo Usage

No organization or company logo requested.

## Public Contact Email or URL

https://github.com/rezmoss/sbomlyze/issues

## Product or tool website

https://rezmoss.github.io/sbomlyze/

## Description

SBOMlyze is an Apache-2.0 CLI and GitHub Action for reviewing SPDX, CycloneDX,
and Syft SBOM changes. It compares component identity, versions, hashes,
licenses, suppliers, and dependency graphs; detects same-version integrity
drift; scores SBOM quality; converts formats; and gates pull requests using
policy, SARIF, JUnit, Markdown, or JSON reports.

## SBOM tool category

- Consume (View)
- Consume (Diff)
- Transform (Translate)
- Transform (Tool Support)

## SPDX Versions supported

- SPDX 2.3

## SPDX verification

Automated Go tests parse SPDX 2.3 documents from synthetic fixtures and real
Syft output, verify package identity, checksums, licenses, external references,
and relationships, and exercise SPDX-to-CycloneDX/Syft conversions. Conversion
tests verify required SPDX 2.3 document fields and reparse generated output to
check component and relationship preservation.

## How to procure

Download provenance-attested binaries from GitHub Releases, install with
Homebrew or `go install`, build from source, or use SBOMlyze Diff from GitHub
Marketplace. The project is free under Apache-2.0.

## Installation instructions

Installation and verified-download instructions are in the repository README:
https://github.com/rezmoss/sbomlyze#installation

## Link to quick start guide

https://github.com/rezmoss/sbomlyze#quick-start

## Link to logo

No separate project logo is currently supplied.
