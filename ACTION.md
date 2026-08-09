# SBOMlyze GitHub Action

The root `action.yml` compares an SBOM in the checked-out pull request or commit
with the same file (or `base-sbom-path`) from the git baseline. It does not run an
SBOM generator or execute repository-provided commands.

## Recommended workflow

Pin both Actions to full commit SHAs. Replace `FULL_40_CHARACTER_ACTION_SHA`
with the future commit that contains this Action before enabling the workflow.
The already-published `v0.3.7` tag contains the binary release but predates the
Action, so its commit SHA is not a valid Action pin.

```yaml
name: SBOM drift

on:
  pull_request:

permissions:
  contents: read

jobs:
  sbom-diff:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0

      # Generate or commit the head SBOM in a separate, reviewed step. SBOMlyze
      # deliberately does not accept or execute generator commands.
      - id: sbomlyze
        uses: rezmoss/sbomlyze@FULL_40_CHARACTER_ACTION_SHA # binary defaults to v0.3.7
        with:
          sbom-path: build/sbom.cdx.json
          policy: .github/sbom-policy.json
          fail-on: policy

      - uses: github/codeql-action/upload-sarif@v3
        if: always() && steps.sbomlyze.outputs.report-sarif != ''
        with:
          sarif_file: ${{ steps.sbomlyze.outputs.report-sarif }}
```

Set `sarif: true` on the SBOMlyze step and grant `security-events: write` if the
SARIF upload is required. Pin `upload-sarif` to a reviewed full SHA in production
as well.

## Inputs

| Input | Required | Default | Meaning |
|---|---:|---|---|
| `sbom-path` | yes | — | Repository-relative head SBOM path. |
| `base-sbom-path` | no | `sbom-path` | Different repository-relative path at the baseline revision. |
| `baseline` | no | `git` | Baseline source. Only `git` is accepted by the MVP. |
| `policy` | no | — | Repository-relative SBOMlyze JSON policy. |
| `comment` | no | `false` | Create or update one PR comment. |
| `github-token` | no | `github.token` | Token used for provenance and an optional comment. |
| `sarif` | no | `false` | Generate `report-sarif`. |
| `fail-on` | no | `policy` | `policy`, `integrity-drift`, `any-change`, or `never`. |
| `version` | no | `v0.3.7` | Exact binary release; floating values such as `latest` are rejected. |

`baseline: release`, `artifact`, `url`, and `file` are reserved for later
versions and currently fail with an explicit error.

## Outputs

`verdict` is `pass` or `fail`. Count outputs are decimal strings:
`added-count`, `removed-count`, `changed-count`, and
`integrity-drift-count`. `report-json`, `report-markdown`, and `report-sarif`
are absolute runner paths so later steps can upload or process the full reports
without hitting GitHub's workflow-output size limit. `report-sarif` is empty
unless `sarif: true`.

Outputs and the Job Summary are written before a configured gate fails, so use
`if: always()` when consuming reports from a later step.

## Pull-request comments and forks

The default requires only `contents: read` and always writes the report to the
Job Summary. To enable comments for same-repository pull requests:

```yaml
permissions:
  contents: read
  pull-requests: write

steps:
  - id: sbomlyze
    uses: rezmoss/sbomlyze@FULL_40_CHARACTER_ACTION_SHA # binary defaults to v0.3.7
    with:
      sbom-path: build/sbom.cdx.json
      comment: true
```

The Action updates its existing bot comment using a private marker rather than
creating duplicates. Forked pull requests normally receive a read-only token;
comment failures caused by missing permissions are warnings, not Action
failures, and the Job Summary remains available. Do not use
`pull_request_target` to run or generate untrusted pull-request code.

## Security behavior

- SBOM, policy, and baseline paths must stay inside the repository; absolute
  paths, traversal, symlink escape, and unsafe archive entries are rejected.
- Head, baseline, and policy files are limited to 50 MiB. Command output,
  downloads, comments, and summaries have separate bounded limits.
- The exact release archive and `checksums.txt` are downloaded only over HTTPS
  from GitHub release hosts. SHA-256 is mandatory before extraction.
- When `gh attestation verify` is available, provenance from this repository's
  release workflow is mandatory. If `gh` is absent, the Action emits a warning
  after checksum verification.
- Inputs are passed to `git`, `tar`, `gh`, and SBOMlyze as process argument
  arrays. No input is interpolated into a shell command.
- Git baselines are read with `git cat-file` and `git show`; the Action never
  checks out baseline code. A missing baseline path is treated as an empty
  first-run baseline. A missing baseline commit fails with instructions to use
  `fetch-depth: 0`.
- Parsing uses SBOMlyze strict mode. Malformed and oversized inputs fail closed.
