# SBOMlyze GitHub Action

The root `action.yml` compares an SBOM in the checked-out pull request or commit
with the same file (or `base-sbom-path`) from the git baseline. It does not run an
SBOM generator or execute repository-provided commands.

## Recommended workflow

Pin all Actions to full commit SHAs. The SBOMlyze SHA below is the published
`v0.4.0` Action. The binary version defaults to the same release.

```yaml
name: SBOM drift

on:
  pull_request:

permissions:
  contents: read
  security-events: write

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
        uses: rezmoss/sbomlyze@38e8c3616f56e3748c06fe26bbe68c80b4763ebc # v0.4.0
        with:
          sbom-path: build/sbom.cdx.json
          policy: .github/sbom-policy.json
          fail-on: policy
          sarif: true

      - uses: github/codeql-action/upload-sarif@e4fba868fa4b1b91e1fdab776edc8cfbe6e9fb81 # v4.37.3
        if: always() && steps.sbomlyze.outputs.report-sarif != ''
        with:
          sarif_file: ${{ steps.sbomlyze.outputs.report-sarif }}
```

Remove `security-events: write`, `sarif: true`, and the upload step if SARIF is
not required. Forked pull requests may not receive permission to upload SARIF;
the SBOMlyze Job Summary remains available.

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
| `version` | no | `v0.4.0` | Exact binary release; floating values such as `latest` are rejected. |

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
    uses: rezmoss/sbomlyze@38e8c3616f56e3748c06fe26bbe68c80b4763ebc # v0.4.0
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
