# SBOMlyze GitHub Action

The root `action.yml` compares an SBOM in the checked-out pull request or commit
with a baseline from git, the latest GitHub release, a successful default-branch
workflow artifact, an explicit HTTPS URL, or a local workspace file. It does not
run an SBOM generator or execute repository-provided commands.

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
| `baseline` | no | `git` | `git`, `release`, `workflow-artifact`, `url`, or `file`. |
| `baseline-repository` | no | current repository | `OWNER/REPO` for release or artifact lookup. |
| `baseline-asset` | for `release` | — | Exact asset name in the latest non-draft, non-prerelease GitHub release. |
| `baseline-artifact` | for `workflow-artifact` | — | Exact artifact name from the newest successful default-branch run containing it. |
| `baseline-artifact-path` | no | `base-sbom-path` | Exact SBOM path inside the artifact ZIP. |
| `baseline-url` | for `url` | — | Public HTTPS URL; credentials and the GitHub token are never forwarded. |
| `baseline-path` | no | `base-sbom-path` | Repository-relative workspace file used by `baseline: file`. |
| `policy` | no | — | Repository-relative SBOMlyze JSON policy. |
| `comment` | no | `false` | Create or update one PR comment. |
| `github-token` | no | `github.token` | Token used for provenance, comments, release assets, and workflow artifacts. |
| `sarif` | no | `false` | Generate `report-sarif`. |
| `fail-on` | no | `policy` | `policy`, `integrity-drift`, `any-change`, or `never`. |
| `version` | no | `v0.4.0` | Exact binary release; floating values such as `latest` are rejected. |

## Baseline providers

### Git pull-request base

`baseline: git` remains the default. It reads `base-sbom-path` directly from the
pull request base SHA without checking out or executing base-branch code. Use
`fetch-depth: 0` so the commit is available.

### Latest GitHub release

```yaml
with:
  sbom-path: build/application.cdx.json
  baseline: release
  baseline-asset: application.cdx.json
```

The latest-release endpoint excludes drafts and prereleases. No release is
treated as a visible first run with an empty baseline; an existing latest
release that lacks the exact asset name fails as configuration error. For a
different repository, set `baseline-repository: OWNER/REPO`; private
cross-repository access requires a token that can read that repository.

### Successful default-branch workflow artifact

```yaml
permissions:
  actions: read
  contents: read

steps:
  - id: sbomlyze
    uses: rezmoss/sbomlyze@FULL_40_CHARACTER_RELEASE_SHA
    with:
      sbom-path: sbom.cdx.json
      baseline: workflow-artifact
      baseline-artifact: baseline-sbom
      baseline-artifact-path: sbom.cdx.json
```

SBOMlyze asks GitHub for successful trusted runs on the repository's default
branch, excludes pull-request runs, searches newest first, ignores expired
artifacts, and extracts only the exact requested file. No matching successful
artifact is a visible first run. An
artifact ZIP with traversal, symlinks, duplicate target paths, encryption,
invalid checksums, or oversized content fails closed. See the
[pinned Syft companion workflow](examples/workflows/syft-companion.yml).

### Explicit URL or local file

```yaml
# Public HTTPS URL. No token or URL credentials are accepted.
with:
  sbom-path: build/application.cdx.json
  baseline: url
  baseline-url: https://downloads.example.org/application.cdx.json

# A file produced or downloaded by an earlier reviewed step.
with:
  sbom-path: build/application.cdx.json
  baseline: file
  baseline-path: downloaded/baseline.cdx.json
```

URL downloads reject HTTP, credentials, non-default ports, private/local
addresses, unsafe redirects, and responses above 50 MiB. Local paths receive
the same traversal, symlink-escape, and size checks as other Action inputs.

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
- Release and workflow-artifact API calls use exact repository, asset, artifact,
  and archive-path matches. `actions: read` is required for private workflow
  artifacts. GitHub tokens are sent only to `api.github.com` and are removed on
  redirects.
- Explicit URL baselines resolve only public HTTPS hosts and never receive the
  GitHub token. For authenticated non-GitHub downloads, use a reviewed download
  step followed by `baseline: file`.
- Parsing uses SBOMlyze strict mode. Malformed and oversized inputs fail closed.
