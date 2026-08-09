# The dependency version did not change. Why did its hash change?

A dependency review usually starts with a familiar question: which package
versions changed? That is necessary, but it is not enough to explain what was
actually built.

A manifest diff, an ordinary SBOM component diff, and an integrity-drift check
answer three different questions. Treating them as interchangeable leaves a
blind spot: a component can keep the same name and version while its bytes
change.

This article shows where each comparison helps, where it stops, and how to add
the missing integrity signal to a pull request without turning every SBOM
change into an incident.

## The three layers

| Layer | Primary question | Strongest signal | Important blind spot |
|---|---|---|---|
| Manifest or lockfile diff | What dependency resolution did the developer request or record? | Direct and resolved version changes | Does not prove what entered the built artifact |
| Ordinary SBOM component diff | What components does each build report? | Added, removed, and version-changed components | A same-name, same-version replacement can look unchanged |
| Hash/integrity drift | Did the recorded bytes change without the component version changing? | Unexpected same-version hash change | Signals investigation; it does not by itself prove malicious intent |

These layers complement one another. SBOMlyze does not replace a package
manager, an SBOM generator, signature verification, or a vulnerability scanner.
It reviews the evidence produced by the build and classifies what changed
between two points in time.

## 1. Manifest diff: developer intent

Suppose a pull request changes a Go module from one released version to the
next:

```diff
- github.com/google/uuid v1.5.0
+ github.com/google/uuid v1.6.0
```

That is an excellent review surface. The reviewer can inspect the upstream
release, compatibility notes, and vulnerability history. A lockfile may add
the fully resolved transitive graph and registry integrity values.

But the manifest describes dependency resolution, not necessarily the final
artifact. It may omit operating-system packages, copied binaries, vendored
files, build-stage tools, generated assets, or components introduced by the
container base image. A source manifest also cannot tell you whether a registry
served different bytes under an existing version or whether a later build step
replaced a file.

Use a manifest diff to review requested dependency intent. Do not ask it to be
an inventory of the finished build.

## 2. Ordinary SBOM component diff: build inventory

An SBOM generator observes a source tree, filesystem, package database,
container image, or built artifact and writes a normalized inventory. Comparing
two inventories can reveal changes a manifest misses:

- a new transitive package;
- an operating-system package added by a base-image update;
- a component removed from the final artifact;
- a resolved version that differs from the source declaration;
- a license, supplier, or dependency-graph change.

This is closer to the question a release reviewer cares about: what is in this
build that was not in the trusted baseline?

The naive implementation is a JSON diff. That usually produces noise from
timestamps, serial numbers, generated identifiers, ordering, and format-specific
metadata. A useful SBOM diff must first identify the same component across both
documents and then classify semantic changes.

SBOMlyze matches component identity using stable identifiers when available,
including Package URLs and CPEs, with format-specific references and names as
fallbacks. It can therefore compare SPDX, CycloneDX, and Syft JSON evidence
without requiring the two documents to have identical layouts.

An ordinary component comparison still has a subtle failure mode. If a package
is called `example` at version `1.4.2` in both SBOMs, a name-and-version diff
calls it unchanged—even if the component bytes are different.

## 3. Integrity drift: same identity and version, different bytes

Integrity drift is the narrow condition where SBOMlyze matches a component in
both SBOMs, sees the same version, and finds that its recorded hash set changed.

```text
component: pkg:golang/example/project@1.4.2
version:   1.4.2 -> 1.4.2
hash:      c4e3...aa89 -> 345c...fa36
verdict:   integrity drift
```

This is more actionable than reporting merely that a JSON field changed. The
version says consumers should be receiving the same release, while the hash
says the recorded content is not the same. Those two facts disagree, so a
reviewer should establish why before merging.

Possible explanations include:

- a package or artifact was replaced without a version bump;
- a dependency mirror or registry served different content;
- the build is not reproducible and embeds timestamps or environment data;
- the SBOM generator changed what bytes it hashes;
- platform, architecture, or build flags changed between the baseline and head;
- the trusted baseline was generated from a different stage of the build.

Some explanations are benign. The point of the check is not to label every hash
change an attack. It is to prevent a silent mismatch from passing as "no
dependency change."

## A real blocked pull request

The public [Go + SPDX demonstration pull request](https://github.com/rezmoss/sbomlyze-go-spdx-demo/pull/2)
changes one SPDX checksum while leaving the component version unchanged.
SBOMlyze reports one integrity-drift finding, triggers the
`deny_integrity_drift` policy, uploads SARIF, and fails the `sbom-diff` check.

The example is deliberately small, but it follows the production review path:

1. The workflow retrieves the baseline SBOM from the pull request's base SHA.
2. SBOMlyze normalizes and matches components in the base and head documents.
3. It classifies the same-version hash change as integrity drift.
4. The policy gate blocks the pull request while preserving the report in the
   Job Summary and code-scanning results.

The [38-second demonstration](assets/tamper-drift-demo.gif) is generated from
that public pull request and its real failed workflow run.

## Add the check without executing pull-request code

If your build already commits or safely generates an SBOM, the file-based
Action can review it directly:

```yaml
name: SBOM review

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

      - id: sbomlyze
        uses: rezmoss/sbomlyze@31503690611fda8ebba4ed2bd186eda000442594 # v0.5.1
        with:
          sbom-path: build/sbom.cdx.json
          policy: .github/sbom-policy.json
          fail-on: policy
          sarif: true

      # Fork PR tokens cannot upload SARIF. The Job Summary still works.
      - uses: github/codeql-action/upload-sarif@e4fba868fa4b1b91e1fdab776edc8cfbe6e9fb81 # v4.37.3
        if: >-
          always() &&
          steps.sbomlyze.outputs.report-sarif != '' &&
          github.event.pull_request.head.repo.full_name == github.repository
        with:
          sarif_file: ${{ steps.sbomlyze.outputs.report-sarif }}
```

The Action does not execute an arbitrary generator supplied by a pull request.
For generated SBOMs, use a separate, pinned generator workflow and publish the
trusted default-branch result as a workflow artifact. SBOMlyze can retrieve that
artifact with `baseline: workflow-artifact` and remain focused on review and
policy.

A minimal policy for the integrity signal is:

```json
{
  "deny_integrity_drift": true
}
```

Keep pull-request comments disabled until you intentionally grant write
permission. The Job Summary remains useful for forked pull requests with
read-only tokens.

## Make the signal trustworthy

Hash comparison is only as stable as the evidence around it. Before making the
check required:

1. Generate baseline and head SBOMs at the same lifecycle stage.
2. Pin the generator and its configuration.
3. Keep operating system, architecture, and build flags comparable.
4. Prefer cryptographic component hashes emitted by the generator; do not
   synthesize them from names and versions.
5. Investigate one expected rebuild to identify legitimate nondeterminism.
6. Update the baseline only after the change has been reviewed and accepted.

If a generator upgrade changes hash semantics, review and land that migration
separately. A broad baseline refresh mixed into an application dependency pull
request defeats the purpose of the control.

## A practical review rule

The three comparisons lead to a simple triage model:

- **Manifest changed, component version changed:** review the intended upgrade.
- **Manifest did not change, SBOM components changed:** identify the build or
  transitive source of the inventory change.
- **Component version did not change, component hash changed:** stop and explain
  the content mismatch before merging.

That last case is small, specific, and easy to miss. Giving it its own policy
signal turns an ambiguous SBOM diff into a review decision.

Try the [GitHub Marketplace Action](https://github.com/marketplace/actions/sbomlyze-diff),
or reproduce the scenario in the
[Go/SPDX](https://github.com/rezmoss/sbomlyze-go-spdx-demo),
[Node/CycloneDX](https://github.com/rezmoss/sbomlyze-node-cyclonedx-demo), and
[container](https://github.com/rezmoss/sbomlyze-container-demo) demo repositories.
