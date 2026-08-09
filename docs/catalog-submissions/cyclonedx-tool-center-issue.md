# Tool Center submission: SBOMlyze

Please add SBOMlyze to the CycloneDX Tool Center.

SBOMlyze is an open-source CLI and GitHub Action that consumes CycloneDX SBOMs,
compares them with a trusted baseline, detects same-version hash/integrity drift
and other semantic changes, evaluates policy, and can convert between
CycloneDX, SPDX, and Syft formats.

The proposed `tools/sbomlyze.json` entry below validates against the current
`schemas/tool.schema.json` on the `main` branch.

```json
{
  "$schema": "https://cyclonedx.org/schema/tool-center-v2.tool.schema.json",
  "specVersion": "2.0",
  "tool": {
    "name": "SBOMlyze",
    "publisher": "rezmoss",
    "description": "Open-source CLI and GitHub Action that compares CycloneDX, SPDX, and Syft SBOMs; detects same-version hash drift, dependency-graph, license, and compliance regressions; and gates pull requests with policy and SARIF.",
    "repository_url": "https://github.com/rezmoss/sbomlyze",
    "website_url": "https://rezmoss.github.io/sbomlyze/",
    "capabilities": [
      "SBOM"
    ],
    "availability": [
      "OPEN_SOURCE",
      "OSI_APPROVED"
    ],
    "functions": [
      "ANALYSIS",
      "TRANSFORM"
    ],
    "analysis": [
      "LICENSE_REPORTING",
      "POLICY_EVALUATION"
    ],
    "transform": [
      "BOM_SERIALIZATION_FORMAT",
      "BOM_STANDARD"
    ],
    "packaging": [
      "APPLICATION",
      "COMMAND_LINE_UTILITY",
      "GITHUB_ACTION"
    ],
    "platform": [
      "LINUX",
      "MAC",
      "WINDOWS"
    ],
    "lifecycle": [
      "BUILD",
      "POST-BUILD"
    ],
    "supportedStandards": [
      "CPE",
      "CYCLONEDX",
      "PACKAGE_URL",
      "SPDX"
    ],
    "cycloneDxVersion": [
      "CYCLONEDX_V1.6",
      "CYCLONEDX_V1.5",
      "CYCLONEDX_V1.4"
    ]
  }
}
```

Evidence:

- Repository: https://github.com/rezmoss/sbomlyze
- CycloneDX demonstration: https://github.com/rezmoss/sbomlyze-node-cyclonedx-demo
- GitHub Marketplace Action: https://github.com/marketplace/actions/sbomlyze-diff
- License: Apache-2.0
