# SBOMlyze Action beta

The beta is a focused installation and review test for the SBOMlyze Diff GitHub
Action. It should take about 10 minutes. We are testing activation and signal
quality before adding more features.

## Try it without a walkthrough

Choose the example closest to your work:

- [Go application with SPDX](https://github.com/rezmoss/sbomlyze-go-spdx-demo)
- [Node application with CycloneDX](https://github.com/rezmoss/sbomlyze-node-cyclonedx-demo)
- [Container with OS and application packages](https://github.com/rezmoss/sbomlyze-container-demo)

Fork the example, follow only its README, and open one demonstration pull
request. Start with `normal-dependency-upgrade`; then try
`same-version-hash-change` if you have time. Read the SBOMlyze Job Summary as if
you were approving a production dependency update.

Do not grant extra permissions or use `pull_request_target`. The examples keep
comments off and remain useful for forks through the Job Summary.

## Send four answers

Open the [beta feedback form](https://github.com/rezmoss/sbomlyze/issues/new?template=beta-feedback.yml)
and answer:

1. Could you install it without help?
2. Did the pull-request result tell you what needed review?
3. Which finding was noisy or misleading?
4. Would you make this a required check? Why or why not?

Please report unclear instructions or permission failures even if you worked
around them. Those are product bugs for this beta.

## Maintainer recruitment plan

Recruit eight people individually, stopping when five have completed the test:

| Cohort | Target | Why it matters |
|---|---:|---|
| Existing contributors or users | 2 | Knows the project but has not used this workflow |
| Syft users | 2 | Tests the generator-companion mental model |
| CycloneDX or SPDX practitioners | 2 | Tests format expectations and report accuracy |
| DevSecOps engineers or small security teams | 2 | Tests required-check usefulness in real review work |

Use a personal, opt-in message; do not bulk-post the same promotion across
communities:

> I am testing a GitHub Action that reviews SBOM changes in pull requests. The
> exercise takes about 10 minutes using a public demo repo. I am looking for
> honest feedback on installation, review clarity, noise, and whether it could
> be a required check. Would you be willing to try it? No setup call is needed:
> https://github.com/rezmoss/sbomlyze/blob/main/BETA.md

Track only completion and the four answers. Fix any issue that blocks install,
hides the review decision, or produces a misleading finding before expanding
the Action's feature set.
