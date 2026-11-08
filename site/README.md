# sbomlyze.com

Hugo source for the project website, published to https://sbomlyze.com (GitHub Pages, `gh-pages` branch).

## How it stays current

After every **successful** release, the `website` job in `.github/workflows/release.yml` calls `.github/workflows/site.yml` with the new tag. It:

1. checks out `main` (pages, wording, styles) and the release tag (code);
2. runs `internal/tools/sitegen` on the tag to write `site/data/gen/*.json` and the generated pages;
3. builds the released binary and renders a real example report (`/examples/`);
4. builds with Hugo, commits to `gh-pages` (keeping `apk/`, `deb/`, `rpm/`, `vendor/`), and
5. waits until sbomlyze.com serves the new tag (`<meta name="sbomlyze-version">`), failing the run otherwise.

A release that fails never touches the site; a site failure never undoes a release. Pushes to `main` under `site/**` redeploy with the latest release's data, for wording fixes. Run **Website** from the Actions tab (optional tag, optional preview-only) to recover or preview.

## Generated, never edited by hand

| Site content | Source |
|---|---|
| Version, Action pin SHA, GitHub stars | release tag, GitHub API |
| Action inputs / outputs | `action.yml` |
| CLI options, output formats | `internal/cli/docs.go` (also prints `--help`) |
| Policy rules | `doc` tags on `internal/policy.Policy` |
| SARIF rules | `output.SARIFRules()` |
| Compliance checks | `internal/compliance` |
| Version ordering table | `analysis.VersionOrderings()` + `internal/analysis/testdata/version-oracle` |
| What's new, Changelog | `CHANGELOG.md` |
| JSON reference | `docs/diff-json-contract.md` |
| Example report | released binary on `testdata/realworld/syft-*.cdx.json` |

These files are git-ignored (`site/data/gen/`, `site/content/changelog.md`, `site/content/json-reference.md`, `site/static/examples/`). The build fails if they are missing. Tests in `internal/tools/sitegen` fail when a policy field has no `doc` tag or README row, or a parsed CLI flag is missing from `--help`.

Hand-written: page templates (`layouts/`), narrative data (`data/home.yaml`, `data/drift.yaml`, `data/action.yaml` baselines and security notes, `data/cli.yaml` identity and formats, `data/compliance.yaml` framework blurbs) and `assets/css/main.css`. On a release PR with new features, CI comments a reminder to review them.

## Local development

```sh
make site-serve      # generate data, then http://localhost:1313
make site            # full CI build into site/public
```

Requires Go and Hugo extended ≥ 0.123 (`brew install hugo`). `static/CNAME` binds the custom domain and must stay.
