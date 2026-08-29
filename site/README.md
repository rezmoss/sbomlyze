# sbomlyze.com

Hugo source for the project website, published to https://sbomlyze.com (GitHub Pages, `gh-pages` branch).

## Local development

```sh
cd site
hugo server          # http://localhost:1313
```

Requires Hugo extended ≥ 0.123 (`brew install hugo`).

## Publishing

Pushing changes under `site/**` to `main` triggers `.github/workflows/deploy-site.yml`, which builds the site and syncs the output into the `gh-pages` branch. The workflow preserves the Linux package repositories (`apk/`, `deb/`, `rpm/`) and the `vendor/` directory served from that branch — only site files are replaced.

The `Update Package Repository` workflow continues to own the package directories on `gh-pages`; it no longer writes `index.html`.

## Where things live

- `hugo.toml` — site config. `params.version` and `params.actionSha` (the pinned commit shown in the GitHub Action example) are bumped automatically by `.github/workflows/sync-site-version.yml` on every release; it opens and merges a PR, then redeploys the site. Run it manually from the Actions tab (with a tag input) if a sync is ever missed.
- `content/` — one stub file per page; the real markup lives in layouts.
- `layouts/_default/` — page templates (`drift`, `action`, `cli`, `compliance`, `install`) plus `baseof.html` (header/footer).
- `layouts/index.html` — home page.
- `data/*.yaml` — all tables and lists (Action inputs, CLI options, policy rules, frameworks…). Edit these to update reference content without touching HTML.
- `assets/css/main.css` — the whole stylesheet.
- `static/CNAME` — custom domain binding for GitHub Pages; must stay.
