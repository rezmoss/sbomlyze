#!/usr/bin/env bash
# Build sbomlyze.com: reference data and examples from SRC, pages from ./site.
# usage: scripts/site-build.sh SRC TAG SHA STARS OUT
# env:
#   SHOWCASE_PREV      previous release's examples dir, for "changed since"
#   SHOWCASE_ARCHIVES  comma-separated tags with archived outputs
#   SHOWCASE_MEDIA     1 = render screenshots and recordings (vhs, node, chrome)
set -euo pipefail
SRC=$(cd "$1" && pwd) TAG=$2 SHA=$3 STARS=$4 OUT=$5
ROOT=$(pwd)
TMP="${RUNNER_TEMP:-$(mktemp -d)}"
BIN="$TMP/sbomlyze-site"

# released binary, for the examples
(cd "$SRC" && go build -o "$BIN" ./cmd/sbomlyze)

# reference data from the release; tags before the generator use this checkout
GEN="$SRC"
if [ ! -d "$SRC/internal/tools/sitegen" ]; then
  echo "::notice::$TAG has no sitegen; generating reference data from $(git -C "$ROOT" rev-parse --short HEAD)"
  GEN="$ROOT"
fi
(cd "$GEN" && go run ./internal/tools/sitegen -repo . -site "$ROOT/site" -tag "$TAG" -sha "$SHA" -stars "$STARS")

# examples: frozen inputs, run with the released binary
rm -rf "$ROOT/site/content/examples" "$ROOT/site/data/gen/showcase.json"
find "$ROOT/site/static/examples" -mindepth 1 -maxdepth 1 ! -name media -exec rm -rf {} + 2>/dev/null || true
if [ ! -d "$SRC/internal/tools/showcase" ]; then
  echo "::notice::examples skipped: $TAG predates them"
else
  # frozen inputs live in this checkout (testdata/showcase)
  (cd "$ROOT" && go run ./internal/tools/showcase -inputs testdata/showcase -bin "$BIN" -site site -tag "$TAG" \
    -prev "${SHOWCASE_PREV:-}" -archives "${SHOWCASE_ARCHIVES:-}")
  if [ "${SHOWCASE_MEDIA:-0}" = 1 ]; then
    scripts/showcase-media.sh testdata/showcase "$BIN" "$ROOT/site/static/examples/media"
  fi
fi

hugo --minify --source "$ROOT/site" --destination "$OUT"
grep -q "content=\"$TAG\"" "$OUT/index.html" || { echo "built site does not show $TAG" >&2; exit 1; }
