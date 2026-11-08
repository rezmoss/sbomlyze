#!/usr/bin/env bash
# Build sbomlyze.com: reference data + example report from SRC, pages from ./site.
# usage: scripts/site-build.sh SRC TAG SHA STARS OUT
set -euo pipefail
SRC=$(cd "$1" && pwd) TAG=$2 SHA=$3 STARS=$4 OUT=$5
ROOT=$(pwd)
BIN="${RUNNER_TEMP:-$(mktemp -d)}/sbomlyze-site"

# released binary, for the example report
(cd "$SRC" && go build -o "$BIN" ./cmd/sbomlyze)

# reference data from the release; tags before the generator use this checkout
GEN="$SRC"
if [ ! -d "$SRC/internal/tools/sitegen" ]; then
  echo "::notice::$TAG has no sitegen; generating reference data from $(git -C "$ROOT" rev-parse --short HEAD)"
  GEN="$ROOT"
fi
(cd "$GEN" && go run ./internal/tools/sitegen -repo . -site "$ROOT/site" -tag "$TAG" -sha "$SHA" -stars "$STARS")

ex="$ROOT/site/static/examples/syft"
mkdir -p "$ex"
for f in html json markdown; do
  ext=$f; [ "$f" = markdown ] && ext=md
  # exit 1 means "differences found"
  "$BIN" "$SRC/testdata/realworld/syft-before.cdx.json" "$SRC/testdata/realworld/syft-after.cdx.json" \
    --format "$f" --no-pager > "$ex/report.$ext" || [ $? -eq 1 ]
  [ -s "$ex/report.$ext" ] || { echo "empty example report: $ext" >&2; exit 1; }
done

hugo --minify --source "$ROOT/site" --destination "$OUT"
grep -q "content=\"$TAG\"" "$OUT/index.html" || { echo "built site does not show $TAG" >&2; exit 1; }
