#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_path="${1:-$repo_root/docs/assets/tamper-drift-demo.gif}"
chrome_path="${CHROME_PATH:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
font_regular="${FONT_REGULAR:-/System/Library/Fonts/Supplemental/Arial.ttf}"
font_bold="${FONT_BOLD:-/System/Library/Fonts/Supplemental/Arial Bold.ttf}"
work_path="$(mktemp -d)"
trap 'rm -rf "$work_path"' EXIT

if [[ ! -x "$chrome_path" ]]; then
  echo "Google Chrome was not found at: $chrome_path" >&2
  echo "Set CHROME_PATH to a Chrome or Chromium executable." >&2
  exit 1
fi

if ! command -v magick >/dev/null 2>&1; then
  echo "ImageMagick is required (brew install imagemagick)." >&2
  exit 1
fi

if [[ ! -f "$font_regular" || ! -f "$font_bold" ]]; then
  echo "Arial font files were not found." >&2
  echo "Set FONT_REGULAR and FONT_BOLD to readable TrueType font files." >&2
  exit 1
fi

mkdir -p "$(dirname "$output_path")"

capture() {
  local url="$1"
  local destination="$2"
  "$chrome_path" \
    --headless=new \
    --disable-gpu \
    --no-sandbox \
    --hide-scrollbars \
    --window-size=1440,1100 \
    --screenshot="$destination" \
    "$url" >/dev/null 2>&1
}

capture \
  "https://github.com/rezmoss/sbomlyze-go-spdx-demo/pull/2" \
  "$work_path/pr.png"
capture \
  "https://github.com/rezmoss/sbomlyze-go-spdx-demo/pull/2/files" \
  "$work_path/files.png"
capture \
  "https://github.com/rezmoss/sbomlyze-go-spdx-demo/pull/2/checks" \
  "$work_path/checks.png"

card() {
  local destination="$1"
  local heading="$2"
  local line_one="$3"
  local line_two="$4"

  magick -size 1280x850 xc:'#0d1117' \
    -font "$font_bold" -fill '#f0f6fc' -pointsize 54 \
    -gravity northwest -annotate +70+160 "$heading" \
    -font "$font_regular" -fill '#8c959f' -pointsize 31 \
    -annotate +70+275 "$line_one" \
    -annotate +70+330 "$line_two" \
    -fill '#2f81f7' -draw 'roundrectangle 70,430 410,500 12,12' \
    -font "$font_bold" -fill white -pointsize 28 \
    -annotate +98+452 'SBOMlyze Diff' \
    "$destination"
}

caption() {
  local source="$1"
  local destination="$2"
  local heading="$3"
  local detail="$4"

  magick "$source" \
    -gravity north -crop 1440x956+0+0 +repage \
    -resize '1280x850!' \
    -fill '#0d1117e8' -draw 'rectangle 0,0 1280,92' \
    -font "$font_bold" -fill '#f0f6fc' -pointsize 31 \
    -gravity northwest -annotate +34+20 "$heading" \
    -font "$font_regular" -fill '#b1bac4' -pointsize 22 \
    -annotate +34+59 "$detail" \
    "$destination"
}

card "$work_path/01-intro.png" \
  'Same version. Different hash.' \
  'A real SPDX pull request changes one checksum.' \
  'Watch SBOMlyze turn silent drift into a review decision.'

caption "$work_path/pr.png" "$work_path/02-pr.png" \
  '1. A dependency PR claims no version change' \
  'Public demo: rezmoss/sbomlyze-go-spdx-demo#2'

caption "$work_path/files.png" "$work_path/03-files.png" \
  '2. The SPDX checksum changed anyway' \
  'The component identity and version remain the same.'

caption "$work_path/checks.png" "$work_path/04-checks.png" \
  '3. SBOM review blocks the pull request' \
  'The required sbom-diff check fails in 16 seconds.'

card "$work_path/05-result.png" \
  'VERDICT: FAIL' \
  'Integrity drift: 1  |  Policy: deny_integrity_drift' \
  'SARIF still uploads, so the finding stays reviewable.'

card "$work_path/06-cta.png" \
  'Do not merge unexplained bytes.' \
  'Review manifest intent, SBOM inventory, and integrity drift.' \
  'github.com/marketplace/actions/sbomlyze-diff'

magick \
  -delay 400 "$work_path/01-intro.png" \
  -delay 500 "$work_path/02-pr.png" \
  -delay 900 "$work_path/03-files.png" \
  -delay 700 "$work_path/04-checks.png" \
  -delay 800 "$work_path/05-result.png" \
  -delay 500 "$work_path/06-cta.png" \
  -loop 0 \
  -layers Optimize \
  "$output_path"

echo "Wrote $output_path (38-second loop)."
