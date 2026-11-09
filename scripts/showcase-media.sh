#!/usr/bin/env bash
# Screenshots and recordings for the site, from the showcase inputs.
# usage: scripts/showcase-media.sh INPUTS BIN OUT   (needs vhs, node, chrome)
set -euo pipefail
IN=$(cd "$1" && pwd) BIN=$(cd "$(dirname "$2")" && pwd)/$(basename "$2") OUT=$(mkdir -p "$3" && cd "$3" && pwd)
ROOT=$(cd "$(dirname "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"; [ -n "${WEB:-}" ] && kill "$WEB" 2>/dev/null || true' EXIT
mkdir -p "$WORK/bin" "$WORK/demo" && ln -s "$BIN" "$WORK/bin/sbomlyze"
# recordings run in demo/: only the files they name, short paths
for f in ggcr-checksum-db.syft.json ggcr-goprivate.syft.json nginx-1.28.0-dec.syft.json; do ln -s "$IN/$f" "$WORK/demo/$f"; done

# web UI with the December nginx SBOM loaded
port=18765
"$BIN" -web --port "$port" >/dev/null 2>&1 &
WEB=$!
for _ in $(seq 1 50); do curl -fs "http://127.0.0.1:$port/" >/dev/null && break; sleep 0.2; done
node "$ROOT/scripts/webui-shot.mjs" "http://127.0.0.1:$port/" "$IN/nginx-1.28.0-dec.syft.json" "$OUT/web-ui.png"

tape() { # name, then tape body on stdin
  { printf 'Output "%s/%s.gif"\nSet Shell bash\nSet FontSize 15\nSet Width 1280\nSet Height 720\nSet Padding 18\nSet Theme "Dracula"\nSet TypingSpeed 35ms\n' "$OUT" "$1"
    printf 'Hide\nType `unset CI GITHUB_ACTIONS; export PATH=%s/bin:$PATH PS1="$ "; cd %s; clear`\nEnter\nSleep 300ms\nShow\n' "$WORK" "$WORK/demo"
    cat; } > "$WORK/$1.tape"
  vhs "$WORK/$1.tape"
}

# Go re-tag caught by policy
printf '%s\n' '{"deny_integrity_drift": true}' > "$WORK/demo/policy.json"
tape retag-policy <<'TAPE'
Type "cat policy.json"
Enter
Sleep 1s
Type "sbomlyze ggcr-checksum-db.syft.json ggcr-goprivate.syft.json --policy policy.json --no-pager"
Sleep 400ms
Enter
Sleep 3s
Type "echo exit=$?"
Enter
Sleep 3.5s
TAPE

# terminal explorer on the December nginx SBOM
tape tui-explorer <<'TAPE'
Type "sbomlyze nginx-1.28.0-dec.syft.json -i"
Enter
Sleep 2s
Type "/"
Sleep 300ms
Type "openssl"
Sleep 600ms
Enter
Sleep 1s
Down 4
Sleep 500ms
Enter
Sleep 2.5s
Escape
Sleep 800ms
Type "t"
Sleep 1.5s
Escape
Sleep 500ms
Type "q"
Sleep 500ms
TAPE
ls -la "$OUT"
