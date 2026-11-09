#!/usr/bin/env bash
# Regenerate the showcase input SBOMs from pinned targets.
# usage: scripts/showcase-inputs.sh OUT   (needs syft $SYFT_VERSION, go, curl, gh, docker)
# Run rarely, into testdata/showcase; the site never rescans.
set -euo pipefail
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
SYFT_VERSION=1.56.0
export SYFT_CHECK_FOR_APP_UPDATE=false
# unused caches; keeps local home paths out of the published config
export SYFT_GOLANG_LOCAL_MOD_CACHE_DIR=/go/pkg/mod SYFT_JAVA_MAVEN_LOCAL_REPOSITORY_DIR=/root/.m2/repository
have=$(syft version 2>/dev/null | awk '/^Version:/{print $2}')
[ "$have" = "$SYFT_VERSION" ] || { echo "need syft $SYFT_VERSION, have ${have:-none}" >&2; exit 1; }
WORK=$(cd "$(mktemp -d)" && pwd -P) # physical path: syft resolves symlinks
trap 'rm -rf "$WORK"' EXIT

# name target: one SBOM per format
scan() {
  local name=$1 target=$2
  shift 2
  for f in syft-json:syft cyclonedx-json:cdx spdx-json:spdx; do
    syft scan "$target" "$@" -q -o "${f%%:*}=$OUT/$name.${f##*:}.json"
  done
}

# dir scan from inside the dir: root-relative paths, named source
dirscan() {
  local name=$1 dir=$2 src=$3 ver=$4
  (cd "$dir" && scan "$name" dir:. --source-name "$src" --source-version "$ver")
}

# images, pinned by linux/amd64 manifest digest
img() { scan "$1" "registry:index.docker.io/$2"; }
img nginx-1.28.0-apr     library/nginx@sha256:7c46bce526d9abd904d656b4afe3742be3fffd9bc2d361dc4ba68bcbc22ca301
img nginx-1.28.0-dec     library/nginx@sha256:3b03dfd827515a07ccf4946000f0bbdd2a4fb6aca7499249fcb6b1f9726823d6
img alpine-3.19.9        library/alpine@sha256:b58899f069c47216f6002a6850143dc6fae0d35eb8b0df9300bbe6327b9c2171
img alpine-3.20.10       library/alpine@sha256:c64c687cbea9300178b30c95835354e34c4e4febc4badfe27102879de0483b5e
img node-20.11.1-alpine  library/node@sha256:121edf6661770d20483818426b32042da33323b6fd30fc1ad4cd6890a817e240
img node-20.18.0-alpine  library/node@sha256:a1d39fe127e43881c6770abf2f0843c955607fb56eb9b45bf6f103c992c5442a
img zookeeper-3.8.3      library/zookeeper@sha256:34e7ff9583a84592fc28a0f19e2c2e55c444a6b22d1d6b3a65b0c167a40d464a
img zookeeper-3.9.2      library/zookeeper@sha256:7b775af48b8853b2c9868f438a065db9e1f86b15a4e00ce94898930ff24aad69
img syft-1.55.0          anchore/syft@sha256:b83763ae05df444f7f768655ce2ea6d7c2f8280d58f9bee221a69d2971d98883
img syft-1.57.0          anchore/syft@sha256:1fe67f9ac8c4c86cbc0075bda33b97a2a804500ee03d450a88721411e133068a

cd "$WORK"

# ripgrep source releases
for v in 14.0.3 14.1.1; do
  curl -fsSL "https://github.com/BurntSushi/ripgrep/archive/refs/tags/$v.tar.gz" | tar xz
  dirscan "ripgrep-$v" "ripgrep-$v" ripgrep "$v"
done

# akka-actor jars from Maven Central (license Apache-2.0 -> BUSL-1.1)
for v in 2.6.20 2.7.0; do
  mkdir "akka-$v"
  curl -fsSL -o "akka-$v/akka-actor_2.13-$v.jar" \
    "https://repo1.maven.org/maven2/com/typesafe/akka/akka-actor_2.13/$v/akka-actor_2.13-$v.jar"
  dirscan "akka-actor-$v" "akka-$v" akka-actor "$v"
done

# go-containerregistry v0.20.4, re-tagged upstream (google/go-containerregistry#2107)
for d in ggcr-checksum-db ggcr-goprivate; do
  mkdir "$d"
  printf 'module example.com/app\n\ngo 1.24\n\nrequire github.com/google/go-containerregistry v0.20.4\n' > "$d/go.mod"
  printf 'package main\n\nimport _ "github.com/google/go-containerregistry/pkg/name"\n\nfunc main() {}\n' > "$d/main.go"
done
export GOFLAGS=-modcacherw
# default: proxy.golang.org + sum.golang.org record the first v0.20.4
(cd ggcr-checksum-db && GOMODCACHE="$WORK/mc1" GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org go mod tidy)
# GOPRIVATE skips proxy and checksum DB: Go fetches the moved tag silently
(cd ggcr-goprivate && GOMODCACHE="$WORK/mc2" GOPRIVATE='github.com/google/*' go mod tidy)
# same app, same version: built twice
dirscan ggcr-checksum-db ggcr-checksum-db example.com/app v1.0.0
dirscan ggcr-goprivate ggcr-goprivate example.com/app v1.0.0

# evidence behind the page claims, published with the SBOMs
cp ripgrep-14.0.3/Cargo.lock "$OUT/evidence-ripgrep-14.0.3.Cargo.lock"
cp ripgrep-14.1.1/Cargo.lock "$OUT/evidence-ripgrep-14.1.1.Cargo.lock"
# what differs between the two v0.20.4 module contents
diff -r "$WORK/mc1/github.com/google/go-containerregistry@v0.20.4" "$WORK/mc2/github.com/google/go-containerregistry@v0.20.4" \
  | sed "s|$WORK/||g" > "$OUT/evidence-ggcr-v0.20.4-content.diff" || true
# installed packages and nginx -v, run inside each nginx image
for b in apr:7c46bce526d9abd904d656b4afe3742be3fffd9bc2d361dc4ba68bcbc22ca301 dec:3b03dfd827515a07ccf4946000f0bbdd2a4fb6aca7499249fcb6b1f9726823d6; do
  docker run --rm --platform linux/amd64 --entrypoint sh "nginx@sha256:${b#*:}" -c \
    'nginx -v 2>&1; echo "debian_version $(cat /etc/debian_version)"; dpkg-query -W -f "\${Package} \${Version}\n"' \
    > "$OUT/evidence-nginx-1.28.0-${b%%:*}.dpkg.txt"
done
# nginx:1.28.0 tag history: date, multi-platform digest, linux/amd64 digest
path=repos/nginx/remote/1.28.0.md
# date window: the full-history query times out on this repo
commits=$(gh api --paginate "repos/docker-library/repo-info/commits?path=$path&since=2025-04-01T00:00:00Z&until=2026-01-31T00:00:00Z&per_page=100" \
  --jq '.[] | .commit.committer.date + " " + .sha')
[ -n "$commits" ] || { echo "no repo-info history for $path" >&2; exit 1; }
printf '%s\n' "$commits" | sort | while read -r date sha; do
    md=$(curl -fsSL "https://raw.githubusercontent.com/docker-library/repo-info/$sha/$path" || true)
    idx=$(awk '/^## /{f=1} f&&/docker pull/{print $4; exit}' <<<"$md")
    amd=$(awk '/ - linux; amd64$/{f=1} f&&/docker pull/{print $4; exit}' <<<"$md")
    echo "$date $sha ${idx:-none} ${amd:-none}"
  done > "$OUT/evidence-nginx-1.28.0-tag-history.txt"

cd "$OUT"
rm -f SHA256SUMS
shasum -a 256 *.json evidence-* > SHA256SUMS
echo "wrote $(ls *.json | wc -l | tr -d ' ') SBOMs to $OUT"
