## 📦 SBOM Diff Report

### SBOM Comparison

| | Before | After |
|---|---|---|
| **File** | syft-before.cdx.json | syft-after.cdx.json |
| **File Size** | 268 KB | 268 KB |
| **Format** | CycloneDX 1.7 | CycloneDX 1.7 |
| **Generator** | syft 1.55.0 | syft 1.57.0 |
| **OS** | (none) | (none) |
| **Source** | anchore/syft | anchore/syft |
| **Total Components** | 369 | 369 |
| **PURL Coverage** | 97.6% | 97.6% |
| **License Coverage** | 0.0% | 0.0% |
| **Hash Coverage** | 1.9% | 1.9% |
| **CPE Coverage** | 94.6% | 94.6% |

### Key Findings

- 🔄 Scanned anchore/syft changed: v1.55.0 → v1.57.0
- 🔄 40 version upgrades (1 major, 17 minor, 20 patch, 2 prerelease) across 43 occurrences among 361 shared packages
- 📄 6 file entries changed content (not package integrity drift): /.github/actions/bootstrap/action.yaml, /.github/workflows/release.yaml, /.github/workflows/validate-github-actions.yaml, /.github/workflows/validations.yaml, /.make/go.mod + 1 more
- 🔄 golang: 342 packages before and after (39 version changes, 2 added/removed/moved)
- 🔄 github: 18 packages before and after (4 version changes)

<details>
<summary>➕ Added Packages by Type (1 total)</summary>

**golang** (1)

| Name | Version | Location |
|------|---------|----------|
| github.com/varlink/go | v0.4.1-0.20261015173642-c935be0c53f7 | /go.mod |

</details>

<details>
<summary>➖ Removed Packages by Type (1 total)</summary>

**golang** (1)

| Name | Version | Location |
|------|---------|----------|
| github.com/becheran/wildmatch-go | v1.0.0 | /go.mod |

</details>

### Summary

| Metric | Count |
|--------|-------|
| Added | 1 |
| Removed | 1 |
| Changed | 43 |
| File changes | 6 |

### Drift Summary

| Type | Count | Status |
|------|-------|--------|
| Version | 43 | ✅ |
| Integrity | 0 | ✅ |
| Metadata | 0 | ✅ |
| File entries (not package drift) | 6 | ℹ️ |

<details>
<summary>➕ Added Components (1)</summary>

| Name | Version |
|------|--------|
| github.com/varlink/go | v0.4.1-0.20261015173642-c935be0c53f7 |

</details>

<details>
<summary>➖ Removed Components (1)</summary>

| Name | Version |
|------|--------|
| github.com/becheran/wildmatch-go | v1.0.0 |

</details>

<details>
<summary>📄 File Changes (6, not package drift)</summary>

- `/.github/actions/bootstrap/action.yaml`
- `/.github/workflows/release.yaml`
- `/.github/workflows/validate-github-actions.yaml`
- `/.github/workflows/validations.yaml`
- `/.make/go.mod`
- `/go.mod`

</details>

<details>
<summary>🔄 Changed Components (43)</summary>

| Name | Before | After | Drift |
|------|--------|-------|-------|
| anchore/go-make/.github/actions/setup @ /.github/actions/bootstrap/action.yaml | v0.9.3 | v0.9.6 | 📦 Version |
| anchore/go-make/.github/actions/setup @ /.github/workflows/validations.yaml | v0.9.3 | v0.9.6 | 📦 Version |
| docker/login-action @ /.github/workflows/release.yaml | v4.6.0 | v4.7.0 | 📦 Version |
| zizmorcore/zizmor-action @ /.github/workflows/validate-github-actions.yaml | v0.6.4 | v0.8.0 | 📦 Version |
| github.com/Microsoft/go-winio @ /go.mod | v0.6.3-0.20251027160822-ad3df93bed29 | v0.6.3-0.20260930231756-f19d9717deb0 | 📦 Version |
| github.com/ProtonMail/go-crypto @ /go.mod | v1.4.1 | v1.5.2 | 📦 Version |
| github.com/anchore/clio @ /go.mod | v0.1.1 | v0.1.2 | 📦 Version |
| github.com/anchore/go-make @ /.make/go.mod | v0.9.3 | v0.9.6 | 📦 Version |
| github.com/anchore/stereoscope @ /go.mod | v0.3.4 | v0.4.1 | 📦 Version |
| github.com/bmatcuk/doublestar/v4 @ /.make/go.mod | v4.10.2 | v4.10.3 | 📦 Version |
| github.com/bmatcuk/doublestar/v4 @ /go.mod | v4.10.2 | v4.10.3 | 📦 Version |
| github.com/containerd/containerd/v2 @ /go.mod | v2.4.1 | v2.4.2 | 📦 Version |
| github.com/containerd/stargz-snapshotter/estargz @ /go.mod | v0.18.2 | v0.19.0 | 📦 Version |
| github.com/deitch/magic @ /go.mod | v0.0.0-20230404182410-1ff89d7342da | v1.0.0 | 📦 Version |
| github.com/docker/cli @ /go.mod | v29.8.2+incompatible | v29.9.2+incompatible | 📦 Version |
| github.com/docker/docker-credential-helpers @ /go.mod | v0.9.8 | v0.9.10 | 📦 Version |
| github.com/docker/go-connections @ /go.mod | v0.8.1 | v0.8.2 | 📦 Version |
| github.com/gabriel-vasile/mimetype @ /go.mod | v1.4.15 | v1.4.16 | 📦 Version |
| github.com/github/go-spdx/v2 @ /go.mod | v2.7.1 | v2.8.0 | 📦 Version |
| github.com/gkampitakis/go-snaps @ /go.mod | v0.5.23 | v0.5.24 | 📦 Version |
| github.com/go-jose/go-jose/v4 @ /go.mod | v4.1.5 | v4.1.6 | 📦 Version |
| github.com/go-test/deep @ /go.mod | v1.1.1 | v1.1.2 | 📦 Version |
| github.com/google/pprof @ /go.mod | v0.0.0-20260802141513-ef3492d7dac3 | v0.0.0-20261016150608-1facf8f91b50 | 📦 Version |
| github.com/gookit/color @ /go.mod | v1.6.2 | v1.6.3 | 📦 Version |
| github.com/gpustack/gguf-parser-go @ /go.mod | v0.26.4 | v0.27.0 | 📦 Version |
| github.com/klauspost/compress @ /go.mod | v1.20.1 | v1.20.3 | 📦 Version |
| github.com/klauspost/pgzip @ /go.mod | v1.2.6 | v1.2.7 | 📦 Version |
| github.com/mattn/go-runewidth @ /go.mod | v0.0.27 | v0.0.31 | 📦 Version |
| github.com/mattn/go-sqlite3 @ /go.mod | v1.14.48 | v1.14.52 | 📦 Version |
| github.com/moby/moby/api @ /go.mod | v1.56.0 | v1.56.1 | 📦 Version |
| github.com/moby/moby/client @ /go.mod | v0.6.0 | v0.6.2 | 📦 Version |
| github.com/ncruces/go-strftime @ /go.mod | v1.0.0 | v1.1.0 | 📦 Version |
| github.com/sigstore/fulcio @ /go.mod | v1.8.7 | v1.8.8 | 📦 Version |
| github.com/vbauerster/cupwriter @ /go.mod | v0.0.4 | v0.0.5 | 📦 Version |
| github.com/vbauerster/mpb/v8 @ /go.mod | v8.14.0 | v8.16.2 | 📦 Version |
| go.podman.io/image/v5 @ /go.mod | v5.41.2 | v5.42.0 | 📦 Version |
| go.podman.io/storage @ /go.mod | v1.64.1 | v1.65.0 | 📦 Version |
| golang.org/x/mod @ /.make/go.mod | v0.41.0 | v0.42.0 | 📦 Version |
| golang.org/x/mod @ /go.mod | v0.41.0 | v0.42.0 | 📦 Version |
| golang.org/x/sys @ /.make/go.mod | v0.48.0 | v0.49.0 | 📦 Version |
| golang.org/x/tools @ /go.mod | v0.51.0 | v0.52.0 | 📦 Version |
| modernc.org/libc @ /go.mod | v1.77.1 | v1.79.0 | 📦 Version |
| modernc.org/sqlite @ /go.mod | v1.60.1 | v1.61.0 | 📦 Version |

</details>

---
*Generated by [sbomlyze](https://github.com/rezmoss/sbomlyze) at 2026-11-08T23:58:59Z*

