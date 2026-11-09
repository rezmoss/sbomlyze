## 📦 SBOM Diff Report

### SBOM Comparison

| | Before | After |
|---|---|---|
| **File** | ripgrep-14.0.3.syft.json | ripgrep-14.1.1.syft.json |
| **File Size** | 99 KB | 103 KB |
| **Format** | Syft JSON 16.1.12 | Syft JSON 16.1.12 |
| **Generator** | syft 1.56.0 | syft 1.56.0 |
| **OS** | (none) | (none) |
| **Source** | ripgrep | ripgrep |
| **Total Components** | 63 | 65 |
| **PURL Coverage** | 84.1% | 84.6% |
| **License Coverage** | 0.0% | 0.0% |
| **Hash Coverage** | 0.0% | 0.0% |
| **CPE Coverage** | 100.0% | 100.0% |

### Scan Context

| | Before | After |
|---|---|---|
| **Schema** | 16.1.12 | 16.1.12 |
| **Scan Scope** | squashed | squashed |

### Key Findings

- 🔄 Scanned ripgrep changed: 14.0.3 → 14.1.1
- 📈 Inventory: +2 components (3.2%), +2 relationships (3.2%)
- 🔄 41 version upgrades (5 minor, 36 patch) among 54 shared packages
- 📄 3 file entries changed content (not package integrity drift): /.github/workflows/ci.yml, /.github/workflows/release.yml, /Cargo.lock

<details>
<summary>➕ Added Packages by Type (11 total)</summary>

**cargo** (11)

| Name | Version | Location |
|------|---------|----------|
| shlex | 1.3.0 | /Cargo.lock |
| windows-sys | 0.59.0 | /Cargo.lock |
| windows-targets | 0.52.6 | /Cargo.lock |
| windows_aarch64_gnullvm | 0.52.6 | /Cargo.lock |
| windows_aarch64_msvc | 0.52.6 | /Cargo.lock |

*...and 6 more*


</details>

<details>
<summary>➖ Removed Packages by Type (9 total)</summary>

**cargo** (9)

| Name | Version | Location |
|------|---------|----------|
| autocfg | 1.1.0 | /Cargo.lock |
| libm | 0.2.8 | /Cargo.lock |
| memoffset | 0.9.0 | /Cargo.lock |
| num-traits | 0.2.17 | /Cargo.lock |
| packed_simd | 0.3.9 | /Cargo.lock |

*...and 4 more*


</details>

### Summary

| Metric | Count |
|--------|-------|
| Added | 11 |
| Removed | 9 |
| Changed | 41 |
| File changes | 3 |

### Drift Summary

| Type | Count | Status |
|------|-------|--------|
| Version | 41 | ✅ |
| Integrity | 0 | ✅ |
| Metadata | 0 | ✅ |
| File entries (not package drift) | 3 | ℹ️ |

### New Dependencies by Depth

| Depth | Count | Risk |
|-------|-------|------|
| 1 (direct) | 0 | Low |
| 2 | 0 | Medium |
| 3+ | 11 | ⚠️ **High** |

<details>
<summary>➕ Added Components (11)</summary>

| Name | Version |
|------|--------|
| shlex | 1.3.0 |
| windows-sys | 0.59.0 |
| windows-targets | 0.52.6 |
| windows_aarch64_gnullvm | 0.52.6 |
| windows_aarch64_msvc | 0.52.6 |
| windows_i686_gnu | 0.52.6 |
| windows_i686_gnullvm | 0.52.6 |
| windows_i686_msvc | 0.52.6 |
| windows_x86_64_gnu | 0.52.6 |
| windows_x86_64_gnullvm | 0.52.6 |
| windows_x86_64_msvc | 0.52.6 |

</details>

<details>
<summary>➖ Removed Components (9)</summary>

| Name | Version |
|------|--------|
| autocfg | 1.1.0 |
| libm | 0.2.8 |
| memoffset | 0.9.0 |
| num-traits | 0.2.17 |
| packed_simd | 0.3.9 |
| scopeguard | 1.2.0 |
| winapi | 0.3.9 |
| winapi-i686-pc-windows-gnu | 0.4.0 |
| winapi-x86_64-pc-windows-gnu | 0.4.0 |

</details>

<details>
<summary>📄 File Changes (3, not package drift)</summary>

- `/.github/workflows/ci.yml`
- `/.github/workflows/release.yml`
- `/Cargo.lock`

</details>

<details>
<summary>🔄 Changed Components (41)</summary>

| Name | Before | After | Drift |
|------|--------|-------|-------|
| globset @ /Cargo.lock | 0.4.14 | 0.4.15 | 📦 Version |
| grep-cli @ /Cargo.lock | 0.1.10 | 0.1.11 | 📦 Version |
| grep-pcre2 @ /Cargo.lock | 0.1.7 | 0.1.8 | 📦 Version |
| grep-printer @ /Cargo.lock | 0.2.1 | 0.2.2 | 📦 Version |
| grep-regex @ /Cargo.lock | 0.1.12 | 0.1.13 | 📦 Version |
| grep-searcher @ /Cargo.lock | 0.1.13 | 0.1.14 | 📦 Version |
| grep @ /Cargo.lock | 0.3.1 | 0.3.2 | 📦 Version |
| ignore @ /Cargo.lock | 0.4.21 | 0.4.23 | 📦 Version |
| ripgrep @ /Cargo.lock | 14.0.3 | 14.1.1 | 📦 Version |
| aho-corasick @ /Cargo.lock | 1.1.2 | 1.1.3 | 📦 Version |
| anyhow @ /Cargo.lock | 1.0.75 | 1.0.87 | 📦 Version |
| bstr @ /Cargo.lock | 1.8.0 | 1.10.0 | 📦 Version |
| cc @ /Cargo.lock | 1.0.83 | 1.1.18 | 📦 Version |
| crossbeam-channel @ /Cargo.lock | 0.5.8 | 0.5.13 | 📦 Version |
| crossbeam-deque @ /Cargo.lock | 0.8.3 | 0.8.5 | 📦 Version |
| crossbeam-epoch @ /Cargo.lock | 0.9.15 | 0.9.18 | 📦 Version |
| crossbeam-utils @ /Cargo.lock | 0.8.16 | 0.8.20 | 📦 Version |
| encoding_rs @ /Cargo.lock | 0.8.33 | 0.8.34 | 📦 Version |
| itoa @ /Cargo.lock | 1.0.9 | 1.0.11 | 📦 Version |
| jobserver @ /Cargo.lock | 0.1.27 | 0.1.32 | 📦 Version |
| libc @ /Cargo.lock | 0.2.150 | 0.2.158 | 📦 Version |
| log @ /Cargo.lock | 0.4.20 | 0.4.22 | 📦 Version |
| memchr @ /Cargo.lock | 2.6.4 | 2.7.4 | 📦 Version |
| memmap2 @ /Cargo.lock | 0.9.0 | 0.9.4 | 📦 Version |
| pcre2 @ /Cargo.lock | 0.2.6 | 0.2.9 | 📦 Version |
| pcre2-sys @ /Cargo.lock | 0.2.7 | 0.2.9 | 📦 Version |
| pkg-config @ /Cargo.lock | 0.3.27 | 0.3.30 | 📦 Version |
| proc-macro2 @ /Cargo.lock | 1.0.70 | 1.0.86 | 📦 Version |
| quote @ /Cargo.lock | 1.0.33 | 1.0.37 | 📦 Version |
| regex @ /Cargo.lock | 1.10.2 | 1.10.6 | 📦 Version |
| regex-automata @ /Cargo.lock | 0.4.3 | 0.4.7 | 📦 Version |
| regex-syntax @ /Cargo.lock | 0.8.2 | 0.8.4 | 📦 Version |
| ryu @ /Cargo.lock | 1.0.15 | 1.0.18 | 📦 Version |
| serde @ /Cargo.lock | 1.0.193 | 1.0.210 | 📦 Version |
| serde_derive @ /Cargo.lock | 1.0.193 | 1.0.210 | 📦 Version |
| serde_json @ /Cargo.lock | 1.0.108 | 1.0.128 | 📦 Version |
| syn @ /Cargo.lock | 2.0.39 | 2.0.77 | 📦 Version |
| termcolor @ /Cargo.lock | 1.4.0 | 1.4.1 | 📦 Version |
| textwrap @ /Cargo.lock | 0.16.0 | 0.16.1 | 📦 Version |
| walkdir @ /Cargo.lock | 2.4.0 | 2.5.0 | 📦 Version |
| winapi-util @ /Cargo.lock | 0.1.6 | 0.1.9 | 📦 Version |

</details>

---
*Generated by [sbomlyze](https://github.com/rezmoss/sbomlyze) at 2026-11-09T02:06:36Z*

