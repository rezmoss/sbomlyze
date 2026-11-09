## 📦 SBOM Diff Report

### SBOM Comparison

| | Before | After |
|---|---|---|
| **File** | node-20.11.1-alpine.syft.json | node-20.18.0-alpine.syft.json |
| **File Size** | 695 KB | 606 KB |
| **Format** | Syft JSON 16.1.12 | Syft JSON 16.1.12 |
| **Generator** | syft 1.56.0 | syft 1.56.0 |
| **OS** | Alpine Linux v3.19 3.19.1 | Alpine Linux v3.20 3.20.3 |
| **Source** | index.docker.io/library/node | index.docker.io/library/node |
| **Total Components** | 257 | 221 |
| **PURL Coverage** | 100.0% | 100.0% |
| **License Coverage** | 99.6% | 99.5% |
| **Hash Coverage** | 0.0% | 0.0% |
| **CPE Coverage** | 100.0% | 100.0% |

### Scan Context

| | Before | After |
|---|---|---|
| **Schema** | 16.1.12 | 16.1.12 |
| **Scan Scope** | squashed | squashed |

### Key Findings

- 🔄 Scanned index.docker.io/library/node changed: sha256:121edf6661770d20483818426b32042da33323b6fd30fc1ad4cd6890a817e240 → sha256:a1d39fe127e43881c6770abf2f0843c955607fb56eb9b45bf6f103c992c5442a
- 📉 Inventory: -36 components (-14.0%), -38 files (-11.8%), -39 relationships (-11.5%)
- 💻 OS changed: Alpine Linux v3.19 3.19.1 → Alpine Linux v3.20 3.20.3
- 🚨 2 version downgrades detected: ansi-regex 6.0.1→5.0.1, strip-ansi 7.1.0→6.0.1
- 🔄 99 version upgrades (14 major, 35 minor, 46 patch, 4 revision) among 206 shared packages
- 🙈 Integrity drift checked only 0 of 105 same-version packages; the rest carry no comparable digest
- 📄 114 file entries changed content: 26 in packages that changed version, 1 in same-version packages, 87 not owned by any package: /lib/apk/db/installed, /usr/local/bin/node, /usr/local/lib/node_modules/corepack/package.json, /usr/local/lib/node_modules/npm/node_modules/@npmcli/agent/package.json, /usr/local/lib/node_modules/npm/node_modules/@npmcli/arborist/package.json + 82 more
- ⚠️ 1 packages changed owned files without a version change: scanelf 1.3.7-r2 (modified /usr/bin/scanelf) — base OS changed (Alpine Linux v3.19 3.19.1 → Alpine Linux v3.20 3.20.3), so same-version rebuilds are expected
- ℹ️ 1 version changes where every hashed owned file is byte-identical: alpine-baselayout 3.4.3-r2→3.6.5-r0 (10 files)
- 📁 98.0% of removed packages are npm, concentrated in /usr/local/lib
- 📁 Top removal areas: /usr/local/lib (50), /lib/apk/db (1)
- 📜 License shift: permissive -37

<details>
<summary>➕ Added Packages by Type (15 total)</summary>

**npm** (15)

| Name | Version | Location |
|------|---------|----------|
| @npmcli/redact | 2.0.1 | /usr/local/lib/node_modules/npm/node_modules/@npmcli/redact/package.json |
| @sigstore/core | 1.1.0 | /usr/local/lib/node_modules/npm/node_modules/@sigstore/core/package.json |
| @sigstore/verify | 1.2.1 | /usr/local/lib/node_modules/npm/node_modules/@sigstore/verify/package.json |
| ansi-regex | 6.0.1 | /usr/local/lib/node_modules/npm/node_modules/@isaacs/cliui/node_modules/ansi-regex/package.json |
| ansi-regex | 6.0.1 | /usr/local/lib/node_modules/npm/node_modules/wrap-ansi/node_modules/ansi-regex/package.json |

*...and 10 more*


</details>

<details>
<summary>➖ Removed Packages by Type (51 total)</summary>

**npm** (50)

| Name | Version | Location |
|------|---------|----------|
| @colors/colors | 1.5.0 | /usr/local/lib/node_modules/npm/node_modules/@colors/colors/package.json |
| @npmcli/disparity-colors | 3.0.0 | /usr/local/lib/node_modules/npm/node_modules/@npmcli/disparity-colors/package.json |
| abort-controller | 3.0.0 | /usr/local/lib/node_modules/npm/node_modules/abort-controller/package.json |
| ansi-regex | 5.0.1 | /usr/local/lib/node_modules/npm/node_modules/cli-columns/node_modules/ansi-regex/package.json |
| ansi-regex | 5.0.1 | /usr/local/lib/node_modules/npm/node_modules/columnify/node_modules/ansi-regex/package.json |

*...and 45 more*

**apk** (1)

| Name | Version | Location |
|------|---------|----------|
| libc-utils | 0.7.2-r5 | /lib/apk/db/installed |

</details>

### Summary

| Metric | Count |
|--------|-------|
| Added | 15 |
| Removed | 51 |
| Changed | 101 |
| File changes | 114 |
| Owned file drift | 1 |

### Drift Summary

| Type | Count | Status |
|------|-------|--------|
| Version | 101 | ✅ |
| Integrity | 0 | ✅ |
| Metadata | 0 | ✅ |
| File entries (not package drift) | 114 | ℹ️ |
| Owned file drift | 1 | ⚠️ **Review Required** |

<details>
<summary>➕ Added Components (15)</summary>

| Name | Version |
|------|--------|
| @npmcli/redact | 2.0.1 |
| @sigstore/core | 1.1.0 |
| @sigstore/verify | 1.2.1 |
| ansi-regex | 6.0.1 |
| ansi-regex | 6.0.1 |
| ip-address | 9.0.5 |
| jsbn | 1.1.0 |
| package-json-from-dist | 1.0.0 |
| proc-log | 3.0.0 |
| proggy | 2.0.0 |
| spdx-expression-parse | 3.0.1 |
| spdx-expression-parse | 3.0.1 |
| sprintf-js | 1.1.3 |
| strip-ansi | 7.1.0 |
| strip-ansi | 7.1.0 |

</details>

<details>
<summary>➖ Removed Components (51)</summary>

| Name | Version |
|------|--------|
| libc-utils | 0.7.2-r5 |
| @colors/colors | 1.5.0 |
| @npmcli/disparity-colors | 3.0.0 |
| abort-controller | 3.0.0 |
| ansi-regex | 5.0.1 |
| ansi-regex | 5.0.1 |
| ansi-regex | 5.0.1 |
| ansi-regex | 5.0.1 |
| ansi-regex | 5.0.1 |
| ansi-regex | 5.0.1 |
| ansi-regex | 5.0.1 |
| ansi-styles | 4.3.0 |
| are-we-there-yet | 4.0.1 |
| base64-js | 1.5.1 |
| buffer | 6.0.3 |
| builtins | 5.0.1 |
| cli-table3 | 0.6.3 |
| clone | 1.0.4 |
| color-support | 1.1.3 |
| columnify | 1.6.0 |
| console-control-strings | 1.1.0 |
| defaults | 1.0.4 |
| delegates | 1.0.0 |
| event-target-shim | 5.0.1 |
| events | 3.3.0 |
| function-bind | 1.1.2 |
| gauge | 5.0.1 |
| has-unicode | 2.0.1 |
| hasown | 2.0.0 |
| ieee754 | 1.2.1 |
| ip | 2.0.0 |
| is-core-module | 2.13.1 |
| lru-cache | 6.0.0 |
| minipass | 3.3.6 |
| minipass | 3.3.6 |
| minipass-json-stream | 1.0.1 |
| npmlog | 7.0.1 |
| process | 0.11.10 |
| read-package-json | 7.0.0 |
| readable-stream | 4.4.2 |
| safe-buffer | 5.2.1 |
| set-blocking | 2.0.0 |
| string_decoder | 1.3.0 |
| strip-ansi | 6.0.1 |
| strip-ansi | 6.0.1 |
| strip-ansi | 6.0.1 |
| strip-ansi | 6.0.1 |
| strip-ansi | 6.0.1 |
| strip-ansi | 6.0.1 |
| wcwidth | 1.0.1 |
| wide-align | 1.1.5 |

</details>

<details open>
<summary>⚠️ Owned File Drift (1 packages, same version, files changed)</summary>

| Package | Version | File | Change | Config |
|---------|---------|------|--------|--------|
| scanelf | 1.3.7-r2 | `/usr/bin/scanelf` | modified | unknown |

</details>

<details>
<summary>📄 File Changes (114, not package drift)</summary>

- `/bin/busybox`
- `/etc/group`
- `/etc/inittab`
- `/etc/network/if-up.d/dad`
- `/etc/passwd`
- `/etc/shadow`
- `/etc/ssl/certs/ca-certificates.crt`
- `/etc/ssl/openssl.cnf`
- `/etc/ssl/openssl.cnf.dist`
- `/lib/apk/db/installed`
- `/lib/ld-musl-x86_64.so.1`
- `/lib/libapk.so.2.14.0`
- `/lib/libcrypto.so.3`
- `/lib/libssl.so.3`
- `/lib/libz.so.1.3.1`
- `/sbin/apk`
- `/usr/bin/getconf`
- `/usr/bin/getent`
- `/usr/bin/iconv`
- `/usr/bin/scanelf`
- `/usr/bin/ssl_client`
- `/usr/lib/engines-3/afalg.so`
- `/usr/lib/engines-3/capi.so`
- `/usr/lib/engines-3/loader_attic.so`
- `/usr/lib/engines-3/padlock.so`
- `/usr/lib/libgcc_s.so.1`
- `/usr/lib/libstdc++.so.6.0.32`
- `/usr/lib/ossl-modules/legacy.so`
- `/usr/local/bin/node`
- `/usr/local/lib/node_modules/corepack/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@npmcli/agent/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@npmcli/arborist/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@npmcli/config/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@npmcli/fs/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@npmcli/git/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@npmcli/installed-package-contents/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@npmcli/map-workspaces/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@npmcli/metavuln-calculator/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@npmcli/package-json/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@npmcli/promise-spawn/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@npmcli/query/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@npmcli/run-script/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@sigstore/bundle/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@sigstore/protobuf-specs/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@sigstore/sign/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@sigstore/tuf/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/@tufjs/models/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/agent-base/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/ansi-regex/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/bin-links/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/binary-extensions/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/cacache/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/cidr-regex/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/cmd-shim/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/debug/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/diff/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/foreground-child/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/glob/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/hosted-git-info/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/http-proxy-agent/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/https-proxy-agent/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/ignore-walk/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/ini/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/init-package-json/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/is-cidr/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/jackspeak/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/json-parse-even-better-errors/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/libnpmaccess/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/libnpmdiff/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/libnpmexec/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/libnpmfund/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/libnpmhook/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/libnpmorg/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/libnpmpack/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/libnpmpublish/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/libnpmsearch/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/libnpmteam/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/libnpmversion/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/lru-cache/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/make-fetch-happen/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/minimatch/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/minipass-collect/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/minipass-fetch/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/minipass/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/node-gyp/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/nopt/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/normalize-package-data/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/npm-bundled/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/npm-package-arg/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/npm-packlist/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/npm-pick-manifest/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/npm-profile/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/npm-registry-fetch/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/npm-user-validate/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/pacote/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/path-scurry/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/postcss-selector-parser/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/proc-log/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/promise-call-limit/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/promzard/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/read/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/semver/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/sigstore/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/socks-proxy-agent/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/socks/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/spdx-exceptions/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/spdx-expression-parse/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/spdx-license-ids/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/ssri/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/strip-ansi/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/tar/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/tuf-js/package.json`
- `/usr/local/lib/node_modules/npm/node_modules/validate-npm-package-name/package.json`
- `/usr/local/lib/node_modules/npm/package.json`

</details>

<details>
<summary>🔄 Changed Components (101)</summary>

| Name | Before | After | Drift |
|------|--------|-------|-------|
| alpine-baselayout @ /lib/apk/db/installed | 3.4.3-r2 | 3.6.5-r0 | 📦 Version |
| alpine-baselayout-data @ /lib/apk/db/installed | 3.4.3-r2 | 3.6.5-r0 | 📦 Version |
| apk-tools @ /lib/apk/db/installed | 2.14.0-r5 | 2.14.4-r0 | 📦 Version |
| busybox @ /lib/apk/db/installed | 1.36.1-r15 | 1.36.1-r29 | 📦 Version |
| busybox-binsh @ /lib/apk/db/installed | 1.36.1-r15 | 1.36.1-r29 | 📦 Version |
| ca-certificates-bundle @ /lib/apk/db/installed | 20230506-r0 | 20240705-r0 | 📦 Version |
| libcrypto3 @ /lib/apk/db/installed | 3.1.4-r5 | 3.3.2-r0 | 📦 Version |
| libgcc @ /lib/apk/db/installed | 13.2.1_git20231014-r0 | 13.2.1_git20240309-r0 | 📦 Version |
| libssl3 @ /lib/apk/db/installed | 3.1.4-r5 | 3.3.2-r0 | 📦 Version |
| libstdc++ @ /lib/apk/db/installed | 13.2.1_git20231014-r0 | 13.2.1_git20240309-r0 | 📦 Version |
| musl @ /lib/apk/db/installed | 1.2.4_git20230717-r4 | 1.2.5-r0 | 📦 Version |
| musl-utils @ /lib/apk/db/installed | 1.2.4_git20230717-r4 | 1.2.5-r0 | 📦 Version |
| ssl_client @ /lib/apk/db/installed | 1.36.1-r15 | 1.36.1-r29 | 📦 Version |
| zlib @ /lib/apk/db/installed | 1.3.1-r0 | 1.3.1-r1 | 📦 Version |
| node @ /usr/local/bin/node | 20.11.1 | 20.18.0 | 📦 Version |
| @npmcli/agent @ /usr/local/lib/node_modules/npm/node_modules/@npmcli/agent/package.json | 2.2.0 | 2.2.2 | 📦 Version |
| @npmcli/arborist @ /usr/local/lib/node_modules/npm/node_modules/@npmcli/arborist/package.json | 7.2.1 | 7.5.4 | 📦 Version |
| @npmcli/config @ /usr/local/lib/node_modules/npm/node_modules/@npmcli/config/package.json | 8.0.2 | 8.3.4 | 📦 Version |
| @npmcli/fs @ /usr/local/lib/node_modules/npm/node_modules/@npmcli/fs/package.json | 3.1.0 | 3.1.1 | 📦 Version |
| @npmcli/git @ /usr/local/lib/node_modules/npm/node_modules/@npmcli/git/package.json | 5.0.3 | 5.0.8 | 📦 Version |
| @npmcli/installed-package-contents @ /usr/local/lib/node_modules/npm/node_modules/@npmcli/installed-package-contents/package.json | 2.0.2 | 2.1.0 | 📦 Version |
| @npmcli/map-workspaces @ /usr/local/lib/node_modules/npm/node_modules/@npmcli/map-workspaces/package.json | 3.0.4 | 3.0.6 | 📦 Version |
| @npmcli/metavuln-calculator @ /usr/local/lib/node_modules/npm/node_modules/@npmcli/metavuln-calculator/package.json | 7.0.0 | 7.1.1 | 📦 Version |
| @npmcli/package-json @ /usr/local/lib/node_modules/npm/node_modules/@npmcli/package-json/package.json | 5.0.0 | 5.2.0 | 📦 Version |
| @npmcli/promise-spawn @ /usr/local/lib/node_modules/npm/node_modules/@npmcli/promise-spawn/package.json | 7.0.0 | 7.0.2 | 📦 Version |
| @npmcli/query @ /usr/local/lib/node_modules/npm/node_modules/@npmcli/query/package.json | 3.0.1 | 3.1.0 | 📦 Version |
| @npmcli/run-script @ /usr/local/lib/node_modules/npm/node_modules/@npmcli/run-script/package.json | 7.0.2 | 8.1.0 | 📦 Version |
| @sigstore/bundle @ /usr/local/lib/node_modules/npm/node_modules/@sigstore/bundle/package.json | 2.1.0 | 2.3.2 | 📦 Version |
| @sigstore/protobuf-specs @ /usr/local/lib/node_modules/npm/node_modules/@sigstore/protobuf-specs/package.json | 0.2.1 | 0.3.2 | 📦 Version |
| @sigstore/sign @ /usr/local/lib/node_modules/npm/node_modules/@sigstore/sign/package.json | 2.2.0 | 2.3.2 | 📦 Version |
| @sigstore/tuf @ /usr/local/lib/node_modules/npm/node_modules/@sigstore/tuf/package.json | 2.2.0 | 2.3.4 | 📦 Version |
| @tufjs/models @ /usr/local/lib/node_modules/npm/node_modules/@tufjs/models/package.json | 2.0.0 | 2.0.1 | 📦 Version |
| agent-base @ /usr/local/lib/node_modules/npm/node_modules/agent-base/package.json | 7.1.0 | 7.1.1 | 📦 Version |
| ansi-regex @ /usr/local/lib/node_modules/npm/node_modules/ansi-regex/package.json | 6.0.1 | 5.0.1 | 📦 Version |
| bin-links @ /usr/local/lib/node_modules/npm/node_modules/bin-links/package.json | 4.0.3 | 4.0.4 | 📦 Version |
| binary-extensions @ /usr/local/lib/node_modules/npm/node_modules/binary-extensions/package.json | 2.2.0 | 2.3.0 | 📦 Version |
| cacache @ /usr/local/lib/node_modules/npm/node_modules/cacache/package.json | 18.0.0 | 18.0.3 | 📦 Version |
| cidr-regex @ /usr/local/lib/node_modules/npm/node_modules/cidr-regex/package.json | 4.0.3 | 4.1.1 | 📦 Version |
| cmd-shim @ /usr/local/lib/node_modules/npm/node_modules/cmd-shim/package.json | 6.0.2 | 6.0.3 | 📦 Version |
| corepack @ /usr/local/lib/node_modules/corepack/package.json | 0.23.0 | 0.29.3 | 📦 Version |
| debug @ /usr/local/lib/node_modules/npm/node_modules/debug/package.json | 4.3.4 | 4.3.5 | 📦 Version |
| diff @ /usr/local/lib/node_modules/npm/node_modules/diff/package.json | 5.1.0 | 5.2.0 | 📦 Version |
| foreground-child @ /usr/local/lib/node_modules/npm/node_modules/foreground-child/package.json | 3.1.1 | 3.2.1 | 📦 Version |
| glob @ /usr/local/lib/node_modules/npm/node_modules/glob/package.json | 10.3.10 | 10.4.2 | 📦 Version |
| hosted-git-info @ /usr/local/lib/node_modules/npm/node_modules/hosted-git-info/package.json | 7.0.1 | 7.0.2 | 📦 Version |
| http-proxy-agent @ /usr/local/lib/node_modules/npm/node_modules/http-proxy-agent/package.json | 7.0.0 | 7.0.2 | 📦 Version |
| https-proxy-agent @ /usr/local/lib/node_modules/npm/node_modules/https-proxy-agent/package.json | 7.0.2 | 7.0.5 | 📦 Version |
| ignore-walk @ /usr/local/lib/node_modules/npm/node_modules/ignore-walk/package.json | 6.0.3 | 6.0.5 | 📦 Version |
| ini @ /usr/local/lib/node_modules/npm/node_modules/ini/package.json | 4.1.1 | 4.1.3 | 📦 Version |
| init-package-json @ /usr/local/lib/node_modules/npm/node_modules/init-package-json/package.json | 6.0.0 | 6.0.3 | 📦 Version |
| is-cidr @ /usr/local/lib/node_modules/npm/node_modules/is-cidr/package.json | 5.0.3 | 5.1.0 | 📦 Version |
| jackspeak @ /usr/local/lib/node_modules/npm/node_modules/jackspeak/package.json | 2.3.6 | 3.4.0 | 📦 Version |
| json-parse-even-better-errors @ /usr/local/lib/node_modules/npm/node_modules/json-parse-even-better-errors/package.json | 3.0.0 | 3.0.2 | 📦 Version |
| libnpmaccess @ /usr/local/lib/node_modules/npm/node_modules/libnpmaccess/package.json | 8.0.1 | 8.0.6 | 📦 Version |
| libnpmdiff @ /usr/local/lib/node_modules/npm/node_modules/libnpmdiff/package.json | 6.0.3 | 6.1.4 | 📦 Version |
| libnpmexec @ /usr/local/lib/node_modules/npm/node_modules/libnpmexec/package.json | 7.0.4 | 8.1.3 | 📦 Version |
| libnpmfund @ /usr/local/lib/node_modules/npm/node_modules/libnpmfund/package.json | 5.0.1 | 5.0.12 | 📦 Version |
| libnpmhook @ /usr/local/lib/node_modules/npm/node_modules/libnpmhook/package.json | 10.0.0 | 10.0.5 | 📦 Version |
| libnpmorg @ /usr/local/lib/node_modules/npm/node_modules/libnpmorg/package.json | 6.0.1 | 6.0.6 | 📦 Version |
| libnpmpack @ /usr/local/lib/node_modules/npm/node_modules/libnpmpack/package.json | 6.0.3 | 7.0.4 | 📦 Version |
| libnpmpublish @ /usr/local/lib/node_modules/npm/node_modules/libnpmpublish/package.json | 9.0.2 | 9.0.9 | 📦 Version |
| libnpmsearch @ /usr/local/lib/node_modules/npm/node_modules/libnpmsearch/package.json | 7.0.0 | 7.0.6 | 📦 Version |
| libnpmteam @ /usr/local/lib/node_modules/npm/node_modules/libnpmteam/package.json | 6.0.0 | 6.0.5 | 📦 Version |
| libnpmversion @ /usr/local/lib/node_modules/npm/node_modules/libnpmversion/package.json | 5.0.1 | 6.0.3 | 📦 Version |
| lru-cache @ /usr/local/lib/node_modules/npm/node_modules/lru-cache/package.json | 10.0.2 | 10.2.2 | 📦 Version |
| make-fetch-happen @ /usr/local/lib/node_modules/npm/node_modules/make-fetch-happen/package.json | 13.0.0 | 13.0.1 | 📦 Version |
| minimatch @ /usr/local/lib/node_modules/npm/node_modules/minimatch/package.json | 9.0.3 | 9.0.5 | 📦 Version |
| minipass @ /usr/local/lib/node_modules/npm/node_modules/minipass/package.json | 7.0.4 | 7.1.2 | 📦 Version |
| minipass-collect @ /usr/local/lib/node_modules/npm/node_modules/minipass-collect/package.json | 1.0.2 | 2.0.1 | 📦 Version |
| minipass-fetch @ /usr/local/lib/node_modules/npm/node_modules/minipass-fetch/package.json | 3.0.4 | 3.0.5 | 📦 Version |
| node-gyp @ /usr/local/lib/node_modules/npm/node_modules/node-gyp/package.json | 10.0.1 | 10.1.0 | 📦 Version |
| nopt @ /usr/local/lib/node_modules/npm/node_modules/nopt/package.json | 7.2.0 | 7.2.1 | 📦 Version |
| normalize-package-data @ /usr/local/lib/node_modules/npm/node_modules/normalize-package-data/package.json | 6.0.0 | 6.0.2 | 📦 Version |
| npm @ /usr/local/lib/node_modules/npm/package.json | 10.2.4 | 10.8.2 | 📦 Version |
| npm-bundled @ /usr/local/lib/node_modules/npm/node_modules/npm-bundled/package.json | 3.0.0 | 3.0.1 | 📦 Version |
| npm-package-arg @ /usr/local/lib/node_modules/npm/node_modules/npm-package-arg/package.json | 11.0.1 | 11.0.2 | 📦 Version |
| npm-packlist @ /usr/local/lib/node_modules/npm/node_modules/npm-packlist/package.json | 8.0.0 | 8.0.2 | 📦 Version |
| npm-pick-manifest @ /usr/local/lib/node_modules/npm/node_modules/npm-pick-manifest/package.json | 9.0.0 | 9.1.0 | 📦 Version |
| npm-profile @ /usr/local/lib/node_modules/npm/node_modules/npm-profile/package.json | 9.0.0 | 10.0.0 | 📦 Version |
| npm-registry-fetch @ /usr/local/lib/node_modules/npm/node_modules/npm-registry-fetch/package.json | 16.1.0 | 17.1.0 | 📦 Version |
| npm-user-validate @ /usr/local/lib/node_modules/npm/node_modules/npm-user-validate/package.json | 2.0.0 | 2.0.1 | 📦 Version |
| pacote @ /usr/local/lib/node_modules/npm/node_modules/pacote/package.json | 17.0.4 | 18.0.6 | 📦 Version |
| path-scurry @ /usr/local/lib/node_modules/npm/node_modules/path-scurry/package.json | 1.10.1 | 1.11.1 | 📦 Version |
| postcss-selector-parser @ /usr/local/lib/node_modules/npm/node_modules/postcss-selector-parser/package.json | 6.0.13 | 6.1.0 | 📦 Version |
| proc-log @ /usr/local/lib/node_modules/npm/node_modules/proc-log/package.json | 3.0.0 | 4.2.0 | 📦 Version |
| promise-call-limit @ /usr/local/lib/node_modules/npm/node_modules/promise-call-limit/package.json | 1.0.2 | 3.0.1 | 📦 Version |
| promzard @ /usr/local/lib/node_modules/npm/node_modules/promzard/package.json | 1.0.0 | 1.0.2 | 📦 Version |
| read @ /usr/local/lib/node_modules/npm/node_modules/read/package.json | 2.1.0 | 3.0.1 | 📦 Version |
| semver @ /usr/local/lib/node_modules/npm/node_modules/semver/package.json | 7.5.4 | 7.6.2 | 📦 Version |
| sigstore @ /usr/local/lib/node_modules/npm/node_modules/sigstore/package.json | 2.1.0 | 2.3.1 | 📦 Version |
| socks @ /usr/local/lib/node_modules/npm/node_modules/socks/package.json | 2.7.1 | 2.8.3 | 📦 Version |
| socks-proxy-agent @ /usr/local/lib/node_modules/npm/node_modules/socks-proxy-agent/package.json | 8.0.2 | 8.0.4 | 📦 Version |
| spdx-exceptions @ /usr/local/lib/node_modules/npm/node_modules/spdx-exceptions/package.json | 2.3.0 | 2.5.0 | 📦 Version |
| spdx-expression-parse @ /usr/local/lib/node_modules/npm/node_modules/spdx-expression-parse/package.json | 3.0.1 | 4.0.0 | 📦 Version |
| spdx-license-ids @ /usr/local/lib/node_modules/npm/node_modules/spdx-license-ids/package.json | 3.0.16 | 3.0.18 | 📦 Version |
| ssri @ /usr/local/lib/node_modules/npm/node_modules/ssri/package.json | 10.0.5 | 10.0.6 | 📦 Version |
| strip-ansi @ /usr/local/lib/node_modules/npm/node_modules/strip-ansi/package.json | 7.1.0 | 6.0.1 | 📦 Version |
| tar @ /usr/local/lib/node_modules/npm/node_modules/tar/package.json | 6.2.0 | 6.2.1 | 📦 Version |
| tuf-js @ /usr/local/lib/node_modules/npm/node_modules/tuf-js/package.json | 2.1.0 | 2.2.1 | 📦 Version |
| validate-npm-package-name @ /usr/local/lib/node_modules/npm/node_modules/validate-npm-package-name/package.json | 5.0.0 | 5.0.1 | 📦 Version |
| yarn @ /opt/yarn-v1.22.22/package.json | 1.22.19 | 1.22.22 | 📦 Version |

</details>

---
*Generated by [sbomlyze](https://github.com/rezmoss/sbomlyze) at 2026-11-09T02:06:29Z*

