## 📦 SBOM Diff Report

### SBOM Comparison

| | Before | After |
|---|---|---|
| **File** | zookeeper-3.8.3.syft.json | zookeeper-3.9.2.syft.json |
| **File Size** | 4 MB | 4 MB |
| **Format** | Syft JSON 16.1.12 | Syft JSON 16.1.12 |
| **Generator** | syft 1.56.0 | syft 1.56.0 |
| **OS** | Ubuntu 22.04.4 LTS | Ubuntu 22.04.5 LTS |
| **Source** | index.docker.io/library/zookeeper | index.docker.io/library/zookeeper |
| **Total Components** | 187 | 194 |
| **PURL Coverage** | 100.0% | 100.0% |
| **License Coverage** | 96.8% | 96.9% |
| **Hash Coverage** | 19.8% | 22.7% |
| **CPE Coverage** | 100.0% | 100.0% |

### Scan Context

| | Before | After |
|---|---|---|
| **Schema** | 16.1.12 | 16.1.12 |
| **Scan Scope** | squashed | squashed |

### Key Findings

- 🔄 Scanned index.docker.io/library/zookeeper changed: sha256:34e7ff9583a84592fc28a0f19e2c2e55c444a6b22d1d6b3a65b0c167a40d464a → sha256:7b775af48b8853b2c9868f438a065db9e1f86b15a4e00ce94898930ff24aad69
- 📈 Inventory: +7 components (3.7%), -4 files (-0.1%), -4 relationships (-0.1%)
- 💻 OS changed: Ubuntu 22.04.4 LTS → Ubuntu 22.04.5 LTS
- 🔄 59 version upgrades (3 major, 3 minor, 23 patch, 30 revision) among 187 shared packages
- 🙈 Integrity drift checked only 0 of 112 same-version packages; the rest carry no comparable digest
- 📄 695 file entries changed content: 652 in packages that changed version, 0 in same-version packages, 43 not owned by any package: /var/lib/dpkg/info/apt.md5sums, /var/lib/dpkg/info/apt.shlibs, /var/lib/dpkg/info/base-files.md5sums, /var/lib/dpkg/info/bash.md5sums, /var/lib/dpkg/info/bash.postinst + 38 more
- 🔄 deb: 148 packages before and after (36 version changes)
- 📜 License shift: permissive +7

<details>
<summary>➕ Added Packages by Type (7 total)</summary>

**maven** (7)

| Name | Version | Location |
|------|---------|----------|
| netty-tcnative-boringssl-static | 2.0.61.Final | /apache-zookeeper-3.9.2-bin/lib/netty-tcnative-boringssl-static-2.0.61.Final-osx-x86_64.jar |
| netty-tcnative-boringssl-static | 2.0.61.Final | /apache-zookeeper-3.9.2-bin/lib/netty-tcnative-boringssl-static-2.0.61.Final-osx-aarch_64.jar |
| netty-tcnative-boringssl-static | 2.0.61.Final | /apache-zookeeper-3.9.2-bin/lib/netty-tcnative-boringssl-static-2.0.61.Final.jar |
| netty-tcnative-boringssl-static | 2.0.61.Final | /apache-zookeeper-3.9.2-bin/lib/netty-tcnative-boringssl-static-2.0.61.Final-linux-x86_64.jar |
| netty-tcnative-boringssl-static | 2.0.61.Final | /apache-zookeeper-3.9.2-bin/lib/netty-tcnative-boringssl-static-2.0.61.Final-windows-x86_64.jar |

*...and 2 more*


</details>

### Summary

| Metric | Count |
|--------|-------|
| Added | 7 |
| Removed | 0 |
| Changed | 59 |
| Moved | 16 |
| File changes | 695 |

### Drift Summary

| Type | Count | Status |
|------|-------|--------|
| Version | 59 | ✅ |
| Integrity | 0 | ✅ |
| Metadata | 0 | ✅ |
| File entries (not package drift) | 695 | ℹ️ |

<details>
<summary>➕ Added Components (7)</summary>

| Name | Version |
|------|--------|
| netty-tcnative-boringssl-static | 2.0.61.Final |
| netty-tcnative-boringssl-static | 2.0.61.Final |
| netty-tcnative-boringssl-static | 2.0.61.Final |
| netty-tcnative-boringssl-static | 2.0.61.Final |
| netty-tcnative-boringssl-static | 2.0.61.Final |
| netty-tcnative-boringssl-static | 2.0.61.Final |
| netty-tcnative-classes | 2.0.61.Final |

</details>

<details>
<summary>↪️ Moved Components (16)</summary>

| Name | Version | From | To |
|------|---------|------|----|
| jackson-annotations | 2.15.2 | /apache-zookeeper-3.8.3-bin/lib/jackson-annotations-2.15.2.jar | /apache-zookeeper-3.9.2-bin/lib/jackson-annotations-2.15.2.jar |
| jackson-core | 2.15.2 | /apache-zookeeper-3.8.3-bin/lib/jackson-core-2.15.2.jar | /apache-zookeeper-3.9.2-bin/lib/jackson-core-2.15.2.jar |
| jackson-databind | 2.15.2 | /apache-zookeeper-3.8.3-bin/lib/jackson-databind-2.15.2.jar | /apache-zookeeper-3.9.2-bin/lib/jackson-databind-2.15.2.jar |
| commons-cli | 1.5.0 | /apache-zookeeper-3.8.3-bin/lib/commons-cli-1.5.0.jar | /apache-zookeeper-3.9.2-bin/lib/commons-cli-1.5.0.jar |
| commons-io | 2.11.0 | /apache-zookeeper-3.8.3-bin/lib/commons-io-2.11.0.jar | /apache-zookeeper-3.9.2-bin/lib/commons-io-2.11.0.jar |
| metrics-core | 4.1.12.1 | /apache-zookeeper-3.8.3-bin/lib/metrics-core-4.1.12.1.jar | /apache-zookeeper-3.9.2-bin/lib/metrics-core-4.1.12.1.jar |
| simpleclient | 0.9.0 | /apache-zookeeper-3.8.3-bin/lib/simpleclient-0.9.0.jar | /apache-zookeeper-3.9.2-bin/lib/simpleclient-0.9.0.jar |
| simpleclient_common | 0.9.0 | /apache-zookeeper-3.8.3-bin/lib/simpleclient_common-0.9.0.jar | /apache-zookeeper-3.9.2-bin/lib/simpleclient_common-0.9.0.jar |
| simpleclient_hotspot | 0.9.0 | /apache-zookeeper-3.8.3-bin/lib/simpleclient_hotspot-0.9.0.jar | /apache-zookeeper-3.9.2-bin/lib/simpleclient_hotspot-0.9.0.jar |
| simpleclient_servlet | 0.9.0 | /apache-zookeeper-3.8.3-bin/lib/simpleclient_servlet-0.9.0.jar | /apache-zookeeper-3.9.2-bin/lib/simpleclient_servlet-0.9.0.jar |
| javax.servlet-api | 3.1.0 | /apache-zookeeper-3.8.3-bin/lib/javax.servlet-api-3.1.0.jar | /apache-zookeeper-3.9.2-bin/lib/javax.servlet-api-3.1.0.jar |
| jline | 2.14.6 | /apache-zookeeper-3.8.3-bin/lib/jline-2.14.6.jar | /apache-zookeeper-3.9.2-bin/lib/jline-2.14.6.jar |
| audience-annotations | 0.12.0 | /apache-zookeeper-3.8.3-bin/lib/audience-annotations-0.12.0.jar | /apache-zookeeper-3.9.2-bin/lib/audience-annotations-0.12.0.jar |
| jctools-core | 3.1.0 | /apache-zookeeper-3.8.3-bin/lib/netty-common-4.1.94.Final.jar | /apache-zookeeper-3.9.2-bin/lib/netty-common-4.1.105.Final.jar |
| slf4j-api | 1.7.30 | /apache-zookeeper-3.8.3-bin/lib/slf4j-api-1.7.30.jar | /apache-zookeeper-3.9.2-bin/lib/slf4j-api-1.7.30.jar |
| snappy-java | 1.1.10.5 | /apache-zookeeper-3.8.3-bin/lib/snappy-java-1.1.10.5.jar | /apache-zookeeper-3.9.2-bin/lib/snappy-java-1.1.10.5.jar |

</details>

<details>
<summary>📄 File Changes (695, not package drift)</summary>

- `/etc/issue`
- `/etc/issue.net`
- `/etc/lsb-release`
- `/opt/java/openjdk/bin/java`
- `/opt/java/openjdk/bin/jfr`
- `/opt/java/openjdk/bin/jrunscript`
- `/opt/java/openjdk/bin/keytool`
- `/opt/java/openjdk/bin/rmiregistry`
- `/opt/java/openjdk/conf/logging.properties`
- `/opt/java/openjdk/conf/management/management.properties`
- `/opt/java/openjdk/conf/net.properties`
- `/opt/java/openjdk/conf/security/java.security`
- `/opt/java/openjdk/legal/java.base/asm.md`
- `/opt/java/openjdk/legal/java.base/cldr.md`
- `/opt/java/openjdk/legal/java.base/icu.md`
- `/opt/java/openjdk/legal/java.base/public_suffix.md`
- `/opt/java/openjdk/legal/java.base/unicode.md`
- `/opt/java/openjdk/legal/java.base/zlib.md`
- `/opt/java/openjdk/legal/java.desktop/giflib.md`
- `/opt/java/openjdk/legal/java.desktop/harfbuzz.md`
- `/opt/java/openjdk/legal/java.desktop/jpeg.md`
- `/opt/java/openjdk/legal/java.desktop/lcms.md`
- `/opt/java/openjdk/legal/java.desktop/libpng.md`
- `/opt/java/openjdk/legal/java.smartcardio/pcsclite.md`
- `/opt/java/openjdk/legal/java.xml.crypto/santuario.md`
- `/opt/java/openjdk/lib/classlist`
- `/opt/java/openjdk/lib/jexec`
- `/opt/java/openjdk/lib/jfr/default.jfc`
- `/opt/java/openjdk/lib/jfr/profile.jfc`
- `/opt/java/openjdk/lib/jrt-fs.jar`
- `/opt/java/openjdk/lib/jspawnhelper`
- `/opt/java/openjdk/lib/libawt.so`
- `/opt/java/openjdk/lib/libawt_headless.so`
- `/opt/java/openjdk/lib/libawt_xawt.so`
- `/opt/java/openjdk/lib/libdt_socket.so`
- `/opt/java/openjdk/lib/libextnet.so`
- `/opt/java/openjdk/lib/libfontmanager.so`
- `/opt/java/openjdk/lib/libinstrument.so`
- `/opt/java/openjdk/lib/libj2gss.so`
- `/opt/java/openjdk/lib/libj2pcsc.so`
- `/opt/java/openjdk/lib/libj2pkcs11.so`
- `/opt/java/openjdk/lib/libjaas.so`
- `/opt/java/openjdk/lib/libjava.so`
- `/opt/java/openjdk/lib/libjavajpeg.so`
- `/opt/java/openjdk/lib/libjawt.so`
- `/opt/java/openjdk/lib/libjdwp.so`
- `/opt/java/openjdk/lib/libjimage.so`
- `/opt/java/openjdk/lib/libjsig.so`
- `/opt/java/openjdk/lib/libjsound.so`
- `/opt/java/openjdk/lib/liblcms.so`
- `/opt/java/openjdk/lib/libmanagement.so`
- `/opt/java/openjdk/lib/libmanagement_agent.so`
- `/opt/java/openjdk/lib/libmanagement_ext.so`
- `/opt/java/openjdk/lib/libmlib_image.so`
- `/opt/java/openjdk/lib/libnet.so`
- `/opt/java/openjdk/lib/libnio.so`
- `/opt/java/openjdk/lib/libprefs.so`
- `/opt/java/openjdk/lib/librmi.so`
- `/opt/java/openjdk/lib/libsctp.so`
- `/opt/java/openjdk/lib/libsplashscreen.so`
- `/opt/java/openjdk/lib/libverify.so`
- `/opt/java/openjdk/lib/libzip.so`
- `/opt/java/openjdk/lib/modules`
- `/opt/java/openjdk/lib/security/cacerts`
- `/opt/java/openjdk/lib/security/default.policy`
- `/opt/java/openjdk/lib/security/public_suffix_list.dat`
- `/opt/java/openjdk/lib/server/classes.jsa`
- `/opt/java/openjdk/lib/server/libjsig.so`
- `/opt/java/openjdk/lib/server/libjvm.so`
- `/opt/java/openjdk/lib/tzdb.dat`
- `/opt/java/openjdk/release`
- `/usr/bin/[`
- `/usr/bin/addpart`
- `/usr/bin/apt`
- `/usr/bin/apt-cache`
- `/usr/bin/apt-cdrom`
- `/usr/bin/apt-config`
- `/usr/bin/apt-get`
- `/usr/bin/apt-mark`
- `/usr/bin/arch`
- `/usr/bin/b2sum`
- `/usr/bin/base32`
- `/usr/bin/base64`
- `/usr/bin/basename`
- `/usr/bin/basenc`
- `/usr/bin/bash`
- `/usr/bin/cat`
- `/usr/bin/chattr`
- `/usr/bin/chcon`
- `/usr/bin/chgrp`
- `/usr/bin/chmod`
- `/usr/bin/choom`
- `/usr/bin/chown`
- `/usr/bin/chrt`
- `/usr/bin/cksum`
- `/usr/bin/clear_console`
- `/usr/bin/comm`
- `/usr/bin/cp`
- `/usr/bin/csplit`
- `/usr/bin/curl`
- `/usr/bin/cut`
- `/usr/bin/date`
- `/usr/bin/dd`
- `/usr/bin/delpart`
- `/usr/bin/df`
- `/usr/bin/dir`
- `/usr/bin/dircolors`
- `/usr/bin/dirname`
- `/usr/bin/dmesg`
- `/usr/bin/dpkg`
- `/usr/bin/dpkg-deb`
- `/usr/bin/dpkg-divert`
- `/usr/bin/dpkg-query`
- `/usr/bin/dpkg-split`
- `/usr/bin/dpkg-statoverride`
- `/usr/bin/dpkg-trigger`
- `/usr/bin/du`
- `/usr/bin/echo`
- `/usr/bin/env`
- `/usr/bin/expand`
- `/usr/bin/expr`
- `/usr/bin/factor`
- `/usr/bin/fallocate`
- `/usr/bin/false`
- `/usr/bin/fincore`
- `/usr/bin/findmnt`
- `/usr/bin/flock`
- `/usr/bin/fmt`
- `/usr/bin/fold`
- `/usr/bin/getconf`
- `/usr/bin/getent`
- `/usr/bin/getopt`
- `/usr/bin/groups`
- `/usr/bin/hardlink`
- `/usr/bin/head`
- `/usr/bin/hostid`
- `/usr/bin/iconv`
- `/usr/bin/id`
- `/usr/bin/install`
- `/usr/bin/ionice`
- `/usr/bin/ipcmk`
- `/usr/bin/ipcrm`
- `/usr/bin/ipcs`
- `/usr/bin/join`
- `/usr/bin/last`
- `/usr/bin/ldd`
- `/usr/bin/link`
- `/usr/bin/ln`
- `/usr/bin/locale`
- `/usr/bin/locale-check`
- `/usr/bin/localedef`
- `/usr/bin/logger`
- `/usr/bin/logname`
- `/usr/bin/ls`
- `/usr/bin/lsattr`
- `/usr/bin/lsblk`
- `/usr/bin/lscpu`
- `/usr/bin/lsipc`
- `/usr/bin/lslocks`
- `/usr/bin/lslogins`
- `/usr/bin/lsmem`
- `/usr/bin/lsns`
- `/usr/bin/mcookie`
- `/usr/bin/md5sum`
- `/usr/bin/mesg`
- `/usr/bin/mkdir`
- `/usr/bin/mkfifo`
- `/usr/bin/mknod`
- `/usr/bin/mktemp`
- `/usr/bin/more`
- `/usr/bin/mount`
- `/usr/bin/mountpoint`
- `/usr/bin/mv`
- `/usr/bin/namei`
- `/usr/bin/nice`
- `/usr/bin/nl`
- `/usr/bin/nohup`
- `/usr/bin/nproc`
- `/usr/bin/nsenter`
- `/usr/bin/numfmt`
- `/usr/bin/od`
- `/usr/bin/openssl`
- `/usr/bin/partx`
- `/usr/bin/paste`
- `/usr/bin/pathchk`
- `/usr/bin/pinky`
- `/usr/bin/pldd`
- `/usr/bin/pr`
- `/usr/bin/printenv`
- `/usr/bin/printf`
- `/usr/bin/prlimit`
- `/usr/bin/ptx`
- `/usr/bin/pwd`
- `/usr/bin/readlink`
- `/usr/bin/realpath`
- `/usr/bin/renice`
- `/usr/bin/resizepart`
- `/usr/bin/rev`
- `/usr/bin/rm`
- `/usr/bin/rmdir`
- `/usr/bin/runcon`
- `/usr/bin/script`
- `/usr/bin/scriptlive`
- `/usr/bin/scriptreplay`
- `/usr/bin/seq`
- `/usr/bin/setarch`
- `/usr/bin/setpriv`
- `/usr/bin/setsid`
- `/usr/bin/setterm`
- `/usr/bin/sha1sum`
- `/usr/bin/sha224sum`
- `/usr/bin/sha256sum`
- `/usr/bin/sha384sum`
- `/usr/bin/sha512sum`
- `/usr/bin/shred`
- `/usr/bin/shuf`
- `/usr/bin/sleep`
- `/usr/bin/sort`
- `/usr/bin/split`
- `/usr/bin/stat`
- `/usr/bin/stdbuf`
- `/usr/bin/stty`
- `/usr/bin/su`
- `/usr/bin/sum`
- `/usr/bin/sync`
- `/usr/bin/tac`
- `/usr/bin/tail`
- `/usr/bin/taskset`
- `/usr/bin/tee`
- `/usr/bin/test`
- `/usr/bin/timeout`
- `/usr/bin/touch`
- `/usr/bin/tr`
- `/usr/bin/true`
- `/usr/bin/truncate`
- `/usr/bin/tsort`
- `/usr/bin/tty`
- `/usr/bin/tzselect`
- `/usr/bin/uclampset`
- `/usr/bin/umount`
- `/usr/bin/uname`
- `/usr/bin/unexpand`
- `/usr/bin/uniq`
- `/usr/bin/unlink`
- `/usr/bin/unshare`
- `/usr/bin/update-alternatives`
- `/usr/bin/users`
- `/usr/bin/utmpdump`
- `/usr/bin/vdir`
- `/usr/bin/wall`
- `/usr/bin/wc`
- `/usr/bin/wdctl`
- `/usr/bin/wget`
- `/usr/bin/whereis`
- `/usr/bin/who`
- `/usr/bin/whoami`
- `/usr/bin/yes`
- `/usr/bin/zdump`
- `/usr/lib/apt/apt-helper`
- `/usr/lib/apt/methods/cdrom`
- `/usr/lib/apt/methods/copy`
- `/usr/lib/apt/methods/file`
- `/usr/lib/apt/methods/ftp`
- `/usr/lib/apt/methods/gpgv`
- `/usr/lib/apt/methods/http`
- `/usr/lib/apt/methods/mirror`
- `/usr/lib/apt/methods/rred`
- `/usr/lib/apt/methods/rsh`
- `/usr/lib/apt/methods/store`
- `/usr/lib/apt/solvers/dump`
- `/usr/lib/os-release`
- `/usr/lib/x86_64-linux-gnu/audit/sotruss-lib.so`
- `/usr/lib/x86_64-linux-gnu/engines-3/afalg.so`
- `/usr/lib/x86_64-linux-gnu/engines-3/loader_attic.so`
- `/usr/lib/x86_64-linux-gnu/engines-3/padlock.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ANSI_X3.110.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ARMSCII-8.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ASMO_449.so`
- `/usr/lib/x86_64-linux-gnu/gconv/BIG5.so`
- `/usr/lib/x86_64-linux-gnu/gconv/BIG5HKSCS.so`
- `/usr/lib/x86_64-linux-gnu/gconv/BRF.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP10007.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP1125.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP1250.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP1251.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP1252.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP1253.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP1254.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP1255.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP1256.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP1257.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP1258.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP737.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP770.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP771.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP772.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP773.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP774.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP775.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CP932.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CSN_369103.so`
- `/usr/lib/x86_64-linux-gnu/gconv/CWI.so`
- `/usr/lib/x86_64-linux-gnu/gconv/DEC-MCS.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-AT-DE-A.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-AT-DE.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-CA-FR.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-DK-NO-A.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-DK-NO.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-ES-A.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-ES-S.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-ES.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-FI-SE-A.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-FI-SE.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-FR.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-IS-FRISS.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-IT.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-PT.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-UK.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EBCDIC-US.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ECMA-CYRILLIC.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EUC-CN.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EUC-JISX0213.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EUC-JP-MS.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EUC-JP.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EUC-KR.so`
- `/usr/lib/x86_64-linux-gnu/gconv/EUC-TW.so`
- `/usr/lib/x86_64-linux-gnu/gconv/GB18030.so`
- `/usr/lib/x86_64-linux-gnu/gconv/GBBIG5.so`
- `/usr/lib/x86_64-linux-gnu/gconv/GBGBK.so`
- `/usr/lib/x86_64-linux-gnu/gconv/GBK.so`
- `/usr/lib/x86_64-linux-gnu/gconv/GEORGIAN-ACADEMY.so`
- `/usr/lib/x86_64-linux-gnu/gconv/GEORGIAN-PS.so`
- `/usr/lib/x86_64-linux-gnu/gconv/GOST_19768-74.so`
- `/usr/lib/x86_64-linux-gnu/gconv/GREEK-CCITT.so`
- `/usr/lib/x86_64-linux-gnu/gconv/GREEK7-OLD.so`
- `/usr/lib/x86_64-linux-gnu/gconv/GREEK7.so`
- `/usr/lib/x86_64-linux-gnu/gconv/HP-GREEK8.so`
- `/usr/lib/x86_64-linux-gnu/gconv/HP-ROMAN8.so`
- `/usr/lib/x86_64-linux-gnu/gconv/HP-ROMAN9.so`
- `/usr/lib/x86_64-linux-gnu/gconv/HP-THAI8.so`
- `/usr/lib/x86_64-linux-gnu/gconv/HP-TURKISH8.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM037.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM038.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1004.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1008.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1008_420.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1025.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1026.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1046.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1047.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1097.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1112.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1122.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1123.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1124.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1129.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1130.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1132.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1133.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1137.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1140.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1141.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1142.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1143.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1144.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1145.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1146.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1147.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1148.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1149.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1153.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1154.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1155.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1156.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1157.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1158.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1160.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1161.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1162.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1163.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1164.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1166.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1167.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM12712.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1364.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1371.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1388.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1390.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM1399.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM16804.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM256.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM273.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM274.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM275.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM277.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM278.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM280.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM281.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM284.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM285.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM290.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM297.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM420.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM423.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM424.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM437.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM4517.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM4899.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM4909.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM4971.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM500.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM5347.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM803.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM850.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM851.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM852.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM855.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM856.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM857.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM858.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM860.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM861.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM862.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM863.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM864.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM865.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM866.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM866NAV.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM868.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM869.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM870.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM871.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM874.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM875.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM880.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM891.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM901.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM902.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM903.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM9030.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM904.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM905.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM9066.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM918.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM921.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM922.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM930.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM932.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM933.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM935.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM937.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM939.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM943.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IBM9448.so`
- `/usr/lib/x86_64-linux-gnu/gconv/IEC_P27-1.so`
- `/usr/lib/x86_64-linux-gnu/gconv/INIS-8.so`
- `/usr/lib/x86_64-linux-gnu/gconv/INIS-CYRILLIC.so`
- `/usr/lib/x86_64-linux-gnu/gconv/INIS.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISIRI-3342.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO-2022-CN-EXT.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO-2022-CN.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO-2022-JP-3.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO-2022-JP.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO-2022-KR.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO-IR-197.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO-IR-209.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO646.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-1.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-10.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-11.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-13.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-14.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-15.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-16.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-2.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-3.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-4.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-5.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-6.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-7.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-8.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-9.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO8859-9E.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO_10367-BOX.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO_11548-1.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO_2033.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO_5427-EXT.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO_5427.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO_5428.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO_6937-2.so`
- `/usr/lib/x86_64-linux-gnu/gconv/ISO_6937.so`
- `/usr/lib/x86_64-linux-gnu/gconv/JOHAB.so`
- `/usr/lib/x86_64-linux-gnu/gconv/KOI-8.so`
- `/usr/lib/x86_64-linux-gnu/gconv/KOI8-R.so`
- `/usr/lib/x86_64-linux-gnu/gconv/KOI8-RU.so`
- `/usr/lib/x86_64-linux-gnu/gconv/KOI8-T.so`
- `/usr/lib/x86_64-linux-gnu/gconv/KOI8-U.so`
- `/usr/lib/x86_64-linux-gnu/gconv/LATIN-GREEK-1.so`
- `/usr/lib/x86_64-linux-gnu/gconv/LATIN-GREEK.so`
- `/usr/lib/x86_64-linux-gnu/gconv/MAC-CENTRALEUROPE.so`
- `/usr/lib/x86_64-linux-gnu/gconv/MAC-IS.so`
- `/usr/lib/x86_64-linux-gnu/gconv/MAC-SAMI.so`
- `/usr/lib/x86_64-linux-gnu/gconv/MAC-UK.so`
- `/usr/lib/x86_64-linux-gnu/gconv/MACINTOSH.so`
- `/usr/lib/x86_64-linux-gnu/gconv/MIK.so`
- `/usr/lib/x86_64-linux-gnu/gconv/NATS-DANO.so`
- `/usr/lib/x86_64-linux-gnu/gconv/NATS-SEFI.so`
- `/usr/lib/x86_64-linux-gnu/gconv/PT154.so`
- `/usr/lib/x86_64-linux-gnu/gconv/RK1048.so`
- `/usr/lib/x86_64-linux-gnu/gconv/SAMI-WS2.so`
- `/usr/lib/x86_64-linux-gnu/gconv/SHIFT_JISX0213.so`
- `/usr/lib/x86_64-linux-gnu/gconv/SJIS.so`
- `/usr/lib/x86_64-linux-gnu/gconv/T.61.so`
- `/usr/lib/x86_64-linux-gnu/gconv/TCVN5712-1.so`
- `/usr/lib/x86_64-linux-gnu/gconv/TIS-620.so`
- `/usr/lib/x86_64-linux-gnu/gconv/TSCII.so`
- `/usr/lib/x86_64-linux-gnu/gconv/UHC.so`
- `/usr/lib/x86_64-linux-gnu/gconv/UNICODE.so`
- `/usr/lib/x86_64-linux-gnu/gconv/UTF-16.so`
- `/usr/lib/x86_64-linux-gnu/gconv/UTF-32.so`
- `/usr/lib/x86_64-linux-gnu/gconv/UTF-7.so`
- `/usr/lib/x86_64-linux-gnu/gconv/VISCII.so`
- `/usr/lib/x86_64-linux-gnu/gconv/libCNS.so`
- `/usr/lib/x86_64-linux-gnu/gconv/libGB.so`
- `/usr/lib/x86_64-linux-gnu/gconv/libISOIR165.so`
- `/usr/lib/x86_64-linux-gnu/gconv/libJIS.so`
- `/usr/lib/x86_64-linux-gnu/gconv/libJISX0213.so`
- `/usr/lib/x86_64-linux-gnu/gconv/libKSC.so`
- `/usr/lib/x86_64-linux-gnu/krb5/plugins/preauth/spake.so`
- `/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2`
- `/usr/lib/x86_64-linux-gnu/libBrokenLocale.so.1`
- `/usr/lib/x86_64-linux-gnu/libanl.so.1`
- `/usr/lib/x86_64-linux-gnu/libapt-pkg.so.6.0.0`
- `/usr/lib/x86_64-linux-gnu/libapt-private.so.0.0.0`
- `/usr/lib/x86_64-linux-gnu/libblkid.so.1.1.0`
- `/usr/lib/x86_64-linux-gnu/libc.so.6`
- `/usr/lib/x86_64-linux-gnu/libc_malloc_debug.so.0`
- `/usr/lib/x86_64-linux-gnu/libcom_err.so.2.1`
- `/usr/lib/x86_64-linux-gnu/libcrypto.so.3`
- `/usr/lib/x86_64-linux-gnu/libcurl.so.4.7.0`
- `/usr/lib/x86_64-linux-gnu/libdl.so.2`
- `/usr/lib/x86_64-linux-gnu/libe2p.so.2.3`
- `/usr/lib/x86_64-linux-gnu/libexpat.so.1.8.7`
- `/usr/lib/x86_64-linux-gnu/libexpatw.so.1.8.7`
- `/usr/lib/x86_64-linux-gnu/libext2fs.so.2.4`
- `/usr/lib/x86_64-linux-gnu/libgnutls.so.30.31.0`
- `/usr/lib/x86_64-linux-gnu/libgssapi_krb5.so.2.2`
- `/usr/lib/x86_64-linux-gnu/libk5crypto.so.3.1`
- `/usr/lib/x86_64-linux-gnu/libkrb5.so.3.3`
- `/usr/lib/x86_64-linux-gnu/libkrb5support.so.0.1`
- `/usr/lib/x86_64-linux-gnu/libm.so.6`
- `/usr/lib/x86_64-linux-gnu/libmemusage.so`
- `/usr/lib/x86_64-linux-gnu/libmount.so.1.1.0`
- `/usr/lib/x86_64-linux-gnu/libmvec.so.1`
- `/usr/lib/x86_64-linux-gnu/libnghttp2.so.14.20.1`
- `/usr/lib/x86_64-linux-gnu/libnsl.so.1`
- `/usr/lib/x86_64-linux-gnu/libnss_compat.so.2`
- `/usr/lib/x86_64-linux-gnu/libnss_dns.so.2`
- `/usr/lib/x86_64-linux-gnu/libnss_files.so.2`
- `/usr/lib/x86_64-linux-gnu/libnss_hesiod.so.2`
- `/usr/lib/x86_64-linux-gnu/libpcprofile.so`
- `/usr/lib/x86_64-linux-gnu/libresolv.so.2`
- `/usr/lib/x86_64-linux-gnu/librt.so.1`
- `/usr/lib/x86_64-linux-gnu/libsmartcols.so.1.1.0`
- `/usr/lib/x86_64-linux-gnu/libss.so.2.0`
- `/usr/lib/x86_64-linux-gnu/libssl.so.3`
- `/usr/lib/x86_64-linux-gnu/libthread_db.so.1`
- `/usr/lib/x86_64-linux-gnu/libutil.so.1`
- `/usr/lib/x86_64-linux-gnu/libuuid.so.1.3.0`
- `/usr/lib/x86_64-linux-gnu/ossl-modules/legacy.so`
- `/usr/libexec/coreutils/libstdbuf.so`
- `/usr/sbin/agetty`
- `/usr/sbin/badblocks`
- `/usr/sbin/blkdiscard`
- `/usr/sbin/blkid`
- `/usr/sbin/blkzone`
- `/usr/sbin/blockdev`
- `/usr/sbin/chcpu`
- `/usr/sbin/chmem`
- `/usr/sbin/chroot`
- `/usr/sbin/ctrlaltdel`
- `/usr/sbin/debugfs`
- `/usr/sbin/dumpe2fs`
- `/usr/sbin/e2freefrag`
- `/usr/sbin/e2fsck`
- `/usr/sbin/e2image`
- `/usr/sbin/e2undo`
- `/usr/sbin/e4crypt`
- `/usr/sbin/e4defrag`
- `/usr/sbin/filefrag`
- `/usr/sbin/findfs`
- `/usr/sbin/fsck`
- `/usr/sbin/fsck.cramfs`
- `/usr/sbin/fsck.minix`
- `/usr/sbin/fsfreeze`
- `/usr/sbin/fstrim`
- `/usr/sbin/hwclock`
- `/usr/sbin/iconvconfig`
- `/usr/sbin/isosize`
- `/usr/sbin/ldattach`
- `/usr/sbin/ldconfig.real`
- `/usr/sbin/logsave`
- `/usr/sbin/losetup`
- `/usr/sbin/mke2fs`
- `/usr/sbin/mkfs`
- `/usr/sbin/mkfs.bfs`
- `/usr/sbin/mkfs.cramfs`
- `/usr/sbin/mkfs.minix`
- `/usr/sbin/mklost+found`
- `/usr/sbin/mkswap`
- `/usr/sbin/pivot_root`
- `/usr/sbin/readprofile`
- `/usr/sbin/resize2fs`
- `/usr/sbin/rtcwake`
- `/usr/sbin/runuser`
- `/usr/sbin/start-stop-daemon`
- `/usr/sbin/sulogin`
- `/usr/sbin/swaplabel`
- `/usr/sbin/swapoff`
- `/usr/sbin/swapon`
- `/usr/sbin/switch_root`
- `/usr/sbin/tune2fs`
- `/usr/sbin/wipefs`
- `/usr/sbin/zic`
- `/usr/sbin/zramctl`
- `/usr/share/ca-certificates/mozilla/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.crt`
- `/usr/share/doc/base-files/changelog.gz`
- `/usr/share/doc/bash/changelog.Debian.gz`
- `/usr/share/doc/bsdutils/changelog.Debian.gz`
- `/usr/share/doc/ca-certificates/changelog.gz`
- `/usr/share/doc/coreutils/changelog.Debian.gz`
- `/usr/share/doc/dpkg/changelog.Debian.gz`
- `/usr/share/doc/libapt-pkg6.0/changelog.gz`
- `/usr/share/doc/libblkid1/changelog.Debian.gz`
- `/usr/share/doc/libc6/changelog.Debian.gz`
- `/usr/share/doc/libcom-err2/changelog.Debian.gz`
- `/usr/share/doc/libcurl4/changelog.Debian.gz`
- `/usr/share/doc/libexpat1/changelog.Debian.gz`
- `/usr/share/doc/libext2fs2/changelog.Debian.gz`
- `/usr/share/doc/libgnutls30/changelog.Debian.gz`
- `/usr/share/doc/libkrb5support0/changelog.Debian.gz`
- `/usr/share/doc/libldap-2.5-0/changelog.Debian.gz`
- `/usr/share/doc/libnghttp2-14/changelog.Debian.gz`
- `/usr/share/doc/libsmartcols1/changelog.Debian.gz`
- `/usr/share/doc/libssl3/changelog.Debian.gz`
- `/usr/share/doc/libuuid1/changelog.Debian.gz`
- `/usr/share/doc/locales/changelog.Debian.gz`
- `/usr/share/doc/logsave/changelog.Debian.gz`
- `/usr/share/doc/tzdata/changelog.Debian.gz`
- `/usr/share/doc/wget/changelog.Debian.gz`
- `/usr/share/info/coreutils.info.gz`
- `/usr/share/zoneinfo/tzdata.zi`
- `/var/lib/dpkg/info/apt.md5sums`
- `/var/lib/dpkg/info/apt.shlibs`
- `/var/lib/dpkg/info/base-files.md5sums`
- `/var/lib/dpkg/info/bash.md5sums`
- `/var/lib/dpkg/info/bash.postinst`
- `/var/lib/dpkg/info/bash.postrm`
- `/var/lib/dpkg/info/bsdutils.md5sums`
- `/var/lib/dpkg/info/ca-certificates.config`
- `/var/lib/dpkg/info/ca-certificates.list`
- `/var/lib/dpkg/info/ca-certificates.md5sums`
- `/var/lib/dpkg/info/coreutils.md5sums`
- `/var/lib/dpkg/info/curl.md5sums`
- `/var/lib/dpkg/info/dpkg.md5sums`
- `/var/lib/dpkg/info/e2fsprogs.md5sums`
- `/var/lib/dpkg/info/libapt-pkg6.0:amd64.md5sums`
- `/var/lib/dpkg/info/libblkid1:amd64.md5sums`
- `/var/lib/dpkg/info/libc-bin.md5sums`
- `/var/lib/dpkg/info/libc6:amd64.md5sums`
- `/var/lib/dpkg/info/libcom-err2:amd64.md5sums`
- `/var/lib/dpkg/info/libcurl4:amd64.md5sums`
- `/var/lib/dpkg/info/libexpat1:amd64.md5sums`
- `/var/lib/dpkg/info/libext2fs2:amd64.md5sums`
- `/var/lib/dpkg/info/libgnutls30:amd64.md5sums`
- `/var/lib/dpkg/info/libgssapi-krb5-2:amd64.md5sums`
- `/var/lib/dpkg/info/libk5crypto3:amd64.md5sums`
- `/var/lib/dpkg/info/libkrb5-3:amd64.md5sums`
- `/var/lib/dpkg/info/libkrb5support0:amd64.md5sums`
- `/var/lib/dpkg/info/libldap-2.5-0:amd64.md5sums`
- `/var/lib/dpkg/info/libmount1:amd64.md5sums`
- `/var/lib/dpkg/info/libnghttp2-14:amd64.md5sums`
- `/var/lib/dpkg/info/libsmartcols1:amd64.md5sums`
- `/var/lib/dpkg/info/libss2:amd64.md5sums`
- `/var/lib/dpkg/info/libssl3:amd64.md5sums`
- `/var/lib/dpkg/info/libuuid1:amd64.md5sums`
- `/var/lib/dpkg/info/locales.md5sums`
- `/var/lib/dpkg/info/logsave.md5sums`
- `/var/lib/dpkg/info/mount.md5sums`
- `/var/lib/dpkg/info/openssl.md5sums`
- `/var/lib/dpkg/info/tzdata.config`
- `/var/lib/dpkg/info/tzdata.md5sums`
- `/var/lib/dpkg/info/util-linux.md5sums`
- `/var/lib/dpkg/info/wget.md5sums`
- `/var/lib/dpkg/status`

</details>

<details>
<summary>🔄 Changed Components (59)</summary>

| Name | Before | After | Drift |
|------|--------|-------|-------|
| apt @ /var/lib/dpkg/status | 2.4.11 | 2.4.13 | 📦 Version |
| base-files @ /var/lib/dpkg/status | 12ubuntu4.6 | 12ubuntu4.7 | 📦 Version |
| bash @ /var/lib/dpkg/status | 5.1-6ubuntu1 | 5.1-6ubuntu1.1 | 📦 Version |
| bsdutils @ /var/lib/dpkg/status | 1:2.37.2-4ubuntu3 | 1:2.37.2-4ubuntu3.4 | 📦 Version |
| ca-certificates @ /var/lib/dpkg/status | 20230311ubuntu0.22.04.1 | 20240203~22.04.1 | 📦 Version |
| coreutils @ /var/lib/dpkg/status | 8.32-4.1ubuntu1.1 | 8.32-4.1ubuntu1.2 | 📦 Version |
| curl @ /var/lib/dpkg/status | 7.81.0-1ubuntu1.15 | 7.81.0-1ubuntu1.18 | 📦 Version |
| dpkg @ /var/lib/dpkg/status | 1.21.1ubuntu2.2 | 1.21.1ubuntu2.3 | 📦 Version |
| e2fsprogs @ /var/lib/dpkg/status | 1.46.5-2ubuntu1.1 | 1.46.5-2ubuntu1.2 | 📦 Version |
| libapt-pkg6.0 @ /var/lib/dpkg/status | 2.4.11 | 2.4.13 | 📦 Version |
| libblkid1 @ /var/lib/dpkg/status | 2.37.2-4ubuntu3 | 2.37.2-4ubuntu3.4 | 📦 Version |
| libc-bin @ /var/lib/dpkg/status | 2.35-0ubuntu3.6 | 2.35-0ubuntu3.8 | 📦 Version |
| libc6 @ /var/lib/dpkg/status | 2.35-0ubuntu3.6 | 2.35-0ubuntu3.8 | 📦 Version |
| libcom-err2 @ /var/lib/dpkg/status | 1.46.5-2ubuntu1.1 | 1.46.5-2ubuntu1.2 | 📦 Version |
| libcurl4 @ /var/lib/dpkg/status | 7.81.0-1ubuntu1.15 | 7.81.0-1ubuntu1.18 | 📦 Version |
| libexpat1 @ /var/lib/dpkg/status | 2.4.7-1ubuntu0.2 | 2.4.7-1ubuntu0.4 | 📦 Version |
| libext2fs2 @ /var/lib/dpkg/status | 1.46.5-2ubuntu1.1 | 1.46.5-2ubuntu1.2 | 📦 Version |
| libgnutls30 @ /var/lib/dpkg/status | 3.7.3-4ubuntu1.4 | 3.7.3-4ubuntu1.5 | 📦 Version |
| libgssapi-krb5-2 @ /var/lib/dpkg/status | 1.19.2-2ubuntu0.3 | 1.19.2-2ubuntu0.4 | 📦 Version |
| libk5crypto3 @ /var/lib/dpkg/status | 1.19.2-2ubuntu0.3 | 1.19.2-2ubuntu0.4 | 📦 Version |
| libkrb5-3 @ /var/lib/dpkg/status | 1.19.2-2ubuntu0.3 | 1.19.2-2ubuntu0.4 | 📦 Version |
| libkrb5support0 @ /var/lib/dpkg/status | 1.19.2-2ubuntu0.3 | 1.19.2-2ubuntu0.4 | 📦 Version |
| libldap-2.5-0 @ /var/lib/dpkg/status | 2.5.16+dfsg-0ubuntu0.22.04.2 | 2.5.18+dfsg-0ubuntu0.22.04.2 | 📦 Version |
| libmount1 @ /var/lib/dpkg/status | 2.37.2-4ubuntu3 | 2.37.2-4ubuntu3.4 | 📦 Version |
| libnghttp2-14 @ /var/lib/dpkg/status | 1.43.0-1ubuntu0.1 | 1.43.0-1ubuntu0.2 | 📦 Version |
| libsmartcols1 @ /var/lib/dpkg/status | 2.37.2-4ubuntu3 | 2.37.2-4ubuntu3.4 | 📦 Version |
| libss2 @ /var/lib/dpkg/status | 1.46.5-2ubuntu1.1 | 1.46.5-2ubuntu1.2 | 📦 Version |
| libssl3 @ /var/lib/dpkg/status | 3.0.2-0ubuntu1.15 | 3.0.2-0ubuntu1.18 | 📦 Version |
| libuuid1 @ /var/lib/dpkg/status | 2.37.2-4ubuntu3 | 2.37.2-4ubuntu3.4 | 📦 Version |
| locales @ /var/lib/dpkg/status | 2.35-0ubuntu3.6 | 2.35-0ubuntu3.8 | 📦 Version |
| logsave @ /var/lib/dpkg/status | 1.46.5-2ubuntu1.1 | 1.46.5-2ubuntu1.2 | 📦 Version |
| mount @ /var/lib/dpkg/status | 2.37.2-4ubuntu3 | 2.37.2-4ubuntu3.4 | 📦 Version |
| openssl @ /var/lib/dpkg/status | 3.0.2-0ubuntu1.15 | 3.0.2-0ubuntu1.18 | 📦 Version |
| tzdata @ /var/lib/dpkg/status | 2024a-0ubuntu0.22.04 | 2024a-0ubuntu0.22.04.1 | 📦 Version |
| util-linux @ /var/lib/dpkg/status | 2.37.2-4ubuntu3 | 2.37.2-4ubuntu3.4 | 📦 Version |
| wget @ /var/lib/dpkg/status | 1.21.2-2ubuntu1 | 1.21.2-2ubuntu1.1 | 📦 Version |
| openjdk @ /opt/java/openjdk/release | 11.0.22+7 | 17.0.13+11 | 📦 Version |
| logback-classic @ /apache-zookeeper-3.9.2-bin/lib/logback-classic-1.2.13.jar | 1.2.10 | 1.2.13 | 📦 Version |
| logback-core @ /apache-zookeeper-3.9.2-bin/lib/logback-core-1.2.13.jar | 1.2.10 | 1.2.13 | 📦 Version |
| netty-buffer @ /apache-zookeeper-3.9.2-bin/lib/netty-buffer-4.1.105.Final.jar | 4.1.94.Final | 4.1.105.Final | 📦 Version |
| netty-codec @ /apache-zookeeper-3.9.2-bin/lib/netty-codec-4.1.105.Final.jar | 4.1.94.Final | 4.1.105.Final | 📦 Version |
| netty-common @ /apache-zookeeper-3.9.2-bin/lib/netty-common-4.1.105.Final.jar | 4.1.94.Final | 4.1.105.Final | 📦 Version |
| netty-handler @ /apache-zookeeper-3.9.2-bin/lib/netty-handler-4.1.105.Final.jar | 4.1.94.Final | 4.1.105.Final | 📦 Version |
| netty-resolver @ /apache-zookeeper-3.9.2-bin/lib/netty-resolver-4.1.105.Final.jar | 4.1.94.Final | 4.1.105.Final | 📦 Version |
| netty-transport @ /apache-zookeeper-3.9.2-bin/lib/netty-transport-4.1.105.Final.jar | 4.1.94.Final | 4.1.105.Final | 📦 Version |
| netty-transport-classes-epoll @ /apache-zookeeper-3.9.2-bin/lib/netty-transport-classes-epoll-4.1.105.Final.jar | 4.1.94.Final | 4.1.105.Final | 📦 Version |
| netty-transport-native-epoll @ /apache-zookeeper-3.9.2-bin/lib/netty-transport-native-epoll-4.1.105.Final-linux-x86_64.jar | 4.1.94.Final | 4.1.105.Final | 📦 Version |
| netty-transport-native-unix-common @ /apache-zookeeper-3.9.2-bin/lib/netty-transport-native-unix-common-4.1.105.Final.jar | 4.1.94.Final | 4.1.105.Final | 📦 Version |
| jrt-fs @ /opt/java/openjdk/lib/jrt-fs.jar | 11.0.22 | 17.0.13 | 📦 Version |
| zookeeper @ /apache-zookeeper-3.9.2-bin/lib/zookeeper-3.9.2.jar | 3.8.3 | 3.9.2 | 📦 Version |
| zookeeper-jute @ /apache-zookeeper-3.9.2-bin/lib/zookeeper-jute-3.9.2.jar | 3.8.3 | 3.9.2 | 📦 Version |
| zookeeper-prometheus-metrics @ /apache-zookeeper-3.9.2-bin/lib/zookeeper-prometheus-metrics-3.9.2.jar | 3.8.3 | 3.9.2 | 📦 Version |
| jetty-http @ /apache-zookeeper-3.9.2-bin/lib/jetty-http-9.4.53.v20231009.jar | 9.4.52.v20230823 | 9.4.53.v20231009 | 📦 Version |
| jetty-io @ /apache-zookeeper-3.9.2-bin/lib/jetty-io-9.4.53.v20231009.jar | 9.4.52.v20230823 | 9.4.53.v20231009 | 📦 Version |
| jetty-security @ /apache-zookeeper-3.9.2-bin/lib/jetty-security-9.4.53.v20231009.jar | 9.4.52.v20230823 | 9.4.53.v20231009 | 📦 Version |
| jetty-server @ /apache-zookeeper-3.9.2-bin/lib/jetty-server-9.4.53.v20231009.jar | 9.4.52.v20230823 | 9.4.53.v20231009 | 📦 Version |
| jetty-servlet @ /apache-zookeeper-3.9.2-bin/lib/jetty-servlet-9.4.53.v20231009.jar | 9.4.52.v20230823 | 9.4.53.v20231009 | 📦 Version |
| jetty-util @ /apache-zookeeper-3.9.2-bin/lib/jetty-util-9.4.53.v20231009.jar | 9.4.52.v20230823 | 9.4.53.v20231009 | 📦 Version |
| jetty-util-ajax @ /apache-zookeeper-3.9.2-bin/lib/jetty-util-ajax-9.4.53.v20231009.jar | 9.4.52.v20230823 | 9.4.53.v20231009 | 📦 Version |

</details>

---
*Generated by [sbomlyze](https://github.com/rezmoss/sbomlyze) at 2026-11-09T02:06:32Z*

