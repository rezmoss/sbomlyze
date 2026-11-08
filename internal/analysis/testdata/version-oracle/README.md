Version pairs with the ordering reported by each ecosystem's reference tool
(third column: -1 first is older, 0 equal, 1 first is newer, ERR invalid):

| File | Tool |
|---|---|
| deb.tsv | `dpkg --compare-versions` (debian:12-slim) |
| apk.tsv | `apk version -t` (alpine:3.20) |
| alpm.tsv | `vercmp` (archlinux:base) |
| rpm.tsv | `rpm.labelCompare` (ubi9) |
| gem.tsv | `Gem::Version#<=>` (ruby:3.3.5) |
| maven.tsv | Maven `ComparableVersion` (maven:3.9) |

Pairs come from real image SBOMs (debian, alpine, ubi9, amazonlinux 2023,
archlinux, ruby, zookeeper) plus each tool's known edge cases.
