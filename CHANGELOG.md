# Changelog

## [0.5.2](https://github.com/rezmoss/sbomlyze/compare/v0.5.1...v0.5.2) (2026-08-28)


### Bug Fixes

* **sbom:** guard nil SPDX packages and external refs (crashes found by new fuzzer); upgrade golang.org/x/text to v0.39.0 for GO-2026-5970 ([#50](https://github.com/rezmoss/sbomlyze/issues/50)) ([fdb5e2b](https://github.com/rezmoss/sbomlyze/commit/fdb5e2b99b7d7d162a0c269c7cd6c2da2f48b9c7))

## [0.5.1](https://github.com/rezmoss/sbomlyze/compare/v0.5.0...v0.5.1) (2026-08-09)


### Bug Fixes

* **sarif:** prevent cross-PR alert collisions ([#47](https://github.com/rezmoss/sbomlyze/issues/47)) ([4ade8dd](https://github.com/rezmoss/sbomlyze/commit/4ade8ddd3302ea3e247282f4ce2239d6625b6e5d))

## [0.5.0](https://github.com/rezmoss/sbomlyze/compare/v0.4.0...v0.5.0) (2026-08-09)


### Features

* **action:** add generated SBOM baseline providers ([02b36c3](https://github.com/rezmoss/sbomlyze/commit/02b36c355ccc967caa8aec364172f4724e9e8df0))
* **action:** add generated SBOM baseline providers ([1fcf995](https://github.com/rezmoss/sbomlyze/commit/1fcf9956e881bce60f9870aa484973fc766210b1))


### Bug Fixes

* **action:** correct Syft artifact baseline workflow ([3910c02](https://github.com/rezmoss/sbomlyze/commit/3910c0226072bc9cfbd4694bfb512763d5e36edb))
* **action:** correct Syft artifact baseline workflow ([4f81bdf](https://github.com/rezmoss/sbomlyze/commit/4f81bdfca566d57448489b85dd58d3a2300487ff))

## [0.4.0](https://github.com/rezmoss/sbomlyze/compare/v0.3.7...v0.4.0) (2026-08-09)


### Features

* **action:** add secure SBOM diff GitHub Action MVP ([fc7cbf4](https://github.com/rezmoss/sbomlyze/commit/fc7cbf4284b9704d1691111946a86e5cec30d7ec))
* **action:** add secure SBOM diff GitHub Action MVP ([6f00ac9](https://github.com/rezmoss/sbomlyze/commit/6f00ac9029063e85ec795de2ff501a64b4a832b5))
