package analysis

import (
	"path"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// Syft package type -> PURL type
var syftPkgTypes = map[string]string{
	"rust-crate": "cargo", "go-module": "golang", "npm": "npm", "python": "pypi",
	"gem": "gem", "java-archive": "maven", "jenkins-plugin": "maven", "deb": "deb",
	"rpm": "rpm", "apk": "apk", "alpm": "alpm", "php-composer": "composer",
	"swift": "swift", "hex": "hex", "dart-pub": "pub", "github-action": "github",
	"github-action-workflow": "github",
}

// CPE 2.3 target_sw -> PURL type
var cpeTargetSW = map[string]string{
	"rust": "cargo", "go": "golang", "golang": "golang", "node.js": "npm",
	"python": "pypi", "ruby": "gem", "rails": "gem", "maven": "maven",
}

// lockfile/manifest name -> PURL type
var manifestEcosystems = map[string]string{
	"Cargo.lock": "cargo", "Cargo.toml": "cargo", "go.mod": "golang", "go.sum": "golang",
	"package-lock.json": "npm", "npm-shrinkwrap.json": "npm", "yarn.lock": "npm", "pnpm-lock.yaml": "npm",
	"poetry.lock": "pypi", "uv.lock": "pypi", "Pipfile.lock": "pypi", "pdm.lock": "pypi",
	"Gemfile.lock": "gem", "composer.lock": "composer", "pom.xml": "maven",
	"Package.resolved": "swift", "mix.lock": "hex", "pubspec.lock": "pub",
}

// Ecosystem: PURL, else Syft type, CPE, lockfile
func Ecosystem(c sbom.Component) string {
	if t := ExtractPURLType(c.PURL); t != "unknown" {
		return t
	}
	if t, ok := syftPkgTypes[c.PkgType]; ok {
		return t
	}
	for _, cpe := range c.CPEs {
		if parts := strings.Split(cpe, ":"); strings.HasPrefix(cpe, "cpe:2.3:") && len(parts) > 10 {
			if t, ok := cpeTargetSW[strings.ToLower(parts[10])]; ok {
				return t
			}
		}
	}
	for _, loc := range c.Locations {
		if t, ok := manifestEcosystems[path.Base(loc)]; ok {
			return t
		}
	}
	return "unknown"
}
