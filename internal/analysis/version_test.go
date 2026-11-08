package analysis

import "testing"

func TestClassifyVersionChange(t *testing.T) {
	tests := []struct {
		eco, from, to string
		dir, level    string
	}{
		// FIX-SPEC Bug 1, repro 1
		{"golang", "v0.2.3", "v1.0.0", DirectionUpgrade, LevelMajor},
		{"golang", "v0.69.0", "v1.21.3", DirectionUpgrade, LevelMajor},
		{"golang", "v0.0.0-20230404182410-1ff89d7342da", "v1.0.0", DirectionUpgrade, LevelMajor},
		{"golang", "v4.6.0", "v4.7.0", DirectionUpgrade, LevelMinor},
		{"golang", "v0.9.3", "v0.9.6", DirectionUpgrade, LevelPatch},
		// pseudo-version of an unreleased patch sorts before the release
		{"golang", "v1.36.12-0.20260120151049-f2248ac996af", "v1.36.12", DirectionUpgrade, LevelPrerelease},
		{"golang", "v0.6.3-0.20251027160822-ad3df93bed29", "v0.6.3-0.20260930231756-f19d9717deb0", DirectionUpgrade, LevelPrerelease},
		{"golang", "v29.8.2+incompatible", "v29.9.2+incompatible", DirectionUpgrade, LevelMinor},
		{"golang", "1.5.0", "1.6.0", DirectionUpgrade, LevelMinor},       // SPDX versionInfo without v
		{"golang", "go1.26.8", "go1.27.3", DirectionUpgrade, LevelMinor}, // pkg:golang/stdlib
		{"golang", "v1.2.3", "v1.2.3-rc.1", DirectionDowngrade, LevelPrerelease},
		{"golang", "v1.2.3+meta", "v1.2.3", DirectionNone, LevelNone},
		{"github", "release/v1", "v1.14.3", DirectionUnknown, LevelUnknown},
		{"github", "v4", "v5", DirectionUpgrade, LevelMajor},
		{"github", "UNKNOWN", "v1.0.0", DirectionUnknown, LevelUnknown},

		{"npm", "2.0.0", "10.0.0", DirectionUpgrade, LevelMajor},
		{"npm", "1.2.3", "1.2.3-rc.1", DirectionDowngrade, LevelPrerelease},
		{"npm", "1.2.3+meta", "1.2.3", DirectionNone, LevelNone},
		{"npm", "1.1.2", "1.1.1", DirectionDowngrade, LevelPatch},
		{"npm", "0.132.0", "0.127.0", DirectionDowngrade, LevelMinor},
		{"cargo", "0.3.1", "0.2.17", DirectionDowngrade, LevelMinor},
		{"composer", "v2.1.0", "v2.2.0", DirectionUpgrade, LevelMinor},
		{"composer", "dev-main", "v2.2.0", DirectionUnknown, LevelUnknown},
		{"gem", "1.2.3", "1.2.4", DirectionUpgrade, LevelPatch},
		{"gem", "1.0.0.pre", "1.0.0", DirectionUnknown, LevelUnknown},
		{"gem", "1.2.3.4", "1.2.3.5", DirectionUnknown, LevelUnknown},

		{"swift", "603.0.2", "604.0.0", DirectionUpgrade, LevelMajor},
		{"hex", "1.14.0", "1.15.0-rc.0", DirectionUpgrade, LevelMinor},

		{"pypi", "1.0.0rc1", "1.0.0", DirectionUpgrade, LevelPrerelease},
		{"pypi", "1.0", "1.0.0", DirectionNone, LevelNone},
		{"pypi", "1.0.dev0", "1.0a1", DirectionUpgrade, LevelPrerelease},
		{"pypi", "1.0a1", "1.0b1", DirectionUpgrade, LevelPrerelease},
		{"pypi", "1.0b2", "1.0rc1", DirectionUpgrade, LevelPrerelease},
		{"pypi", "1.0", "1.0.post1", DirectionUpgrade, LevelPrerelease},
		{"pypi", "1.0.post1.dev0", "1.0.post1", DirectionUpgrade, LevelPrerelease},
		{"pypi", "1.0-1", "1.0.post1", DirectionNone, LevelNone},
		{"pypi", "1.0+abc", "1.0+5", DirectionUpgrade, LevelPrerelease},
		{"pypi", "1.0", "1.0+local", DirectionUpgrade, LevelPrerelease},
		{"pypi", "1!0.1", "2.0", DirectionDowngrade, LevelMajor},
		{"pypi", "1.0.0-ALPHA.1", "1.0.0a2", DirectionUpgrade, LevelPrerelease},
		{"pypi", "2.31.0", "2.32.3", DirectionUpgrade, LevelMinor},
		{"pypi", "not a version", "1.0", DirectionUnknown, LevelUnknown},

		// no supported comparator: unknown, never a guessed downgrade
		{"maven", "1.2.3", "1.2.4", DirectionUnknown, LevelUnknown},
		{"deb", "1:2.3-1", "1:2.4-1", DirectionUnknown, LevelUnknown},
		{"unknown", "1.0", "0.9", DirectionUnknown, LevelUnknown},
	}
	for _, tt := range tests {
		dir, level := ClassifyVersionChange(tt.eco, tt.from, tt.to)
		if dir != tt.dir || level != tt.level {
			t.Errorf("%s %s -> %s: got %s/%s, want %s/%s", tt.eco, tt.from, tt.to, dir, level, tt.dir, tt.level)
		}
	}
}
