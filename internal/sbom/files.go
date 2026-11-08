package sbom

import (
	"encoding/json"
	"strings"
)

// FileEntry: file in an SBOM inventory
type FileEntry struct {
	Path   string            `json:"path"`
	Hashes map[string]string `json:"hashes,omitempty"`
	Layer  string            `json:"layer,omitempty"` // provenance only, not matched
}

// NormalizeFilePath: "bin/ls", "./bin/ls" -> "/bin/ls"
func NormalizeFilePath(p string) string {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "./")
	if p != "" && !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// syftFile: Syft JSON files[] entry
type syftFile struct {
	ID       string `json:"id"`
	Location struct {
		Path    string `json:"path"`
		LayerID string `json:"layerID"`
	} `json:"location"`
	Digests []struct {
		Algorithm string `json:"algorithm"`
		Value     string `json:"value"`
	} `json:"digests"`
}

// parseSyftFiles: inventory + file ID -> path
func parseSyftFiles(raw json.RawMessage) ([]FileEntry, map[string]string) {
	var files []syftFile
	if len(raw) == 0 || json.Unmarshal(raw, &files) != nil {
		return nil, nil
	}
	entries := make([]FileEntry, 0, len(files))
	byID := make(map[string]string, len(files))
	for _, f := range files {
		path := NormalizeFilePath(f.Location.Path)
		if path == "" {
			continue
		}
		e := FileEntry{Path: path, Layer: f.Location.LayerID}
		for _, d := range f.Digests {
			if d.Algorithm != "" && d.Value != "" {
				if e.Hashes == nil {
					e.Hashes = make(map[string]string, len(f.Digests))
				}
				e.Hashes[d.Algorithm] = d.Value
			}
		}
		entries = append(entries, e)
		if f.ID != "" {
			byID[f.ID] = path
		}
	}
	return entries, byID
}

// syftConfigFiles: dpkg conffiles; else unknown
func syftConfigFiles(metadataType string, metadata json.RawMessage) (paths []string, known bool) {
	if metadataType != "dpkg-db-entry" || len(metadata) == 0 {
		return nil, false
	}
	var md struct {
		Files []struct {
			Path         string `json:"path"`
			IsConfigFile bool   `json:"isConfigFile"`
		} `json:"files"`
	}
	if json.Unmarshal(metadata, &md) != nil {
		return nil, false
	}
	for _, f := range md.Files {
		if f.IsConfigFile {
			paths = append(paths, NormalizeFilePath(f.Path))
		}
	}
	return paths, true
}
