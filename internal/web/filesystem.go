package web

import (
	"encoding/json"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// FileEntry represents a single file from the SBOM
type FileEntry struct {
	ID       string       `json:"id"`
	Path     string       `json:"path"`
	LayerID  string       `json:"layerID,omitempty"`
	FileType string       `json:"fileType,omitempty"`
	MimeType string       `json:"mimeType,omitempty"`
	Mode     int          `json:"mode"`
	UserID   int          `json:"userID"`
	GroupID  int          `json:"groupID"`
	Size     int64        `json:"size"`
	Digests  []FileDigest `json:"digests,omitempty"`
	// Component relationships (stored as syft artifact IDs, resolved to component IDs at query time)
	ContainedBy []string `json:"-"` // artifact IDs of components that contain this file
	EvidentFor  []string `json:"-"` // artifact IDs of components this file is evidence for
}

// FileDigest holds a hash algorithm and value
type FileDigest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// DirChild represents an immediate child entry in a directory
type DirChild struct {
	Name  string
	Path  string
	IsDir bool
}

// FileIndex is the pre-built index for fast file browsing
type FileIndex struct {
	Files           []FileEntry       // sorted by path
	PathToIdx       map[string]int    // path → Files index
	DirEntries      map[string][]DirChild // dir path → immediate children
	SearchIndex     []string          // lowercase searchable string per file
	TotalFiles      int
	SyftIDToCompIdx map[string]int    // syft artifact ID → Components index
	// Reverse index: file path → component indices that reference it via Locations
	LocationRefs    map[string][]int
}

// FileBrowseEntry is a single entry in a directory listing
type FileBrowseEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	FileType string `json:"fileType,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	IsDir    bool   `json:"isDir"`
	Size     int64  `json:"size"`
	Mode     int    `json:"mode"`
	Children int    `json:"children,omitempty"`
}

// Breadcrumb represents a path segment for navigation
type Breadcrumb struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// FileBrowseResponse is the API response for directory listing
type FileBrowseResponse struct {
	Entries     []FileBrowseEntry `json:"entries"`
	Total       int               `json:"total"`
	Path        string            `json:"path"`
	Breadcrumbs []Breadcrumb      `json:"breadcrumbs"`
}

// FileComponentRef describes a component's relationship to a file
type FileComponentRef struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Type         string   `json:"type"`
	Relationship string   `json:"relationship"`
	Licenses     []string `json:"licenses,omitempty"`
}

// FileInfoResponse is the API response for file detail
type FileInfoResponse struct {
	File       *FileEntry         `json:"file"`
	Components []FileComponentRef `json:"components"`
}

// buildFileIndex parses the raw Syft JSON files array and relationships
// to build a browsable file index.
func buildFileIndex(rawData []byte, comps []sbom.Component, compIndex map[string]int) *FileIndex {
	// Parse files and artifact relationships from raw JSON
	var doc struct {
		Files []struct {
			ID       string `json:"id"`
			Location struct {
				Path    string `json:"path"`
				LayerID string `json:"layerID"`
			} `json:"location"`
			Metadata *struct {
				Mode     int    `json:"mode"`
				Type     string `json:"type"`
				UserID   int    `json:"userID"`
				GroupID  int    `json:"groupID"`
				MimeType string `json:"mimeType"`
				Size     int64  `json:"size"`
			} `json:"metadata"`
			Digests []struct {
				Algorithm string `json:"algorithm"`
				Value     string `json:"value"`
			} `json:"digests"`
		} `json:"files"`
		Artifacts []struct {
			SyftID   string `json:"id"`
			Name     string `json:"name"`
			Version  string `json:"version"`
			PURL     string `json:"purl"`
			Locations []struct {
				Path string `json:"path"`
			} `json:"locations"`
		} `json:"artifacts"`
		ArtifactRelationships []struct {
			Parent string `json:"parent"`
			Child  string `json:"child"`
			Type   string `json:"type"`
		} `json:"artifactRelationships"`
	}

	if err := json.Unmarshal(rawData, &doc); err != nil {
		return nil
	}

	if len(doc.Files) == 0 && len(doc.Artifacts) == 0 {
		return nil
	}

	// Build syft artifact ID → component index mapping
	syftIDToCompIdx := make(map[string]int, len(doc.Artifacts))
	for _, art := range doc.Artifacts {
		if art.SyftID != "" {
			// Find matching component by name+version+purl
			for i, c := range comps {
				if c.Name == art.Name && c.Version == art.Version && c.PURL == art.PURL {
					syftIDToCompIdx[art.SyftID] = i
					break
				}
			}
		}
	}

	// Build file entries from files array
	fileIDToIdx := make(map[string]int, len(doc.Files))
	pathSeen := make(map[string]bool, len(doc.Files))
	files := make([]FileEntry, 0, len(doc.Files))

	for _, f := range doc.Files {
		if f.Location.Path == "" {
			continue
		}
		entry := FileEntry{
			ID:      f.ID,
			Path:    f.Location.Path,
			LayerID: f.Location.LayerID,
		}
		if f.Metadata != nil {
			entry.Mode = f.Metadata.Mode
			entry.FileType = f.Metadata.Type
			entry.MimeType = f.Metadata.MimeType
			entry.UserID = f.Metadata.UserID
			entry.GroupID = f.Metadata.GroupID
			entry.Size = f.Metadata.Size
		}
		for _, d := range f.Digests {
			entry.Digests = append(entry.Digests, FileDigest{
				Algorithm: d.Algorithm,
				Value:     d.Value,
			})
		}

		fileIDToIdx[f.ID] = len(files)
		pathSeen[f.Location.Path] = true
		files = append(files, entry)
	}

	// Also collect file paths from component Locations that aren't already in the files array
	locationRefs := make(map[string][]int)
	for i, c := range comps {
		for _, loc := range c.Locations {
			locationRefs[loc] = append(locationRefs[loc], i)
			if !pathSeen[loc] {
				pathSeen[loc] = true
				files = append(files, FileEntry{
					Path: loc,
				})
			}
		}
	}

	if len(files) == 0 {
		return nil
	}

	// Process relationships: contains and evident-by link artifacts to files
	for _, rel := range doc.ArtifactRelationships {
		switch rel.Type {
		case "contains":
			if idx, ok := fileIDToIdx[rel.Child]; ok {
				if _, isArt := syftIDToCompIdx[rel.Parent]; isArt {
					files[idx].ContainedBy = append(files[idx].ContainedBy, rel.Parent)
				}
			}
		case "evident-by":
			if idx, ok := fileIDToIdx[rel.Child]; ok {
				if _, isArt := syftIDToCompIdx[rel.Parent]; isArt {
					files[idx].EvidentFor = append(files[idx].EvidentFor, rel.Parent)
				}
			}
		}
	}

	// Sort files by path
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	// Build PathToIdx
	pathToIdx := make(map[string]int, len(files))
	for i, f := range files {
		pathToIdx[f.Path] = i
	}

	// Build DirEntries: group immediate children per directory
	dirChildren := make(map[string]map[string]DirChild)
	dirSet := make(map[string]bool)

	for _, f := range files {
		p := f.Path
		parent := path.Dir(p)
		name := path.Base(p)
		if parent == "." {
			parent = "/"
		}

		if dirChildren[parent] == nil {
			dirChildren[parent] = make(map[string]DirChild)
		}
		dirChildren[parent][name] = DirChild{
			Name:  name,
			Path:  p,
			IsDir: false,
		}

		// Synthesize intermediate directories
		cur := parent
		for cur != "/" && cur != "." && !dirSet[cur] {
			dirSet[cur] = true
			grandparent := path.Dir(cur)
			dirName := path.Base(cur)
			if grandparent == "." {
				grandparent = "/"
			}
			if dirChildren[grandparent] == nil {
				dirChildren[grandparent] = make(map[string]DirChild)
			}
			dirChildren[grandparent][dirName] = DirChild{
				Name:  dirName,
				Path:  cur,
				IsDir: true,
			}
			cur = grandparent
		}
	}

	// Convert map of maps to map of slices
	dirEntries := make(map[string][]DirChild, len(dirChildren))
	for dir, childMap := range dirChildren {
		children := make([]DirChild, 0, len(childMap))
		for _, child := range childMap {
			children = append(children, child)
		}
		sort.Slice(children, func(i, j int) bool {
			// Directories first, then alphabetical
			if children[i].IsDir != children[j].IsDir {
				return children[i].IsDir
			}
			return children[i].Name < children[j].Name
		})
		dirEntries[dir] = children
	}

	// Build search index
	searchIndex := make([]string, len(files))
	for i, f := range files {
		searchIndex[i] = strings.ToLower(f.Path + " " + f.FileType + " " + f.MimeType)
	}

	return &FileIndex{
		Files:           files,
		PathToIdx:       pathToIdx,
		DirEntries:      dirEntries,
		SearchIndex:     searchIndex,
		TotalFiles:      len(files),
		SyftIDToCompIdx: syftIDToCompIdx,
		LocationRefs:    locationRefs,
	}
}

// buildFileIndexFromLocations builds a minimal file index from component Locations only.
// Used for non-Syft formats where there's no files array.
func buildFileIndexFromLocations(comps []sbom.Component, compIndex map[string]int) *FileIndex {
	pathSeen := make(map[string]bool)
	locationRefs := make(map[string][]int)
	var files []FileEntry

	for i, c := range comps {
		for _, loc := range c.Locations {
			locationRefs[loc] = append(locationRefs[loc], i)
			if !pathSeen[loc] {
				pathSeen[loc] = true
				files = append(files, FileEntry{Path: loc})
			}
		}
	}

	if len(files) == 0 {
		return nil
	}

	// Sort
	sort.Slice(files, func(i, j int) bool {
		return files[i].Path < files[j].Path
	})

	pathToIdx := make(map[string]int, len(files))
	for i, f := range files {
		pathToIdx[f.Path] = i
	}

	// Build DirEntries
	dirChildren := make(map[string]map[string]DirChild)
	dirSet := make(map[string]bool)

	for _, f := range files {
		parent := path.Dir(f.Path)
		name := path.Base(f.Path)
		if parent == "." {
			parent = "/"
		}
		if dirChildren[parent] == nil {
			dirChildren[parent] = make(map[string]DirChild)
		}
		dirChildren[parent][name] = DirChild{Name: name, Path: f.Path, IsDir: false}

		cur := parent
		for cur != "/" && cur != "." && !dirSet[cur] {
			dirSet[cur] = true
			gp := path.Dir(cur)
			dn := path.Base(cur)
			if gp == "." {
				gp = "/"
			}
			if dirChildren[gp] == nil {
				dirChildren[gp] = make(map[string]DirChild)
			}
			dirChildren[gp][dn] = DirChild{Name: dn, Path: cur, IsDir: true}
			cur = gp
		}
	}

	dirEntries := make(map[string][]DirChild, len(dirChildren))
	for dir, childMap := range dirChildren {
		children := make([]DirChild, 0, len(childMap))
		for _, child := range childMap {
			children = append(children, child)
		}
		sort.Slice(children, func(i, j int) bool {
			if children[i].IsDir != children[j].IsDir {
				return children[i].IsDir
			}
			return children[i].Name < children[j].Name
		})
		dirEntries[dir] = children
	}

	searchIndex := make([]string, len(files))
	for i, f := range files {
		searchIndex[i] = strings.ToLower(f.Path)
	}

	return &FileIndex{
		Files:           files,
		PathToIdx:       pathToIdx,
		DirEntries:      dirEntries,
		SearchIndex:     searchIndex,
		TotalFiles:      len(files),
		SyftIDToCompIdx: nil,
		LocationRefs:    locationRefs,
	}
}

// handleFilesystem handles GET /api/filesystem?path=/&q=search&offset=0&limit=100
func handleFilesystem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state.mu.RLock()
	defer state.mu.RUnlock()

	if state.FileIndex == nil {
		http.Error(w, "No file data available", http.StatusNotFound)
		return
	}

	idx := state.FileIndex
	query := strings.TrimSpace(r.URL.Query().Get("q"))
	dirPath := r.URL.Query().Get("path")
	if dirPath == "" {
		dirPath = "/"
	}
	offset := parseIntParam(r, "offset", 0)
	limit := parseIntParam(r, "limit", 100)

	var entries []FileBrowseEntry
	var total int

	if query != "" {
		// Search mode: linear scan of search index
		lowerQ := strings.ToLower(query)
		var matches []FileBrowseEntry
		for i, s := range idx.SearchIndex {
			if strings.Contains(s, lowerQ) {
				f := idx.Files[i]
				matches = append(matches, FileBrowseEntry{
					Name:     path.Base(f.Path),
					Path:     f.Path,
					FileType: f.FileType,
					MimeType: f.MimeType,
					IsDir:    false,
					Size:     f.Size,
					Mode:     f.Mode,
				})
			}
		}
		total = len(matches)
		if offset < len(matches) {
			end := offset + limit
			if end > len(matches) {
				end = len(matches)
			}
			entries = matches[offset:end]
		}
	} else {
		// Browse mode: list directory children
		children := idx.DirEntries[dirPath]
		total = len(children)
		if offset < len(children) {
			end := offset + limit
			if end > len(children) {
				end = len(children)
			}
			for _, child := range children[offset:end] {
				entry := FileBrowseEntry{
					Name:  child.Name,
					Path:  child.Path,
					IsDir: child.IsDir,
				}
				if child.IsDir {
					entry.Children = len(idx.DirEntries[child.Path])
				} else if fi, ok := idx.PathToIdx[child.Path]; ok {
					f := idx.Files[fi]
					entry.FileType = f.FileType
					entry.MimeType = f.MimeType
					entry.Size = f.Size
					entry.Mode = f.Mode
				}
				entries = append(entries, entry)
			}
		}
	}

	if entries == nil {
		entries = []FileBrowseEntry{}
	}

	// Build breadcrumbs
	breadcrumbs := buildBreadcrumbs(dirPath)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(FileBrowseResponse{
		Entries:     entries,
		Total:       total,
		Path:        dirPath,
		Breadcrumbs: breadcrumbs,
	})
}

// handleFilesystemInfo handles GET /api/filesystem/info?path=...
func handleFilesystemInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state.mu.RLock()
	defer state.mu.RUnlock()

	if state.FileIndex == nil {
		http.Error(w, "No file data available", http.StatusNotFound)
		return
	}

	filePath := r.URL.Query().Get("path")
	if filePath == "" {
		http.Error(w, "Path required", http.StatusBadRequest)
		return
	}

	idx := state.FileIndex
	fi, ok := idx.PathToIdx[filePath]
	if !ok {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	file := idx.Files[fi]
	var compRefs []FileComponentRef
	seen := make(map[int]bool)

	// Resolve ContainedBy relationships
	for _, artID := range file.ContainedBy {
		if compIdx, ok := idx.SyftIDToCompIdx[artID]; ok && !seen[compIdx] {
			seen[compIdx] = true
			c := state.Components[compIdx]
			compRefs = append(compRefs, FileComponentRef{
				ID:           c.ID,
				Name:         c.Name,
				Version:      c.Version,
				Type:         c.Type,
				Relationship: "contains",
				Licenses:     c.Licenses,
			})
		}
	}

	// Resolve EvidentFor relationships
	for _, artID := range file.EvidentFor {
		if compIdx, ok := idx.SyftIDToCompIdx[artID]; ok && !seen[compIdx] {
			seen[compIdx] = true
			c := state.Components[compIdx]
			compRefs = append(compRefs, FileComponentRef{
				ID:           c.ID,
				Name:         c.Name,
				Version:      c.Version,
				Type:         c.Type,
				Relationship: "evident-by",
				Licenses:     c.Licenses,
			})
		}
	}

	// Resolve Location references
	if refs, ok := idx.LocationRefs[filePath]; ok {
		for _, compIdx := range refs {
			if !seen[compIdx] {
				seen[compIdx] = true
				c := state.Components[compIdx]
				compRefs = append(compRefs, FileComponentRef{
					ID:           c.ID,
					Name:         c.Name,
					Version:      c.Version,
					Type:         c.Type,
					Relationship: "location",
					Licenses:     c.Licenses,
				})
			}
		}
	}

	if compRefs == nil {
		compRefs = []FileComponentRef{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(FileInfoResponse{
		File:       &file,
		Components: compRefs,
	})
}

func buildBreadcrumbs(dirPath string) []Breadcrumb {
	if dirPath == "/" || dirPath == "" {
		return []Breadcrumb{{Name: "/", Path: "/"}}
	}

	crumbs := []Breadcrumb{{Name: "/", Path: "/"}}
	parts := strings.Split(strings.TrimPrefix(dirPath, "/"), "/")
	currentPath := ""
	for _, part := range parts {
		if part == "" {
			continue
		}
		currentPath += "/" + part
		crumbs = append(crumbs, Breadcrumb{Name: part, Path: currentPath})
	}
	return crumbs
}
