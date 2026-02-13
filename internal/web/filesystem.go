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

// FileStats holds aggregate statistics about files in the SBOM
type FileStats struct {
	TotalFiles   int            `json:"totalFiles"`
	TotalSize    int64          `json:"totalSize"`
	ByFileType   map[string]int `json:"byFileType"`
	ByMimeType   []TypeCount    `json:"byMimeType"`
	ByExtension  []TypeCount    `json:"byExtension"`
	UnownedFiles int            `json:"unownedFiles"`
}

// TypeCount holds a name/count pair for ranked statistics
type TypeCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// LayerInfo describes a container image layer's file statistics
type LayerInfo struct {
	LayerID   string `json:"layerID"`
	FileCount int    `json:"fileCount"`
	TotalSize int64  `json:"totalSize"`
}

// FileIndex is the pre-built index for fast file browsing
type FileIndex struct {
	Files           []FileEntry        // sorted by path
	PathToIdx       map[string]int     // path → Files index
	DirEntries      map[string][]DirChild // dir path → immediate children
	SearchIndex     []string           // lowercase searchable string per file
	TotalFiles      int
	SyftIDToCompIdx map[string]int     // syft artifact ID → Components index
	// Reverse index: file path → component indices that reference it via Locations
	LocationRefs    map[string][]int
	Stats           *FileStats         // aggregate file statistics
	Layers          []LayerInfo        // ordered unique layers
	LayerToFiles    map[string][]int   // layerID → file indices
	CompToFiles     map[int][]int      // component index → file indices
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
	Layers      []LayerInfo       `json:"layers,omitempty"`
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
	// To avoid O(len(Artifacts) * len(comps)) behavior, first build a lookup
	// from component identity (purl or name+version) to its index, then do
	// O(1) lookups for each artifact.
	buildCompKey := func(name, version, purl string) string {
		if purl != "" {
			return purl
		}
		// Use a delimiter unlikely to appear in name/version to avoid collisions.
		return name + "\x00" + version
	}

	compKeyToIdx := make(map[string]int, len(comps))
	for i, c := range comps {
		key := buildCompKey(c.Name, c.Version, c.PURL)
		if key == "" {
			continue
		}
		// Preserve "first match wins" behavior if duplicates exist.
		if _, exists := compKeyToIdx[key]; !exists {
			compKeyToIdx[key] = i
		}
	}

	syftIDToCompIdx := make(map[string]int, len(doc.Artifacts))
	for _, art := range doc.Artifacts {
		if art.SyftID == "" {
			continue
		}
		key := buildCompKey(art.Name, art.Version, art.PURL)
		if key == "" {
			continue
		}
		if idx, ok := compKeyToIdx[key]; ok {
			syftIDToCompIdx[art.SyftID] = idx
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

	idx := &FileIndex{
		Files:           files,
		PathToIdx:       pathToIdx,
		DirEntries:      dirEntries,
		SearchIndex:     searchIndex,
		TotalFiles:      len(files),
		SyftIDToCompIdx: syftIDToCompIdx,
		LocationRefs:    locationRefs,
		LayerToFiles:    make(map[string][]int),
		CompToFiles:     make(map[int][]int),
	}

	buildLayerIndex(idx)
	buildCompToFiles(idx)
	idx.Stats = computeFileStats(idx)

	return idx
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

	idx := &FileIndex{
		Files:           files,
		PathToIdx:       pathToIdx,
		DirEntries:      dirEntries,
		SearchIndex:     searchIndex,
		TotalFiles:      len(files),
		SyftIDToCompIdx: nil,
		LocationRefs:    locationRefs,
		LayerToFiles:    make(map[string][]int),
		CompToFiles:     make(map[int][]int),
	}

	// Build CompToFiles from LocationRefs
	for filePath, compIndices := range locationRefs {
		if fi, ok := pathToIdx[filePath]; ok {
			for _, compIdx := range compIndices {
				idx.CompToFiles[compIdx] = append(idx.CompToFiles[compIdx], fi)
			}
		}
	}

	idx.Stats = computeFileStats(idx)

	return idx
}

// computeFileStats computes aggregate statistics from the file index in a single pass.
func computeFileStats(idx *FileIndex) *FileStats {
	stats := &FileStats{
		TotalFiles: len(idx.Files),
		ByFileType: make(map[string]int),
	}

	mimeMap := make(map[string]int)
	extMap := make(map[string]int)

	// Build a set of file indices that have component ownership
	ownedFiles := make(map[int]bool)
	for _, fileIndices := range idx.CompToFiles {
		for _, fi := range fileIndices {
			ownedFiles[fi] = true
		}
	}

	for i, f := range idx.Files {
		stats.TotalSize += f.Size

		if f.FileType != "" {
			stats.ByFileType[f.FileType]++
		}
		if f.MimeType != "" {
			mimeMap[f.MimeType]++
		}

		ext := path.Ext(f.Path)
		if ext != "" {
			extMap[ext]++
		}

		// Check ownership: ContainedBy, EvidentFor, or LocationRefs
		if !ownedFiles[i] {
			if _, hasLocRef := idx.LocationRefs[f.Path]; !hasLocRef {
				stats.UnownedFiles++
			}
		}
	}

	stats.ByMimeType = topNTypeCounts(mimeMap, 15)
	stats.ByExtension = topNTypeCounts(extMap, 15)

	return stats
}

// topNTypeCounts converts a map to sorted []TypeCount, keeping at most n entries.
func topNTypeCounts(m map[string]int, n int) []TypeCount {
	counts := make([]TypeCount, 0, len(m))
	for name, count := range m {
		counts = append(counts, TypeCount{Name: name, Count: count})
	}
	sort.Slice(counts, func(i, j int) bool {
		return counts[i].Count > counts[j].Count
	})
	if len(counts) > n {
		counts = counts[:n]
	}
	return counts
}

// buildLayerIndex builds the Layers and LayerToFiles index from the file entries.
func buildLayerIndex(idx *FileIndex) {
	layerOrder := make([]string, 0)
	layerSeen := make(map[string]bool)
	layerSize := make(map[string]int64)

	for i, f := range idx.Files {
		if f.LayerID == "" {
			continue
		}
		if !layerSeen[f.LayerID] {
			layerSeen[f.LayerID] = true
			layerOrder = append(layerOrder, f.LayerID)
		}
		idx.LayerToFiles[f.LayerID] = append(idx.LayerToFiles[f.LayerID], i)
		layerSize[f.LayerID] += f.Size
	}

	idx.Layers = make([]LayerInfo, 0, len(layerOrder))
	for _, lid := range layerOrder {
		idx.Layers = append(idx.Layers, LayerInfo{
			LayerID:   lid,
			FileCount: len(idx.LayerToFiles[lid]),
			TotalSize: layerSize[lid],
		})
	}
}

// buildCompToFiles builds the CompToFiles reverse index from file relationships.
func buildCompToFiles(idx *FileIndex) {
	for i, f := range idx.Files {
		for _, artID := range f.ContainedBy {
			if compIdx, ok := idx.SyftIDToCompIdx[artID]; ok {
				idx.CompToFiles[compIdx] = append(idx.CompToFiles[compIdx], i)
			}
		}
		for _, artID := range f.EvidentFor {
			if compIdx, ok := idx.SyftIDToCompIdx[artID]; ok {
				idx.CompToFiles[compIdx] = append(idx.CompToFiles[compIdx], i)
			}
		}
	}

	// Also include LocationRefs
	for filePath, compIndices := range idx.LocationRefs {
		if fi, ok := idx.PathToIdx[filePath]; ok {
			for _, compIdx := range compIndices {
				idx.CompToFiles[compIdx] = append(idx.CompToFiles[compIdx], fi)
			}
		}
	}

	// Deduplicate file indices per component
	for compIdx, fileIndices := range idx.CompToFiles {
		seen := make(map[int]bool, len(fileIndices))
		deduped := make([]int, 0, len(fileIndices))
		for _, fi := range fileIndices {
			if !seen[fi] {
				seen[fi] = true
				deduped = append(deduped, fi)
			}
		}
		idx.CompToFiles[compIdx] = deduped
	}
}

// handleFilesystem handles GET /api/filesystem?path=/&q=search&offset=0&limit=100&layer=ID&component=ID
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
	layerFilter := r.URL.Query().Get("layer")
	componentFilter := r.URL.Query().Get("component")

	var entries []FileBrowseEntry
	var total int

	// Determine which file indices to search based on filters
	var filterSet map[int]bool

	if componentFilter != "" {
		// Look up component index
		if compIdx, ok := state.CompIndex[componentFilter]; ok {
			filterSet = make(map[int]bool)
			for _, fi := range idx.CompToFiles[compIdx] {
				filterSet[fi] = true
			}
		} else {
			filterSet = make(map[int]bool) // empty → no results
		}
	}

	if layerFilter != "" {
		layerFiles := make(map[int]bool)
		for _, fi := range idx.LayerToFiles[layerFilter] {
			layerFiles[fi] = true
		}
		if filterSet != nil {
			// Intersect with component filter
			intersect := make(map[int]bool)
			for fi := range filterSet {
				if layerFiles[fi] {
					intersect[fi] = true
				}
			}
			filterSet = intersect
		} else {
			filterSet = layerFiles
		}
	}

	if filterSet != nil || query != "" {
		// Filtered or search mode: build flat list from matching files
		var matches []FileBrowseEntry

		if query != "" && isGlobPattern(query) {
			// Glob search
			for i, f := range idx.Files {
				if filterSet != nil && !filterSet[i] {
					continue
				}
				if matchGlob(query, f.Path) {
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
		} else if query != "" {
			// Substring search
			lowerQ := strings.ToLower(query)
			for i, s := range idx.SearchIndex {
				if filterSet != nil && !filterSet[i] {
					continue
				}
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
		} else {
			// Filter only (no search query): flat list of filtered files
			sortedIndices := make([]int, 0, len(filterSet))
			for fi := range filterSet {
				sortedIndices = append(sortedIndices, fi)
			}
			sort.Ints(sortedIndices)
			for _, fi := range sortedIndices {
				f := idx.Files[fi]
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

	resp := FileBrowseResponse{
		Entries:     entries,
		Total:       total,
		Path:        dirPath,
		Breadcrumbs: breadcrumbs,
	}

	// Include layer info when available
	if len(idx.Layers) > 0 {
		resp.Layers = idx.Layers
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
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

// isGlobPattern returns true if the query contains glob metacharacters.
func isGlobPattern(q string) bool {
	return strings.ContainsAny(q, "*?[")
}

// matchGlob matches a file path against a glob pattern.
// If the pattern doesn't start with /, it matches against the base name.
// If it starts with / and contains **, it uses doublestar matching.
// Otherwise it uses path.Match against the full path.
func matchGlob(pattern, filePath string) bool {
	if !strings.HasPrefix(pattern, "/") {
		// Match against base name only
		matched, _ := path.Match(pattern, path.Base(filePath))
		return matched
	}

	if strings.Contains(pattern, "**") {
		return matchDoublestar(pattern, filePath)
	}

	matched, _ := path.Match(pattern, filePath)
	return matched
}

// matchDoublestar handles ** glob patterns that match across path separators.
func matchDoublestar(pattern, filePath string) bool {
	// Split on ** to get segments
	parts := strings.SplitN(pattern, "**", 2)
	prefix := parts[0]
	suffix := ""
	if len(parts) > 1 {
		suffix = parts[1]
	}

	// Check prefix
	if prefix != "" && prefix != "/" {
		if !strings.HasPrefix(filePath, prefix) {
			return false
		}
	}

	// Check suffix
	if suffix != "" && suffix != "/" {
		// Remove leading slash from suffix for matching
		suffix = strings.TrimPrefix(suffix, "/")
		if suffix == "" {
			return true
		}
		// Check if any suffix of filePath matches the pattern suffix
		remaining := strings.TrimPrefix(filePath, prefix)
		pathParts := strings.Split(remaining, "/")
		for i := range pathParts {
			candidate := strings.Join(pathParts[i:], "/")
			matched, _ := path.Match(suffix, candidate)
			if matched {
				return true
			}
			// Also try matching just the last segment
			if i == len(pathParts)-1 {
				matched, _ = path.Match(suffix, pathParts[i])
				if matched {
					return true
				}
			}
		}
		return false
	}

	return true
}

// handleFilesystemStats handles GET /api/filesystem/stats
func handleFilesystemStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state.mu.RLock()
	defer state.mu.RUnlock()

	if state.FileIndex == nil || state.FileIndex.Stats == nil {
		http.Error(w, "No file data available", http.StatusNotFound)
		return
	}

	idx := state.FileIndex
	resp := struct {
		*FileStats
		Layers []LayerInfo `json:"layers,omitempty"`
	}{
		FileStats: idx.Stats,
		Layers:    idx.Layers,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
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
