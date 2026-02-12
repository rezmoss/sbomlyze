package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// --- Helper: build a test FileIndex with known data ---

func buildTestFileIndex() *FileIndex {
	comps := []sbom.Component{
		{ID: "comp-a", Name: "libfoo", Version: "1.0", PURL: "pkg:deb/libfoo@1.0"},
		{ID: "comp-b", Name: "libbar", Version: "2.0", PURL: "pkg:deb/libbar@2.0"},
		{ID: "comp-c", Name: "myapp", Version: "3.0", PURL: "pkg:golang/myapp@3.0", Locations: []string{"/usr/bin/myapp"}},
	}
	compIndex := buildCompIndex(comps)

	files := []FileEntry{
		{ID: "f1", Path: "/etc/config.yaml", LayerID: "layer-aaa", FileType: "RegularFile", MimeType: "text/plain", Size: 1024, ContainedBy: []string{"syft-a"}},
		{ID: "f2", Path: "/etc/config.json", LayerID: "layer-aaa", FileType: "RegularFile", MimeType: "application/json", Size: 2048},
		{ID: "f3", Path: "/usr/lib/libfoo.so", LayerID: "layer-bbb", FileType: "RegularFile", MimeType: "application/x-sharedlib", Size: 50000, ContainedBy: []string{"syft-a"}},
		{ID: "f4", Path: "/usr/lib/libbar.so", LayerID: "layer-bbb", FileType: "RegularFile", MimeType: "application/x-sharedlib", Size: 30000, EvidentFor: []string{"syft-b"}},
		{ID: "f5", Path: "/usr/bin/myapp", LayerID: "layer-ccc", FileType: "RegularFile", MimeType: "application/x-executable", Size: 100000},
		{ID: "f6", Path: "/var/log/app.log", LayerID: "layer-ccc", FileType: "RegularFile", MimeType: "text/plain", Size: 5000},
		{ID: "f7", Path: "/tmp/link", LayerID: "layer-ccc", FileType: "SymbolicLink", Size: 0},
		{ID: "f8", Path: "/opt/app.jar", LayerID: "layer-bbb", FileType: "RegularFile", MimeType: "application/java-archive", Size: 70000, ContainedBy: []string{"syft-a", "syft-b"}},
	}

	// Sort by path (they should be sorted for the index)
	// Already roughly sorted, but let's be sure the index builder handles it

	pathToIdx := make(map[string]int, len(files))
	for i, f := range files {
		pathToIdx[f.Path] = i
	}

	searchIndex := make([]string, len(files))
	for i, f := range files {
		searchIndex[i] = f.Path + " " + f.FileType + " " + f.MimeType
	}

	syftIDToCompIdx := map[string]int{
		"syft-a": 0, // comp-a / libfoo
		"syft-b": 1, // comp-b / libbar
	}

	locationRefs := map[string][]int{
		"/usr/bin/myapp": {2}, // comp-c
	}

	// Build directory entries manually for browse tests
	dirEntries := map[string][]DirChild{
		"/": {
			{Name: "etc", Path: "/etc", IsDir: true},
			{Name: "opt", Path: "/opt", IsDir: true},
			{Name: "tmp", Path: "/tmp", IsDir: true},
			{Name: "usr", Path: "/usr", IsDir: true},
			{Name: "var", Path: "/var", IsDir: true},
		},
		"/etc": {
			{Name: "config.json", Path: "/etc/config.json", IsDir: false},
			{Name: "config.yaml", Path: "/etc/config.yaml", IsDir: false},
		},
		"/usr/lib": {
			{Name: "libbar.so", Path: "/usr/lib/libbar.so", IsDir: false},
			{Name: "libfoo.so", Path: "/usr/lib/libfoo.so", IsDir: false},
		},
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

	// Set global state for handler tests
	state.mu.Lock()
	state.Components = comps
	state.CompIndex = compIndex
	state.FileIndex = idx
	state.mu.Unlock()

	return idx
}

// ============================================================
// Unit tests for isGlobPattern
// ============================================================

func TestIsGlobPattern(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"*.jar", true},
		{"/etc/**", true},
		{"config.yaml", false},
		{"lib[ab].so", true},
		{"/usr/lib/libfoo.so", false},
		{"?onfig", true},
		{"", false},
	}
	for _, tt := range tests {
		got := isGlobPattern(tt.input)
		if got != tt.want {
			t.Errorf("isGlobPattern(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

// ============================================================
// Unit tests for matchGlob
// ============================================================

func TestMatchGlob(t *testing.T) {
	tests := []struct {
		pattern  string
		filePath string
		want     bool
	}{
		// Base name matching (no leading /)
		{"*.jar", "/opt/app.jar", true},
		{"*.jar", "/usr/lib/libfoo.so", false},
		{"*.so", "/usr/lib/libfoo.so", true},
		{"config.*", "/etc/config.yaml", true},
		{"config.*", "/etc/other.yaml", false},

		// Full path matching (leading /)
		{"/etc/*.yaml", "/etc/config.yaml", true},
		{"/etc/*.yaml", "/etc/config.json", false},
		{"/etc/*.yaml", "/var/config.yaml", false},

		// Doublestar matching
		{"/etc/**", "/etc/config.yaml", true},
		{"/etc/**", "/etc/sub/deep/file.txt", true},
		{"/etc/**", "/var/log/file.txt", false},
		{"/usr/**", "/usr/lib/libfoo.so", true},
		{"/usr/**", "/usr/bin/myapp", true},

		// Edge cases
		{"*", "/any/file.txt", true},
		{"*.log", "/var/log/app.log", true},
	}
	for _, tt := range tests {
		got := matchGlob(tt.pattern, tt.filePath)
		if got != tt.want {
			t.Errorf("matchGlob(%q, %q) = %v, want %v", tt.pattern, tt.filePath, got, tt.want)
		}
	}
}

// ============================================================
// Unit tests for topNTypeCounts
// ============================================================

func TestTopNTypeCounts(t *testing.T) {
	t.Run("sorts descending and limits", func(t *testing.T) {
		m := map[string]int{"a": 10, "b": 30, "c": 20, "d": 5}
		result := topNTypeCounts(m, 2)
		if len(result) != 2 {
			t.Fatalf("expected 2 results, got %d", len(result))
		}
		if result[0].Name != "b" || result[0].Count != 30 {
			t.Errorf("expected first={b,30}, got {%s,%d}", result[0].Name, result[0].Count)
		}
		if result[1].Name != "c" || result[1].Count != 20 {
			t.Errorf("expected second={c,20}, got {%s,%d}", result[1].Name, result[1].Count)
		}
	})

	t.Run("handles empty map", func(t *testing.T) {
		result := topNTypeCounts(map[string]int{}, 10)
		if len(result) != 0 {
			t.Errorf("expected empty result, got %d", len(result))
		}
	})

	t.Run("n larger than map", func(t *testing.T) {
		m := map[string]int{"x": 1, "y": 2}
		result := topNTypeCounts(m, 10)
		if len(result) != 2 {
			t.Errorf("expected 2 results, got %d", len(result))
		}
	})
}

// ============================================================
// Unit tests for computeFileStats
// ============================================================

func TestComputeFileStats(t *testing.T) {
	resetState()
	idx := buildTestFileIndex()

	stats := idx.Stats
	if stats == nil {
		t.Fatal("expected non-nil stats")
	}

	if stats.TotalFiles != 8 {
		t.Errorf("expected 8 total files, got %d", stats.TotalFiles)
	}

	expectedSize := int64(1024 + 2048 + 50000 + 30000 + 100000 + 5000 + 0 + 70000)
	if stats.TotalSize != expectedSize {
		t.Errorf("expected total size %d, got %d", expectedSize, stats.TotalSize)
	}

	// Check file type counts
	if stats.ByFileType["RegularFile"] != 7 {
		t.Errorf("expected 7 RegularFile, got %d", stats.ByFileType["RegularFile"])
	}
	if stats.ByFileType["SymbolicLink"] != 1 {
		t.Errorf("expected 1 SymbolicLink, got %d", stats.ByFileType["SymbolicLink"])
	}

	// Check MIME types are populated
	if len(stats.ByMimeType) == 0 {
		t.Error("expected non-empty ByMimeType")
	}

	// Check extensions are populated
	if len(stats.ByExtension) == 0 {
		t.Error("expected non-empty ByExtension")
	}

	// Unowned files: f2 (/etc/config.json), f6 (/var/log/app.log), f7 (/tmp/link)
	// have no ContainedBy, no EvidentFor, and no LocationRefs
	if stats.UnownedFiles != 3 {
		t.Errorf("expected 3 unowned files, got %d", stats.UnownedFiles)
	}
}

// ============================================================
// Unit tests for buildLayerIndex
// ============================================================

func TestBuildLayerIndex(t *testing.T) {
	resetState()
	idx := buildTestFileIndex()

	if len(idx.Layers) != 3 {
		t.Fatalf("expected 3 layers, got %d", len(idx.Layers))
	}

	// layer-aaa has f1, f2
	if idx.Layers[0].LayerID != "layer-aaa" {
		t.Errorf("expected first layer=layer-aaa, got %s", idx.Layers[0].LayerID)
	}
	if idx.Layers[0].FileCount != 2 {
		t.Errorf("expected layer-aaa to have 2 files, got %d", idx.Layers[0].FileCount)
	}

	// Verify LayerToFiles mapping
	if len(idx.LayerToFiles["layer-aaa"]) != 2 {
		t.Errorf("expected 2 files in layer-aaa, got %d", len(idx.LayerToFiles["layer-aaa"]))
	}
	if len(idx.LayerToFiles["layer-bbb"]) != 3 {
		t.Errorf("expected 3 files in layer-bbb, got %d", len(idx.LayerToFiles["layer-bbb"]))
	}
	if len(idx.LayerToFiles["layer-ccc"]) != 3 {
		t.Errorf("expected 3 files in layer-ccc, got %d", len(idx.LayerToFiles["layer-ccc"]))
	}
}

// ============================================================
// Unit tests for buildCompToFiles
// ============================================================

func TestBuildCompToFiles(t *testing.T) {
	resetState()
	idx := buildTestFileIndex()

	// comp-a (index 0) via syft-a: ContainedBy in f1, f3, f8
	compAFiles := idx.CompToFiles[0]
	if len(compAFiles) != 3 {
		t.Errorf("expected comp-a to have 3 files, got %d", len(compAFiles))
	}

	// comp-b (index 1) via syft-b: EvidentFor in f4, ContainedBy in f8
	compBFiles := idx.CompToFiles[1]
	if len(compBFiles) != 2 {
		t.Errorf("expected comp-b to have 2 files, got %d", len(compBFiles))
	}

	// comp-c (index 2) via LocationRefs on /usr/bin/myapp
	compCFiles := idx.CompToFiles[2]
	if len(compCFiles) != 1 {
		t.Errorf("expected comp-c to have 1 file, got %d", len(compCFiles))
	}
}

// ============================================================
// Handler test: handleFilesystemStats
// ============================================================

func TestHandleFilesystemStats(t *testing.T) {
	t.Run("returns stats when data available", func(t *testing.T) {
		resetState()
		buildTestFileIndex()

		req := httptest.NewRequest(http.MethodGet, "/api/filesystem/stats", nil)
		rr := httptest.NewRecorder()
		handleFilesystemStats(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
		}

		var resp struct {
			TotalFiles   int            `json:"totalFiles"`
			TotalSize    int64          `json:"totalSize"`
			ByFileType   map[string]int `json:"byFileType"`
			ByMimeType   []TypeCount    `json:"byMimeType"`
			ByExtension  []TypeCount    `json:"byExtension"`
			UnownedFiles int            `json:"unownedFiles"`
			Layers       []LayerInfo    `json:"layers"`
		}
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if resp.TotalFiles != 8 {
			t.Errorf("expected 8 total files, got %d", resp.TotalFiles)
		}
		if len(resp.Layers) != 3 {
			t.Errorf("expected 3 layers, got %d", len(resp.Layers))
		}
		if len(resp.ByFileType) == 0 {
			t.Error("expected non-empty ByFileType")
		}
	})

	t.Run("returns 404 when no file data", func(t *testing.T) {
		resetState()

		req := httptest.NewRequest(http.MethodGet, "/api/filesystem/stats", nil)
		rr := httptest.NewRecorder()
		handleFilesystemStats(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("expected 404, got %d", rr.Code)
		}
	})

	t.Run("rejects non-GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/filesystem/stats", nil)
		rr := httptest.NewRecorder()
		handleFilesystemStats(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("expected 405, got %d", rr.Code)
		}
	})
}

// ============================================================
// Handler test: handleFilesystem with layer filter
// ============================================================

func TestHandleFilesystem_LayerFilter(t *testing.T) {
	resetState()
	buildTestFileIndex()

	req := httptest.NewRequest(http.MethodGet, "/api/filesystem?layer=layer-aaa", nil)
	rr := httptest.NewRecorder()
	handleFilesystem(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp FileBrowseResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// layer-aaa has 2 files: /etc/config.yaml, /etc/config.json
	if resp.Total != 2 {
		t.Errorf("expected 2 files for layer-aaa, got %d", resp.Total)
	}

	// All entries should be files (flat list), not directories
	for _, e := range resp.Entries {
		if e.IsDir {
			t.Errorf("expected flat file list, got directory entry: %s", e.Name)
		}
	}
}

func TestHandleFilesystem_LayerFilterEmpty(t *testing.T) {
	resetState()
	buildTestFileIndex()

	req := httptest.NewRequest(http.MethodGet, "/api/filesystem?layer=nonexistent", nil)
	rr := httptest.NewRecorder()
	handleFilesystem(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp FileBrowseResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if resp.Total != 0 {
		t.Errorf("expected 0 files for nonexistent layer, got %d", resp.Total)
	}
}

// ============================================================
// Handler test: handleFilesystem with component filter
// ============================================================

func TestHandleFilesystem_ComponentFilter(t *testing.T) {
	resetState()
	buildTestFileIndex()

	// comp-a has 3 files via ContainedBy(syft-a)
	req := httptest.NewRequest(http.MethodGet, "/api/filesystem?component=comp-a", nil)
	rr := httptest.NewRecorder()
	handleFilesystem(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp FileBrowseResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if resp.Total != 3 {
		t.Errorf("expected 3 files for comp-a, got %d", resp.Total)
	}
}

func TestHandleFilesystem_ComponentFilterViaLocation(t *testing.T) {
	resetState()
	buildTestFileIndex()

	// comp-c has 1 file via LocationRefs
	req := httptest.NewRequest(http.MethodGet, "/api/filesystem?component=comp-c", nil)
	rr := httptest.NewRecorder()
	handleFilesystem(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp FileBrowseResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if resp.Total != 1 {
		t.Errorf("expected 1 file for comp-c, got %d", resp.Total)
	}
	if len(resp.Entries) > 0 && resp.Entries[0].Name != "myapp" {
		t.Errorf("expected file myapp, got %s", resp.Entries[0].Name)
	}
}

// ============================================================
// Handler test: handleFilesystem with combined filters
// ============================================================

func TestHandleFilesystem_LayerAndComponentFilter(t *testing.T) {
	resetState()
	buildTestFileIndex()

	// comp-a has files in layer-aaa (/etc/config.yaml) and layer-bbb (/usr/lib/libfoo.so, /opt/app.jar)
	// Filtering by layer-bbb AND comp-a should give 2 files
	req := httptest.NewRequest(http.MethodGet, "/api/filesystem?component=comp-a&layer=layer-bbb", nil)
	rr := httptest.NewRecorder()
	handleFilesystem(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp FileBrowseResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if resp.Total != 2 {
		t.Errorf("expected 2 files for comp-a in layer-bbb, got %d", resp.Total)
	}
}

// ============================================================
// Handler test: handleFilesystem with glob search
// ============================================================

func TestHandleFilesystem_GlobSearch(t *testing.T) {
	t.Run("basename glob *.so", func(t *testing.T) {
		resetState()
		buildTestFileIndex()

		req := httptest.NewRequest(http.MethodGet, "/api/filesystem?q=*.so", nil)
		rr := httptest.NewRecorder()
		handleFilesystem(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}

		var resp FileBrowseResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if resp.Total != 2 {
			t.Errorf("expected 2 .so files, got %d", resp.Total)
		}
	})

	t.Run("basename glob *.jar", func(t *testing.T) {
		resetState()
		buildTestFileIndex()

		req := httptest.NewRequest(http.MethodGet, "/api/filesystem?q=*.jar", nil)
		rr := httptest.NewRecorder()
		handleFilesystem(rr, req)

		var resp FileBrowseResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if resp.Total != 1 {
			t.Errorf("expected 1 .jar file, got %d", resp.Total)
		}
	})

	t.Run("full path glob /etc/*", func(t *testing.T) {
		resetState()
		buildTestFileIndex()

		req := httptest.NewRequest(http.MethodGet, "/api/filesystem?q=/etc/*", nil)
		rr := httptest.NewRecorder()
		handleFilesystem(rr, req)

		var resp FileBrowseResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if resp.Total != 2 {
			t.Errorf("expected 2 files in /etc/*, got %d", resp.Total)
		}
	})

	t.Run("doublestar /usr/**", func(t *testing.T) {
		resetState()
		buildTestFileIndex()

		req := httptest.NewRequest(http.MethodGet, "/api/filesystem?q=/usr/**", nil)
		rr := httptest.NewRecorder()
		handleFilesystem(rr, req)

		var resp FileBrowseResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		// /usr/lib/libfoo.so, /usr/lib/libbar.so, /usr/bin/myapp
		if resp.Total != 3 {
			t.Errorf("expected 3 files under /usr/**, got %d", resp.Total)
		}
	})

	t.Run("no glob match", func(t *testing.T) {
		resetState()
		buildTestFileIndex()

		req := httptest.NewRequest(http.MethodGet, "/api/filesystem?q=*.xyz", nil)
		rr := httptest.NewRecorder()
		handleFilesystem(rr, req)

		var resp FileBrowseResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse: %v", err)
		}

		if resp.Total != 0 {
			t.Errorf("expected 0 matches for *.xyz, got %d", resp.Total)
		}
	})
}

// ============================================================
// Handler test: handleFilesystem with glob + layer filter
// ============================================================

func TestHandleFilesystem_GlobWithLayerFilter(t *testing.T) {
	resetState()
	buildTestFileIndex()

	// *.so files in layer-bbb only
	req := httptest.NewRequest(http.MethodGet, "/api/filesystem?q=*.so&layer=layer-bbb", nil)
	rr := httptest.NewRecorder()
	handleFilesystem(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp FileBrowseResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	// Both .so files are in layer-bbb
	if resp.Total != 2 {
		t.Errorf("expected 2 .so files in layer-bbb, got %d", resp.Total)
	}
}

// ============================================================
// Handler test: handleFilesystem includes layers in response
// ============================================================

func TestHandleFilesystem_IncludesLayers(t *testing.T) {
	resetState()
	buildTestFileIndex()

	req := httptest.NewRequest(http.MethodGet, "/api/filesystem?path=/", nil)
	rr := httptest.NewRecorder()
	handleFilesystem(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp FileBrowseResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if len(resp.Layers) != 3 {
		t.Errorf("expected 3 layers in response, got %d", len(resp.Layers))
	}
}

// ============================================================
// Handler test: handleFilesystem substring search still works
// ============================================================

func TestHandleFilesystem_SubstringSearch(t *testing.T) {
	resetState()
	buildTestFileIndex()

	req := httptest.NewRequest(http.MethodGet, "/api/filesystem?q=config", nil)
	rr := httptest.NewRecorder()
	handleFilesystem(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp FileBrowseResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if resp.Total != 2 {
		t.Errorf("expected 2 config files, got %d", resp.Total)
	}
}

// ============================================================
// Handler test: handleGetComponent returns fileCount
// ============================================================

func TestHandleGetComponent_FileCount(t *testing.T) {
	resetState()
	buildTestFileIndex()

	req := httptest.NewRequest(http.MethodGet, "/api/component/comp-a", nil)
	rr := httptest.NewRecorder()
	handleGetComponent(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var detail ComponentDetail
	if err := json.Unmarshal(rr.Body.Bytes(), &detail); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if detail.FileCount != 3 {
		t.Errorf("expected fileCount=3 for comp-a, got %d", detail.FileCount)
	}
}

func TestHandleGetComponent_FileCountZero(t *testing.T) {
	resetState()
	loadTestState([]sbom.Component{
		{ID: "comp-x", Name: "nofiles", Version: "1.0"},
	}, sbom.SBOMInfo{})

	req := httptest.NewRequest(http.MethodGet, "/api/component/comp-x", nil)
	rr := httptest.NewRecorder()
	handleGetComponent(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var detail ComponentDetail
	if err := json.Unmarshal(rr.Body.Bytes(), &detail); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}

	if detail.FileCount != 0 {
		t.Errorf("expected fileCount=0, got %d", detail.FileCount)
	}
}

// ============================================================
// Unit tests for buildFileIndex integration
// ============================================================

func TestBuildFileIndex_WithSyftData(t *testing.T) {
	comps := []sbom.Component{
		{ID: "c1", Name: "pkg1", Version: "1.0", PURL: "pkg:deb/pkg1@1.0"},
	}
	compIndex := buildCompIndex(comps)

	rawData := []byte(`{
		"files": [
			{
				"id": "file1",
				"location": {"path": "/usr/bin/app", "layerID": "sha256:abc123"},
				"metadata": {"type": "RegularFile", "mimeType": "application/x-executable", "size": 1000, "mode": 493}
			},
			{
				"id": "file2",
				"location": {"path": "/etc/app.conf", "layerID": "sha256:def456"},
				"metadata": {"type": "RegularFile", "mimeType": "text/plain", "size": 200}
			}
		],
		"artifacts": [
			{
				"id": "syft-1",
				"name": "pkg1",
				"version": "1.0",
				"purl": "pkg:deb/pkg1@1.0",
				"locations": [{"path": "/usr/bin/app"}]
			}
		],
		"artifactRelationships": [
			{"parent": "syft-1", "child": "file1", "type": "contains"}
		]
	}`)

	idx := buildFileIndex(rawData, comps, compIndex)
	if idx == nil {
		t.Fatal("expected non-nil index")
	}

	// Stats should be computed
	if idx.Stats == nil {
		t.Fatal("expected non-nil stats")
	}
	if idx.Stats.TotalFiles != 2 {
		t.Errorf("expected 2 files, got %d", idx.Stats.TotalFiles)
	}

	// Layers should be built
	if len(idx.Layers) != 2 {
		t.Errorf("expected 2 layers, got %d", len(idx.Layers))
	}

	// CompToFiles should be built
	if len(idx.CompToFiles[0]) == 0 {
		t.Error("expected comp 0 to have files")
	}

	// Unowned: /etc/app.conf has no relationship
	if idx.Stats.UnownedFiles != 1 {
		t.Errorf("expected 1 unowned file, got %d", idx.Stats.UnownedFiles)
	}
}

func TestBuildFileIndexFromLocations_Stats(t *testing.T) {
	comps := []sbom.Component{
		{ID: "c1", Name: "pkg1", Version: "1.0", Locations: []string{"/opt/lib.jar"}},
		{ID: "c2", Name: "pkg2", Version: "2.0", Locations: []string{"/opt/lib.jar", "/opt/app.war"}},
	}
	compIndex := buildCompIndex(comps)

	idx := buildFileIndexFromLocations(comps, compIndex)
	if idx == nil {
		t.Fatal("expected non-nil index")
	}

	if idx.Stats == nil {
		t.Fatal("expected non-nil stats")
	}

	if idx.Stats.TotalFiles != 2 {
		t.Errorf("expected 2 files, got %d", idx.Stats.TotalFiles)
	}

	// Both files have location refs, so no unowned
	if idx.Stats.UnownedFiles != 0 {
		t.Errorf("expected 0 unowned files, got %d", idx.Stats.UnownedFiles)
	}

	// CompToFiles should work
	if len(idx.CompToFiles) != 2 {
		t.Errorf("expected 2 components in CompToFiles, got %d", len(idx.CompToFiles))
	}
}
