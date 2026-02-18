package web

import (
	"fmt"
	"io/fs"
	"net/http"
	"sync"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// ServerState holds current SBOM data.
type ServerState struct {
	mu            sync.RWMutex
	Components    []sbom.Component
	Info          sbom.SBOMInfo
	Stats         analysis.Stats
	DepGraph      map[string][]string
	Relationships map[string]int // Syft only
	RawSBOMData   []byte
	CompIndex     map[string]int // ID → index
	SearchIndex   []string       // lowercase search strings
	FileIndex     *FileIndex
}

var state = &ServerState{}

// Serve starts the web server.
func Serve(port int) error {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/upload", handleUpload)
	mux.HandleFunc("/api/tree", handleGetTree)
	mux.HandleFunc("/api/stats", handleGetStats)
	mux.HandleFunc("/api/component/", handleGetComponent)
	mux.HandleFunc("/api/search", handleSearch)
	mux.HandleFunc("/api/filesystem", handleFilesystem)
	mux.HandleFunc("/api/filesystem/info", handleFilesystemInfo)
	mux.HandleFunc("/api/filesystem/stats", handleFilesystemStats)

	// Serve static files
	staticFS, err := fs.Sub(staticFiles, "static")
	if err != nil {
		return fmt.Errorf("failed to create sub filesystem: %w", err)
	}
	mux.Handle("/", http.FileServer(http.FS(staticFS)))

	addr := fmt.Sprintf(":%d", port)
	return http.ListenAndServe(addr, mux)
}
