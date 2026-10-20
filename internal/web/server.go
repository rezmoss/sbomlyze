package web

import (
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"sync"
	"time"

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

	// Loopback only: the API is unauthenticated and holds the uploaded SBOM.
	srv := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", port),
		Handler:           loopbackHostOnly(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServe()
}

// loopbackHostOnly rejects requests whose Host is not a loopback name, so a
// DNS-rebinding page cannot read the API through the user's browser.
func loopbackHostOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.Host)
		if err != nil {
			host = r.Host
		}
		switch host {
		case "localhost", "127.0.0.1", "::1", "[::1]":
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "Forbidden host", http.StatusForbidden)
		}
	})
}
