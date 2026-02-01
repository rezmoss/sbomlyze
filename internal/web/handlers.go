package web

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strings"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/sbom"
)

// TreeNode represents a node in the dependency tree
type TreeNode struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Version      string     `json:"version"`
	Type         string     `json:"type"`
	Children     []TreeNode `json:"children,omitempty"`
	HasChildren  bool       `json:"hasChildren"`
	ChildrenIDs  []string   `json:"childrenIds,omitempty"`
}

// ComponentDetail provides detailed info about a component
type ComponentDetail struct {
	ID           string            `json:"id"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	PURL         string            `json:"purl,omitempty"`
	Type         string            `json:"type"`
	Licenses     []string          `json:"licenses,omitempty"`
	Hashes       map[string]string `json:"hashes,omitempty"`
	Dependencies []string          `json:"dependencies,omitempty"`
	Supplier     string            `json:"supplier,omitempty"`
	RawJSON      json.RawMessage   `json:"rawJson,omitempty"`
}

func handleUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form (max 50MB)
	if err := r.ParseMultipartForm(50 << 20); err != nil {
		http.Error(w, "Failed to parse form: "+err.Error(), http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get file: "+err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read file: "+err.Error(), http.StatusBadRequest)
		return
	}

	var comps []sbom.Component
	var info sbom.SBOMInfo

	// Use existing format detection and parsing
	if sbom.IsCycloneDX(data) {
		comps, info, err = sbom.ParseCycloneDXWithInfo(data)
	} else if sbom.IsSyft(data) {
		comps, info, err = sbom.ParseSyftWithInfo(data)
	} else if sbom.IsSPDX(data) {
		comps, err = sbom.ParseSPDXFromBytes(data)
	} else {
		http.Error(w, "Unknown SBOM format", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, "Failed to parse SBOM: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Normalize components
	comps = sbom.NormalizeComponents(comps)

	// Compute stats and dependency graph
	stats := analysis.ComputeStats(comps)
	depGraph := analysis.BuildDependencyGraph(comps)

	// Extract relationship statistics (Syft format)
	relationships := extractRelationships(data)

	// Store in server state
	state.mu.Lock()
	state.Components = comps
	state.Info = info
	state.Stats = stats
	state.DepGraph = depGraph
	state.Relationships = relationships
	state.RawSBOMData = data
	state.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"components": len(comps),
		"info":       info,
	})
}

func handleGetTree(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state.mu.RLock()
	defer state.mu.RUnlock()

	if len(state.Components) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]TreeNode{})
		return
	}

	// Build component lookup map
	compMap := make(map[string]sbom.Component)
	for _, c := range state.Components {
		compMap[c.ID] = c
	}

	// Find root nodes using exported FindRoots
	roots := analysis.FindRoots(state.DepGraph)

	// If no roots found (no dependencies), treat all components as roots
	if len(roots) == 0 {
		for _, c := range state.Components {
			roots = append(roots, c.ID)
		}
		sort.Strings(roots)
	}

	// Build tree nodes for roots
	var treeNodes []TreeNode
	for _, rootID := range roots {
		if comp, ok := compMap[rootID]; ok {
			node := buildTreeNode(comp, state.DepGraph, compMap, 0)
			treeNodes = append(treeNodes, node)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(treeNodes)
}

func buildTreeNode(comp sbom.Component, depGraph map[string][]string, compMap map[string]sbom.Component, depth int) TreeNode {
	node := TreeNode{
		ID:          comp.ID,
		Name:        comp.Name,
		Version:     comp.Version,
		Type:        analysis.ExtractPURLType(comp.PURL),
		ChildrenIDs: depGraph[comp.ID],
		HasChildren: len(depGraph[comp.ID]) > 0,
	}

	// Only expand children for first 2 levels to avoid huge payloads
	if depth < 2 && len(depGraph[comp.ID]) > 0 {
		for _, childID := range depGraph[comp.ID] {
			if childComp, ok := compMap[childID]; ok {
				childNode := buildTreeNode(childComp, depGraph, compMap, depth+1)
				node.Children = append(node.Children, childNode)
			}
		}
	}

	return node
}

func handleGetStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state.mu.RLock()
	defer state.mu.RUnlock()

	response := map[string]interface{}{
		"stats": state.Stats,
		"info":  state.Info,
	}

	// Add relationship statistics if available (Syft format)
	if len(state.Relationships) > 0 {
		response["relationships"] = state.Relationships
	}

	// Calculate coverage percentages
	if state.Stats.TotalComponents > 0 {
		total := float64(state.Stats.TotalComponents)
		response["coverage"] = map[string]interface{}{
			"cpe_percent":     float64(state.Stats.WithCPEs) / total * 100,
			"purl_percent":    float64(state.Stats.WithPURL) / total * 100,
			"license_percent": float64(state.Stats.TotalComponents-state.Stats.WithoutLicense) / total * 100,
			"hash_percent":    float64(state.Stats.WithHashes) / total * 100,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleGetComponent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract component ID from path: /api/component/{id}
	id := strings.TrimPrefix(r.URL.Path, "/api/component/")
	if id == "" {
		http.Error(w, "Component ID required", http.StatusBadRequest)
		return
	}

	state.mu.RLock()
	defer state.mu.RUnlock()

	// Find component by ID
	for _, c := range state.Components {
		if c.ID == id {
			detail := ComponentDetail{
				ID:           c.ID,
				Name:         c.Name,
				Version:      c.Version,
				PURL:         c.PURL,
				Type:         analysis.ExtractPURLType(c.PURL),
				Licenses:     c.Licenses,
				Hashes:       c.Hashes,
				Dependencies: state.DepGraph[c.ID],
				Supplier:     c.Supplier,
				RawJSON:      c.RawJSON,
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(detail)
			return
		}
	}

	http.Error(w, "Component not found", http.StatusNotFound)
}

func handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := strings.ToLower(r.URL.Query().Get("q"))
	if query == "" {
		http.Error(w, "Search query required", http.StatusBadRequest)
		return
	}

	state.mu.RLock()
	defer state.mu.RUnlock()

	var results []ComponentDetail
	for _, c := range state.Components {
		// Build searchable string from all fields (like TUI mode)
		searchable := strings.ToLower(
			c.Name + " " +
				c.Version + " " +
				c.PURL + " " +
				c.ID + " " +
				c.Supplier + " " +
				strings.Join(c.Licenses, " ") +
				strings.Join(c.CPEs, " ") +
				string(c.RawJSON),
		)

		if strings.Contains(searchable, query) {
			results = append(results, ComponentDetail{
				ID:       c.ID,
				Name:     c.Name,
				Version:  c.Version,
				PURL:     c.PURL,
				Type:     analysis.ExtractPURLType(c.PURL),
				Licenses: c.Licenses,
				Supplier: c.Supplier,
				RawJSON:  c.RawJSON,
			})
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}

func containsLicense(licenses []string, query string) bool {
	lowerQuery := strings.ToLower(query)
	for _, lic := range licenses {
		if strings.Contains(strings.ToLower(lic), lowerQuery) {
			return true
		}
	}
	return false
}

// extractRelationships extracts relationship statistics from Syft SBOM format
func extractRelationships(data []byte) map[string]int {
	var doc struct {
		ArtifactRelationships []struct {
			Type string `json:"type"`
		} `json:"artifactRelationships"`
	}

	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}

	if len(doc.ArtifactRelationships) == 0 {
		return nil
	}

	counts := make(map[string]int)
	for _, rel := range doc.ArtifactRelationships {
		if rel.Type != "" {
			counts[rel.Type]++
		}
	}

	return counts
}
