package web

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/rezmoss/sbomlyze/internal/analysis"
	"github.com/rezmoss/sbomlyze/internal/sbom"
)

func webTestdataPath(name string) string {
	return filepath.Join("..", "..", "testdata", name)
}

func resetState() {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.Components = nil
	state.Info = sbom.SBOMInfo{}
	state.Stats = analysis.Stats{}
	state.DepGraph = nil
	state.Relationships = nil
	state.RawSBOMData = nil
	state.CompIndex = nil
	state.SearchIndex = nil
}

func loadTestState(comps []sbom.Component, info sbom.SBOMInfo) {
	state.mu.Lock()
	defer state.mu.Unlock()
	state.Components = comps
	state.Info = info
	state.Stats = analysis.ComputeStats(comps)
	state.DepGraph = analysis.BuildDependencyGraph(comps)
	state.CompIndex = buildCompIndex(comps)
	state.SearchIndex = buildSearchIndex(comps)
}

func createMultipartRequest(filePath string) (*http.Request, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	return req, nil
}

func TestExtractRelationships(t *testing.T) {
	t.Run("extracts relationship counts from Syft format", func(t *testing.T) {
		data := []byte(`{
			"artifactRelationships": [
				{"type": "contains"},
				{"type": "contains"},
				{"type": "dependency-of"},
				{"type": "evident-by"}
			]
		}`)

		result := extractRelationships(data)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result["contains"] != 2 {
			t.Errorf("expected 2 contains, got %d", result["contains"])
		}
		if result["dependency-of"] != 1 {
			t.Errorf("expected 1 dependency-of, got %d", result["dependency-of"])
		}
		if result["evident-by"] != 1 {
			t.Errorf("expected 1 evident-by, got %d", result["evident-by"])
		}
	})

	t.Run("returns nil for non-Syft format", func(t *testing.T) {
		data := []byte(`{
			"bomFormat": "CycloneDX",
			"components": []
		}`)

		result := extractRelationships(data)

		if result != nil {
			t.Errorf("expected nil for non-Syft format, got %v", result)
		}
	})

	t.Run("returns nil for invalid JSON", func(t *testing.T) {
		data := []byte(`invalid json`)

		result := extractRelationships(data)

		if result != nil {
			t.Errorf("expected nil for invalid JSON, got %v", result)
		}
	})

	t.Run("returns nil for empty relationships", func(t *testing.T) {
		data := []byte(`{
			"artifactRelationships": []
		}`)

		result := extractRelationships(data)

		if result != nil {
			t.Errorf("expected nil for empty relationships, got %v", result)
		}
	})

	t.Run("handles missing type field", func(t *testing.T) {
		data := []byte(`{
			"artifactRelationships": [
				{"type": "contains"},
				{"other": "field"},
				{"type": ""}
			]
		}`)

		result := extractRelationships(data)

		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result["contains"] != 1 {
			t.Errorf("expected 1 contains, got %d", result["contains"])
		}
		if _, exists := result[""]; exists {
			t.Errorf("empty type should not be counted")
		}
	})
}

// --- Upload Handler Tests ---

func TestHandleUpload_CycloneDX(t *testing.T) {
	resetState()
	req, err := createMultipartRequest(webTestdataPath("cyclonedx-before.json"))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handleUpload(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if resp["success"] != true {
		t.Error("expected success=true")
	}
	if int(resp["components"].(float64)) != 3 {
		t.Errorf("expected 3 components, got %v", resp["components"])
	}
}

func TestHandleUpload_Syft(t *testing.T) {
	resetState()
	req, err := createMultipartRequest(webTestdataPath("syft-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handleUpload(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if int(resp["components"].(float64)) != 3 {
		t.Errorf("expected 3 components, got %v", resp["components"])
	}
}

func TestHandleUpload_SPDX(t *testing.T) {
	resetState()
	req, err := createMultipartRequest(webTestdataPath("spdx-sample.json"))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handleUpload(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if int(resp["components"].(float64)) != 2 {
		t.Errorf("expected 2 components, got %v", resp["components"])
	}
}

func TestHandleUpload_UnknownFormat(t *testing.T) {
	resetState()
	req, err := createMultipartRequest(webTestdataPath("invalid.json"))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handleUpload(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleUpload_NoFile(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/upload", nil)
	req.Header.Set("Content-Type", "multipart/form-data; boundary=---")
	rr := httptest.NewRecorder()
	handleUpload(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// --- Tree Handler Tests ---

func TestHandleGetTree_WithData(t *testing.T) {
	resetState()
	loadTestState([]sbom.Component{
		{ID: "a", Name: "a", Version: "1.0", Dependencies: []string{"b"}},
		{ID: "b", Name: "b", Version: "1.0"},
	}, sbom.SBOMInfo{})

	req := httptest.NewRequest(http.MethodGet, "/api/tree", nil)
	rr := httptest.NewRecorder()
	handleGetTree(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp struct {
		Nodes []TreeNode `json:"nodes"`
		Total int        `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse: %v", err)
	}
	if len(resp.Nodes) == 0 {
		t.Error("expected non-empty tree")
	}
	if resp.Total == 0 {
		t.Error("expected non-zero total")
	}
}

func TestHandleGetTree_Empty(t *testing.T) {
	resetState()
	req := httptest.NewRequest(http.MethodGet, "/api/tree", nil)
	rr := httptest.NewRecorder()
	handleGetTree(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp struct {
		Nodes []TreeNode `json:"nodes"`
		Total int        `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(resp.Nodes) != 0 {
		t.Errorf("expected empty tree, got %d nodes", len(resp.Nodes))
	}
	if resp.Total != 0 {
		t.Errorf("expected total=0, got %d", resp.Total)
	}
}

func TestHandleGetTree_NoDeps(t *testing.T) {
	resetState()
	loadTestState([]sbom.Component{
		{ID: "a", Name: "a", Version: "1.0"},
		{ID: "b", Name: "b", Version: "1.0"},
	}, sbom.SBOMInfo{})

	req := httptest.NewRequest(http.MethodGet, "/api/tree", nil)
	rr := httptest.NewRecorder()
	handleGetTree(rr, req)

	var resp struct {
		Nodes []TreeNode `json:"nodes"`
		Total int        `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	// With no deps, all components become roots
	if len(resp.Nodes) != 2 {
		t.Errorf("expected 2 root nodes (no deps), got %d", len(resp.Nodes))
	}
	if resp.Total != 2 {
		t.Errorf("expected total=2, got %d", resp.Total)
	}
}

// --- Stats Handler Tests ---

func TestHandleGetStats_WithData(t *testing.T) {
	resetState()
	loadTestState([]sbom.Component{
		{ID: "a", Name: "a", Version: "1.0", PURL: "pkg:npm/a@1.0"},
		{ID: "b", Name: "b", Version: "1.0"},
	}, sbom.SBOMInfo{OSName: "alpine"})

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	rr := httptest.NewRecorder()
	handleGetStats(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if _, ok := resp["stats"]; !ok {
		t.Error("expected 'stats' field in response")
	}
}

func TestHandleGetStats_Empty(t *testing.T) {
	resetState()
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	rr := httptest.NewRecorder()
	handleGetStats(rr, req)

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	stats := resp["stats"].(map[string]interface{})
	if stats["total_components"].(float64) != 0 {
		t.Errorf("expected 0 total components, got %v", stats["total_components"])
	}
}

func TestHandleGetStats_CoveragePercentages(t *testing.T) {
	resetState()
	loadTestState([]sbom.Component{
		{ID: "a", Name: "a", PURL: "pkg:npm/a@1.0"},
		{ID: "b", Name: "b"},
	}, sbom.SBOMInfo{})

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	rr := httptest.NewRecorder()
	handleGetStats(rr, req)

	var resp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	coverage, ok := resp["coverage"].(map[string]interface{})
	if !ok {
		t.Fatal("expected coverage field")
	}
	purlPct := coverage["purl_percent"].(float64)
	if purlPct != 50 {
		t.Errorf("expected purl_percent=50, got %v", purlPct)
	}
}

// --- Component Handler Tests ---

func TestHandleGetComponent_Found(t *testing.T) {
	resetState()
	loadTestState([]sbom.Component{
		{ID: "pkg:npm/test", Name: "test", Version: "1.0"},
	}, sbom.SBOMInfo{})

	req := httptest.NewRequest(http.MethodGet, "/api/component/pkg:npm/test", nil)
	rr := httptest.NewRecorder()
	handleGetComponent(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var detail ComponentDetail
	if err := json.Unmarshal(rr.Body.Bytes(), &detail); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if detail.Name != "test" {
		t.Errorf("expected name=test, got %s", detail.Name)
	}
}

func TestHandleGetComponent_NotFound(t *testing.T) {
	resetState()
	loadTestState([]sbom.Component{
		{ID: "a", Name: "a"},
	}, sbom.SBOMInfo{})

	req := httptest.NewRequest(http.MethodGet, "/api/component/nonexistent", nil)
	rr := httptest.NewRecorder()
	handleGetComponent(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rr.Code)
	}
}

// --- Search Handler Tests ---

func TestHandleSearch_ByName(t *testing.T) {
	resetState()
	loadTestState([]sbom.Component{
		{ID: "a", Name: "lodash", Version: "4.17.21"},
		{ID: "b", Name: "express", Version: "4.18.0"},
	}, sbom.SBOMInfo{})

	req := httptest.NewRequest(http.MethodGet, "/api/search?q=lodash", nil)
	rr := httptest.NewRecorder()
	handleSearch(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp struct {
		Results []ComponentDetail `json:"results"`
		Total   int               `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(resp.Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(resp.Results))
	}
	if resp.Total != 1 {
		t.Errorf("expected total=1, got %d", resp.Total)
	}
	if len(resp.Results) > 0 && resp.Results[0].Name != "lodash" {
		t.Errorf("expected lodash, got %s", resp.Results[0].Name)
	}
}

func TestHandleSearch_ByLicense(t *testing.T) {
	resetState()
	loadTestState([]sbom.Component{
		{ID: "a", Name: "mit-pkg", Licenses: []string{"MIT"}},
		{ID: "b", Name: "gpl-pkg", Licenses: []string{"GPL-3.0"}},
	}, sbom.SBOMInfo{})

	req := httptest.NewRequest(http.MethodGet, "/api/search?q=mit", nil)
	rr := httptest.NewRecorder()
	handleSearch(rr, req)

	var resp struct {
		Results []ComponentDetail `json:"results"`
		Total   int               `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(resp.Results) != 1 {
		t.Errorf("expected 1 result for MIT search, got %d", len(resp.Results))
	}
}

func TestHandleSearch_NoResults(t *testing.T) {
	resetState()
	loadTestState([]sbom.Component{
		{ID: "a", Name: "lodash"},
	}, sbom.SBOMInfo{})

	req := httptest.NewRequest(http.MethodGet, "/api/search?q=nonexistent", nil)
	rr := httptest.NewRecorder()
	handleSearch(rr, req)

	var resp struct {
		Results []ComponentDetail `json:"results"`
		Total   int               `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if len(resp.Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(resp.Results))
	}
	if resp.Total != 0 {
		t.Errorf("expected total=0, got %d", resp.Total)
	}
}

