package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWebWorkflow_UploadThenQuery(t *testing.T) {
	resetState()

	// Step 1: Upload a CycloneDX SBOM
	req, err := createMultipartRequest(webTestdataPath("cyclonedx-before.json"))
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	handleUpload(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", rr.Code, rr.Body.String())
	}

	var uploadResp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &uploadResp); err != nil {
		t.Fatalf("failed to parse upload response: %v", err)
	}
	componentCount := int(uploadResp["components"].(float64))
	if componentCount == 0 {
		t.Fatal("expected >0 components after upload")
	}

	// Step 2: Query the tree
	req = httptest.NewRequest(http.MethodGet, "/api/tree", nil)
	rr = httptest.NewRecorder()
	handleGetTree(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("tree request failed: %d", rr.Code)
	}
	var treeNodes []TreeNode
	if err := json.Unmarshal(rr.Body.Bytes(), &treeNodes); err != nil {
		t.Fatalf("failed to parse tree response: %v", err)
	}
	if len(treeNodes) == 0 {
		t.Error("expected non-empty tree after upload")
	}

	// Step 3: Query stats
	req = httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	rr = httptest.NewRecorder()
	handleGetStats(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("stats request failed: %d", rr.Code)
	}
	var statsResp map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &statsResp); err != nil {
		t.Fatalf("failed to parse stats response: %v", err)
	}
	stats := statsResp["stats"].(map[string]interface{})
	if int(stats["total_components"].(float64)) != componentCount {
		t.Errorf("stats total_components=%v doesn't match upload count=%d",
			stats["total_components"], componentCount)
	}

	// Step 4: Search for a component
	req = httptest.NewRequest(http.MethodGet, "/api/search?q=lodash", nil)
	rr = httptest.NewRecorder()
	handleSearch(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("search request failed: %d", rr.Code)
	}

	// Step 5: Get a component by ID (use first tree node's ID)
	if len(treeNodes) > 0 {
		compID := treeNodes[0].ID
		req = httptest.NewRequest(http.MethodGet, "/api/component/"+compID, nil)
		rr = httptest.NewRecorder()
		handleGetComponent(rr, req)
		if rr.Code != http.StatusOK {
			t.Errorf("get component failed: %d", rr.Code)
		}
		var detail ComponentDetail
		if err := json.Unmarshal(rr.Body.Bytes(), &detail); err != nil {
			t.Fatalf("failed to parse component response: %v", err)
		}
		if detail.ID != compID {
			t.Errorf("expected component ID=%s, got %s", compID, detail.ID)
		}
	}
}
