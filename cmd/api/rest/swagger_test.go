package rest

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestSwaggerDocumentsManagementRequests(t *testing.T) {
	h := &ApiHandler{Cfg: validEditConfigPtr()}
	response := httptest.NewRecorder()
	h.InitRoutes().ServeHTTP(response, httptest.NewRequest("GET", "http://localhost/swagger/doc.json", nil))
	if response.Code != 200 {
		t.Fatalf("Swagger status=%d", response.Code)
	}
	var document struct {
		Consumes []string                  `json:"consumes"`
		Schemes  []string                  `json:"schemes"`
		Paths    map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if len(document.Consumes) != 1 || document.Consumes[0] != "application/json" {
		t.Fatalf("media types=%v", document.Consumes)
	}
	release := document.Paths["/pfcp_associations/release"]
	if release["post"] == nil || release["get"] != nil {
		t.Fatal("Swagger advertises a state-changing GET")
	}
	if len(document.Schemes) != 2 {
		t.Fatalf("schemes=%v", document.Schemes)
	}
}
