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

func TestSwaggerRequiresCompleteConfigSections(t *testing.T) {
	h := &ApiHandler{Cfg: validEditConfigPtr()}
	out := httptest.NewRecorder()
	h.InitRoutes().ServeHTTP(out, httptest.NewRequest("GET", "http://localhost/swagger/doc.json", nil))
	if out.Code != 200 {
		t.Fatalf("status=%d", out.Code)
	}
	var doc struct {
		Definitions map[string]struct {
			Required   []string       `json:"required"`
			Properties map[string]any `json:"properties"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(out.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"LoggingLevelConfig", "LoggingCallerConfig", "DataPlaneEbpfConfig", "DataPlaneAddressesConfig", "PFCPN4Config", "PFCPSxaConfig", "PFCPSxbConfig", "PFCPTimersConfig", "GTPPathConfig"} {
		schema, ok := doc.Definitions["rest."+name]
		if !ok || len(schema.Properties) == 0 {
			t.Fatalf("missing %s", name)
		}
		required := make(map[string]bool)
		for _, key := range schema.Required {
			required[key] = true
		}
		for key := range schema.Properties {
			if !required[key] {
				t.Errorf("%s.%s is not required", name, key)
			}
		}
	}
}
