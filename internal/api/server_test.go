package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"SEIMlite/internal/discovery"
	"SEIMlite/internal/models"
)

func TestComputeStatsCountsOnlyRunningServicesAndThreats(t *testing.T) {
	server := &Server{
		services: []discovery.Service{},
		alerts: []*models.CorrelationAlert{
			{Severity: 2, SourceIP: "10.0.0.5"},
			{Severity: 1, SourceIP: "10.0.0.6"},
		},
	}

	stats := server.computeStats()
	if got := stats["active_services"]; got != 0 {
		t.Fatalf("active_services = %v, want 0", got)
	}
	if got := stats["active_threats"]; got != 1 {
		t.Fatalf("active_threats = %v, want 1", got)
	}
	if got := stats["threat_level"]; got != "Medium" {
		t.Fatalf("threat_level = %v, want Medium", got)
	}
}

func TestTopologyBranchesThreatIPFromService(t *testing.T) {
	server := &Server{
		services: []discovery.Service{{Name: "ssh", DefaultPort: 22}},
		alerts: []*models.CorrelationAlert{{
			Severity:    4,
			Title:       "SSH Brute Force Attack",
			Description: "Detected 5 failed SSH login attempts",
			SourceIP:    "203.0.113.9",
		}},
	}

	server.services[0] = discovery.Service{Name: "ssh", DefaultPort: 22, Ports: []int{22}}

	req := httptest.NewRequest(http.MethodGet, "/api/topology", nil)
	w := httptest.NewRecorder()
	server.handleTopology(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var topology map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &topology); err != nil {
		t.Fatalf("decode topology: %v", err)
	}
	links := topology["links"].([]interface{})
	found := false
	for _, item := range links {
		link := item.(map[string]interface{})
		if link["source"] == "ssh" && link["target"] == "203.0.113.9" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected SSH alert IP to branch from the ssh service node")
	}
}

func TestHandleServicesCountsAlertsPerService(t *testing.T) {
	server := &Server{
		services: []discovery.Service{{Name: "ssh", DefaultPort: 22}},
		alerts: []*models.CorrelationAlert{{
			Severity:    4,
			Title:       "SSH Brute Force Attack",
			Description: "Detected 5 failed SSH login attempts",
			SourceIP:    "203.0.113.9",
		}},
	}

	req := httptest.NewRequest(http.MethodGet, "/api/services", nil)
	w := httptest.NewRecorder()
	server.handleServices(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var services []map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &services); err != nil {
		t.Fatalf("decode services: %v", err)
	}
	if len(services) == 0 {
		t.Fatal("expected at least one service entry")
	}
	for _, svc := range services {
		if svc["id"] == "ssh" {
			if got := svc["alerts"]; got != float64(1) {
				t.Fatalf("ssh alert count = %v, want 1", got)
			}
			return
		}
	}
	
	t.Fatal("expected ssh service entry")
}
