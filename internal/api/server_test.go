package api

import (
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
