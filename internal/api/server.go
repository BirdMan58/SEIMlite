package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"SEIMlite/internal/discovery"
	"SEIMlite/internal/models"
	"SEIMlite/web"
)

type Server struct {
	hub      *Hub
	services []discovery.Service
	alerts   []*models.CorrelationAlert // keep last 50 for initial load
}

func NewServer(hub *Hub) *Server {
	s := &Server{
		hub:      hub,
		services: discovery.KnownServices,
		alerts:   []*models.CorrelationAlert{},
	}

	go hub.Run()
	return s
}

// AddAlert stores an alert (for initial load) and broadcasts it.
func (s *Server) AddAlert(alert *models.CorrelationAlert) {
	// Keep only last 50
	if len(s.alerts) >= 50 {
		s.alerts = s.alerts[1:]
	}
	s.alerts = append(s.alerts, alert)
	// Broadcast via hub
	s.hub.BroadcastAlert(alert)
}

func (s *Server) Start(addr string) error {
	mux := http.NewServeMux()

	// Serve static files with proper MIME types and nosniff header
	mux.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		// Extract the file path (e.g., "/static/style.css" -> "style.css")
		path := strings.TrimPrefix(r.URL.Path, "/static/")
		if path == "" {
			http.NotFound(w, r)
			return
		}

		// Read the file from the embedded filesystem
		content, err := web.StaticFS.ReadFile("static/" + path)
		if err != nil {
			http.NotFound(w, r)
			return
		}

		// Set the correct MIME type based on the file extension
		ext := filepath.Ext(path)
		contentType := ""
		switch ext {
		case ".css":
			contentType = "text/css"
		case ".js":
			contentType = "application/javascript"
		case ".html":
			contentType = "text/html"
		case ".json":
			contentType = "application/json"
		case ".png":
			contentType = "image/png"
		case ".jpg", ".jpeg":
			contentType = "image/jpeg"
		case ".svg":
			contentType = "image/svg+xml"
		case ".ico":
			contentType = "image/x-icon"
		default:
			contentType = "application/octet-stream"
		}

		// Set headers to prevent the "nosniff" blocking error
		w.Header().Set("Content-Type", contentType)
		// Informs the browser that the response's Content-Type has been set correctly.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Write(content)
	})
	// Also serve index.html at root
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		// Serve index.html from embedded FS
		content, err := web.StaticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "index.html not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		w.Write(content)
	})

	// REST API endpoints
	mux.HandleFunc("/api/services", s.handleServices)
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/topology", s.handleTopology)
	mux.HandleFunc("/api/nextcloud/security", s.handleNextcloudSecurity)

	// WebSocket
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		ServeWs(s.hub, w, r)
	})

	fmt.Printf("[API] Dashboard available at http://%s\n", addr)
	return http.ListenAndServe(addr, mux)
}

// ---- Handlers ----

func (s *Server) handleServices(w http.ResponseWriter, r *http.Request) {
	// Return a list of discovered services with current status
	// For now, it'll return the known services with static status
	// In future, it will enhance to include real running status
	result := []map[string]interface{}{}
	for _, svc := range s.services {
		// Simulate running status (it know SSH is running if it are here)
		running := discovery.IsServiceRunning(svc) // it needs to export this function
		result = append(result, map[string]interface{}{
			"id":     svc.Name,
			"label":  svc.Name,
			"port":   svc.DefaultPort,
			"status": map[bool]string{true: "online", false: "offline"}[running],
			"alerts": 0, // it will count alerts later
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.alerts)
}

func (s *Server) computeStats() map[string]interface{} {
	total := len(s.alerts)
	activeServices := 0
	activeThreats := 0
	severityCount := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}

	for _, svc := range s.services {
		if discovery.IsServiceRunning(svc) {
			activeServices++
		}
	}

	for _, a := range s.alerts {
		if a == nil {
			continue
		}
		sev := "low"
		if a.Severity >= 4 {
			sev = "critical"
		} else if a.Severity >= 3 {
			sev = "high"
		} else if a.Severity >= 2 {
			sev = "medium"
		}
		severityCount[sev]++
		if a.Severity >= 2 {
			activeThreats++
		}
	}

	threatLevel := "Low"
	switch {
	case severityCount["critical"] > 0:
		threatLevel = "Critical"
	case severityCount["high"] > 0:
		threatLevel = "High"
	case severityCount["medium"] > 0:
		threatLevel = "Medium"
	}

	return map[string]interface{}{
		"total_alerts":     total,
		"active_services":  activeServices,
		"active_threats":   activeThreats,
		"events_today":     0,
		"threat_level":     threatLevel,
		"blocked_ips":      0,
		"severity_dist":    severityCount,
		"security_summary": map[string]interface{}{
			"active_threats": activeThreats,
			"status":         map[bool]string{true: "warning", false: "healthy"}[activeThreats > 0],
		},
	}
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := s.computeStats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func hasThreatAlert(alerts []*models.CorrelationAlert) bool {
	for _, alert := range alerts {
		if alert != nil && alert.Severity >= 2 {
			return true
		}
	}
	return false
}

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	nodes := []map[string]interface{}{
		{"id": "homelab", "label": "🏠 Homelab", "type": "center"},
	}
	links := []map[string]interface{}{}

	for _, svc := range s.services {
		running := discovery.IsServiceRunning(svc)
		if !running {
			continue
		}

		serviceNode := map[string]interface{}{
			"id":     svc.Name,
			"label":  svc.Name,
			"type":   "service",
			"port":   svc.DefaultPort,
			"threat": false,
		}
		nodes = append(nodes, serviceNode)
		links = append(links, map[string]interface{}{
			"source": "homelab",
			"target": svc.Name,
			"active": true,
		})
	}

	extIPs := map[string]bool{}
	for _, a := range s.alerts {
		if a != nil && a.SourceIP != "" && a.Severity >= 2 {
			extIPs[a.SourceIP] = true
		}
	}
	for ip := range extIPs {
		nodes = append(nodes, map[string]interface{}{
			"id":     ip,
			"label":  ip,
			"type":   "external",
			"threat": true,
		})
		links = append(links, map[string]interface{}{
			"source": "homelab",
			"target": ip,
			"active": true,
		})
	}

	topology := map[string]interface{}{
		"nodes": nodes,
		"links": links,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(topology)
}

func (s *Server) handleNextcloudSecurity(w http.ResponseWriter, r *http.Request) {
	baseURL := os.Getenv("NEXTCLOUD_URL")
	if baseURL == "" {
		http.Error(w, "NEXTCLOUD_URL is not configured", http.StatusServiceUnavailable)
		return
	}

	findings, err := discovery.AuditNextcloud(r.Context(), baseURL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"checked_at": time.Now().UTC(),
		"findings":   findings,
	})
}

func (s *Server) NotifyAlert(alert *models.CorrelationAlert) {
	s.AddAlert(alert)
}
