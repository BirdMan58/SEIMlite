package normalizer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"SEIMlite/internal/discovery"
	"SEIMlite/internal/models"
)

type NextcloudNormalizer struct{}

func (n NextcloudNormalizer) ServiceName() string {
	return "nextcloud"
}

func (n NextcloudNormalizer) Start(pretty bool, eventChan chan<- *models.NormalizedEvent) error {
	baseURL := strings.TrimSpace(os.Getenv("NEXTCLOUD_URL"))
	if baseURL == "" {
		fmt.Println("[NEXTCLOUD] NEXTCLOUD_URL is not configured; skipping Nextcloud event monitoring")
		return nil
	}

	// Check immediately so the service has a fresh snapshot once started.
	if err := n.emitAuditEvents(pretty, baseURL, eventChan); err != nil {
		fmt.Printf("[NEXTCLOUD] initial audit failed: %v\n", err)
	}

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		if err := n.emitAuditEvents(pretty, baseURL, eventChan); err != nil {
			fmt.Printf("[NEXTCLOUD] audit failed: %v\n", err)
		}
		<-ticker.C
	}
}

func (n NextcloudNormalizer) emitAuditEvents(pretty bool, baseURL string, eventChan chan<- *models.NormalizedEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	findings, err := discovery.AuditNextcloud(ctx, baseURL)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		return nil
	}

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	for _, finding := range findings {
		event := n.eventForFinding(baseURL, finding, hostname)
		if event == nil {
			continue
		}
		eventChan <- event

		var jsonData []byte
		if pretty {
			jsonData, _ = json.MarshalIndent(event, "", "  ")
		} else {
			jsonData, _ = json.Marshal(event)
		}
		fmt.Println(string(jsonData))
	}
	return nil
}

func (n NextcloudNormalizer) eventForFinding(baseURL string, finding discovery.NextcloudFinding, hostname string) *models.NormalizedEvent {
	if finding.ID == "" {
		return nil
	}

	now := time.Now().UTC()
	event := &models.NormalizedEvent{
		Timestamp: now.Format("2006-01-02T15:04:05.000Z07:00"),
		FullLog:   fmt.Sprintf("%s | %s | %s", finding.Title, finding.Details, finding.Remediation),
		Location:  baseURL,
		Agent: struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			IP   string `json:"ip"`
		}{
			ID:   "000",
			Name: hostname,
			IP:   "127.0.0.1",
		},
		Manager: struct {
			Name string `json:"name"`
		}{
			Name: "SEIMlite",
		},
		Decoder: struct {
			Name string `json:"name"`
		}{
			Name: "nextcloud",
		},
		Rule: struct {
			Level       int      `json:"level"`
			Description string   `json:"description"`
			ID          string   `json:"id"`
			Groups      []string `json:"groups"`
		}{
			Level:       severityToLevel(finding.Severity),
			Description: "nextcloud: security finding",
			ID:          finding.ID,
			Groups:      []string{"nextcloud", "security", strings.ToLower(finding.Severity)},
		},
	}

	if parsed, err := url.Parse(baseURL); err == nil && parsed.Host != "" {
		event.Data.SrcIP = parsed.Hostname()
	} else {
		event.Data.SrcIP = "127.0.0.1"
	}
	event.Data.DstUser = "nextcloud"
	return event
}

func severityToLevel(level string) int {
	switch strings.ToLower(level) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}
