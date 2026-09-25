package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// NextcloudFinding is a read-only security audit result. It does not change
// the Nextcloud installation.
type NextcloudFinding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Details     string `json:"details"`
	Remediation string `json:"remediation"`
}

type nextcloudStatus struct {
	Installed   bool   `json:"installed"`
	Maintenance bool   `json:"maintenance"`
	Version     string `json:"versionstring"`
}

// AuditNextcloud checks a configured Nextcloud URL and its public status
// endpoint. The URL should come from trusted local configuration, not a
// request parameter, to avoid turning this endpoint into an SSRF primitive.
func AuditNextcloud(ctx context.Context, baseURL string) ([]NextcloudFinding, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("NEXTCLOUD_URL must be an absolute http or https URL")
	}

	statusURL := *parsed
	statusURL.Path = strings.TrimRight(statusURL.Path, "/") + "/status.php"
	statusURL.RawQuery = ""
	statusURL.Fragment = ""

	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statusURL.String(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return []NextcloudFinding{{
			ID:          "nextcloud-unreachable",
			Severity:    "high",
			Title:       "Nextcloud status endpoint is unreachable",
			Details:     err.Error(),
			Remediation: "Confirm the service URL and reverse proxy are available, then restrict exposure to trusted networks.",
		}}, nil
	}
	defer resp.Body.Close()

	findings := make([]NextcloudFinding, 0, 8)
	if parsed.Scheme != "https" {
		findings = append(findings, NextcloudFinding{
			ID:          "nextcloud-no-https",
			Severity:    "high",
			Title:       "Nextcloud URL is not HTTPS",
			Details:     "Credentials and session cookies may be exposed in transit.",
			Remediation: "Put Nextcloud behind TLS and redirect HTTP to HTTPS. Set trusted_proxies and overwriteprotocol when using a reverse proxy.",
		})
	}
	findings = append(findings, checkNextcloudHeaders(resp.Header, parsed.Scheme == "https")...)

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return findings, fmt.Errorf("read status response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		findings = append(findings, NextcloudFinding{
			ID:          "nextcloud-status-failed",
			Severity:    "high",
			Title:       "Nextcloud status check failed",
			Details:     fmt.Sprintf("status.php returned HTTP %d", resp.StatusCode),
			Remediation: "Check the web server, PHP handler, reverse-proxy routing, and Nextcloud logs.",
		})
		return findings, nil
	}

	var status nextcloudStatus
	if err := json.Unmarshal(body, &status); err != nil {
		findings = append(findings, NextcloudFinding{
			ID:          "nextcloud-invalid-status",
			Severity:    "medium",
			Title:       "Nextcloud status response is not valid JSON",
			Details:     "The endpoint responded successfully, but it does not look like Nextcloud status.php.",
			Remediation: "Verify that NEXTCLOUD_URL points to the Nextcloud installation and that the reverse proxy is not serving another page.",
		})
		return findings, nil
	}
	if !status.Installed {
		findings = append(findings, NextcloudFinding{
			ID:          "nextcloud-not-installed",
			Severity:    "critical",
			Title:       "Nextcloud reports that it is not installed",
			Details:     "An unconfigured installation should not be exposed to a network.",
			Remediation: "Complete installation or remove the public route until configuration is complete.",
		})
	}
	if status.Maintenance {
		findings = append(findings, NextcloudFinding{
			ID:          "nextcloud-maintenance",
			Severity:    "low",
			Title:       "Nextcloud is in maintenance mode",
			Details:     "User-facing operations may be unavailable.",
			Remediation: "Disable maintenance mode after backups and upgrades are complete.",
		})
	}

	return findings, nil
}

func checkNextcloudHeaders(headers http.Header, https bool) []NextcloudFinding {
	findings := []NextcloudFinding{}
	if https && headers.Get("Strict-Transport-Security") == "" {
		findings = append(findings, NextcloudFinding{
			ID:          "nextcloud-missing-hsts",
			Severity:    "medium",
			Title:       "Strict-Transport-Security is missing",
			Details:     "Browsers are not instructed to keep using HTTPS.",
			Remediation: "Configure HSTS at the TLS-terminating web server after confirming every trusted domain supports HTTPS.",
		})
	}
	if !strings.EqualFold(headers.Get("X-Content-Type-Options"), "nosniff") {
		findings = append(findings, NextcloudFinding{
			ID:          "nextcloud-missing-nosniff",
			Severity:    "medium",
			Title:       "X-Content-Type-Options is missing or weak",
			Details:     "The response does not explicitly prevent MIME sniffing.",
			Remediation: "Set X-Content-Type-Options: nosniff at the web server or reverse proxy.",
		})
	}
	if headers.Get("Referrer-Policy") == "" {
		findings = append(findings, NextcloudFinding{
			ID:          "nextcloud-missing-referrer-policy",
			Severity:    "low",
			Title:       "Referrer-Policy is missing",
			Details:     "URLs may be disclosed as referrer information.",
			Remediation: "Set a restrictive policy such as strict-origin-when-cross-origin.",
		})
	}
	if headers.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(headers.Get("Content-Security-Policy")), "frame-ancestors") {
		findings = append(findings, NextcloudFinding{
			ID:          "nextcloud-missing-clickjacking-protection",
			Severity:    "medium",
			Title:       "Clickjacking protection is missing",
			Details:     "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
			Remediation: "Set X-Frame-Options: SAMEORIGIN or an equivalent Content-Security-Policy frame-ancestors directive.",
		})
	}
	return findings
}
