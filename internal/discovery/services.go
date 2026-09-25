package discovery

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Service describes a detectable service.
type Service struct {
	Name          string
	DefaultPort   int
	Ports         []int
	ProcessNames  []string
	SearchCmdline bool
}

var KnownServices = []Service{
	{Name: "ssh", DefaultPort: 22, Ports: []int{22}, ProcessNames: []string{"sshd"}, SearchCmdline: false},
	{Name: "jellyfin", DefaultPort: 8096, Ports: []int{8096, 8920}, ProcessNames: []string{"jellyfin"}, SearchCmdline: true},
	{Name: "nextcloud", DefaultPort: 8080, Ports: []int{8080, 80, 443}, ProcessNames: []string{"nextcloud"}, SearchCmdline: true},
	{Name: "vaultwarden", DefaultPort: 8000, Ports: []int{8000, 80, 443}, ProcessNames: []string{"vaultwarden"}, SearchCmdline: true},
	{Name: "pihole", DefaultPort: 53, Ports: []int{53}, ProcessNames: []string{"pihole-FTL", "pihole"}, SearchCmdline: false},
}

func getCmdline(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return ""
	}
	cmd := strings.ReplaceAll(string(data), "\x00", " ")
	return strings.TrimSpace(cmd)
}

func getComm(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func candidatePorts(svc Service) []int {
	seen := map[int]bool{}
	ports := make([]int, 0, len(svc.Ports)+1)
	for _, port := range append([]int{svc.DefaultPort}, svc.Ports...) {
		if port <= 0 || seen[port] {
			continue
		}
		seen[port] = true
		ports = append(ports, port)
	}
	return ports
}

func httpServiceMatches(name, body string, headers http.Header) bool {
	lower := strings.ToLower(body)
	switch name {
	case "nextcloud":
		return strings.Contains(lower, "nextcloud") || strings.Contains(lower, "oc_login_name") || strings.Contains(lower, "login") && strings.Contains(lower, "nextcloud")
	case "vaultwarden":
		return strings.Contains(lower, "vaultwarden") || strings.Contains(lower, "bitwarden")
	case "jellyfin":
		return strings.Contains(lower, "jellyfin") || strings.Contains(lower, "emby") || strings.Contains(lower, "server dashboard")
	case "pihole":
		return strings.Contains(lower, "pihole") || strings.Contains(lower, "pi-hole") || strings.Contains(lower, "blocklists")
	default:
		return false
	}
}

func detectHTTPService(name string, ports []int) bool {
	for _, port := range ports {
		if !isTCPPortOpen(port) {
			continue
		}
		url := fmt.Sprintf("http://127.0.0.1:%d/", port)
		client := &http.Client{Timeout: 800 * time.Millisecond}
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			continue
		}
		if httpServiceMatches(name, string(bodyBytes), resp.Header) {
			return true
		}
	}
	return false
}

// IsServiceRunning checks if a given service is currently running.
func IsServiceRunning(svc Service) bool {
	ports := candidatePorts(svc)
	if svc.Name == "nextcloud" || svc.Name == "vaultwarden" || svc.Name == "jellyfin" || svc.Name == "pihole" {
		if detectHTTPService(svc.Name, ports) {
			return true
		}
	}
	for _, port := range ports {
		if isTCPPortOpen(port) {
			return true
		}
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		comm := getComm(pid)
		cmdline := getCmdline(pid)
		for _, pattern := range svc.ProcessNames {
			if strings.Contains(strings.ToLower(comm), strings.ToLower(pattern)) {
				return true
			}
			if svc.SearchCmdline && strings.Contains(strings.ToLower(cmdline), strings.ToLower(pattern)) {
				return true
			}
		}
	}
	return false
}

// Discover returns a map of service name -> bool (true if running).
func Discover() map[string]bool {
	result := make(map[string]bool)
	for _, svc := range KnownServices {
		result[svc.Name] = IsServiceRunning(svc)
	}
	return result
}

// isTCPPortOpen checks if a TCP port is open on localhost.
func isTCPPortOpen(port int) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// ServicePort returns the configured default port for a known service.
func ServicePort(name string) int {
	for _, svc := range KnownServices {
		if svc.Name == name {
			return svc.DefaultPort
		}
	}
	return 0
}
