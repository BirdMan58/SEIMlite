package discovery

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Service describes a detectable service.
type Service struct {
	Name          string
	DefaultPort   int
	ProcessNames  []string
	SearchCmdline bool
}

var KnownServices = []Service{
	{Name: "ssh", DefaultPort: 22, ProcessNames: []string{"sshd"}, SearchCmdline: false},
	{Name: "jellyfin", DefaultPort: 8096, ProcessNames: []string{"jellyfin"}, SearchCmdline: true},
	{Name: "nextcloud", DefaultPort: 80, ProcessNames: []string{"nextcloud"}, SearchCmdline: true},
	{Name: "vaultwarden", DefaultPort: 8000, ProcessNames: []string{"vaultwarden"}, SearchCmdline: true},
	{Name: "pihole", DefaultPort: 53, ProcessNames: []string{"pihole-FTL", "pihole"}, SearchCmdline: false},
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

// IsServiceRunning checks if a given service is currently running.
func IsServiceRunning(svc Service) bool {
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
