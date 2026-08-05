package normalizer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"SEIMlite/internal/models"
)

// ============================================================
// USER CACHE
// ============================================================

var (
	userCache        sync.Map
	userCacheLock    sync.Mutex
	lastCacheRefresh time.Time
)

// refreshUserCache reads /etc/passwd and caches all usernames.
func refreshUserCache() {
	userCacheLock.Lock()
	defer userCacheLock.Unlock()

	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		fmt.Printf("[WARN] Could not read /etc/passwd: %v\n", err)
		return
	}

	// Clear the cache
	userCache = sync.Map{}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		// Format: username:password:UID:GID:...
		parts := strings.Split(line, ":")
		if len(parts) >= 1 {
			username := strings.TrimSpace(parts[0])
			if username != "" {
				userCache.Store(username, true)
			}
		}
	}
	lastCacheRefresh = time.Now()
	fmt.Printf("[CACHE] Refreshed user cache: %d users loaded\n", countCache())
}

// countCache returns the number of cached users (for debugging).
func countCache() int {
	count := 0
	userCache.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// isValidSystemUser checks if a username exists in the cached user list.
// If the cache is empty or older than 5 minutes, it refreshes.
func isValidSystemUser(username string) bool {
	// Refresh if cache is empty or older than 5 minutes
	if time.Since(lastCacheRefresh) > 5*time.Minute || lastCacheRefresh.IsZero() {
		refreshUserCache()
	}

	_, exists := userCache.Load(username)
	return exists
}

// ============================================================
// SSH NORMALIZER
// ============================================================

// SSHNormalizer implements the Normalizer interface for SSH logs.
type SSHNormalizer struct{}

func (n SSHNormalizer) ServiceName() string {
	return "ssh"
}

// parsedFields holds the extracted data from a single log line.
type parsedFields struct {
	srcIP         string
	srcPort       string
	dstUser       string
	clientVersion string
}

// Regex patterns for SSH log parsing
var (
	// Standard failed password (valid or invalid user)
	failRe = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)`)

	// Standard accepted password/publickey
	acceptRe = regexp.MustCompile(`Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)`)

	// PAM: "password check failed for user (root)"
	pamFailRe = regexp.MustCompile(`password check failed for user \((\S+)\)`)

	// PAM: "authentication failure; ... user=root ... rhost=192.168.122.1"
	authFailRe = regexp.MustCompile(`authentication failure.*rhost=(\S+).*user=(\S+)`)

	// Hydra: "Connection closed by authenticating user root 192.168.122.1 port 39398"
	connClosedRe = regexp.MustCompile(`Connection closed by authenticating user (\S+) (\S+) port (\d+)`)

	// Hydra: "Disconnected from authenticating user root 192.168.122.1 port 39390"
	disconnectedRe = regexp.MustCompile(`Disconnected from authenticating user (\S+) (\S+) port (\d+)`)

	// Client version extraction (e.g., "ssh2", "OpenSSH_8.9p1")
	versionRe = regexp.MustCompile(`(OpenSSH_\S+|ssh\d+)$`)
)

// parseSSHLog extracts all fields from a single log line.
// Returns: eventType ("login_failure" or "login_success"), fields, ok
func parseSSHLog(line string) (eventType string, fields parsedFields, ok bool) {
	// Quick filter for SSH-related lines
	if !strings.Contains(line, "sshd") && !strings.Contains(line, "ssh") {
		return "", parsedFields{}, false
	}

	// Extract client version from the end of the line
	clientVersion := "Unknown"
	if matches := versionRe.FindStringSubmatch(line); len(matches) > 1 {
		clientVersion = matches[1]
	}

	// 1. Standard Failed password
	if matches := failRe.FindStringSubmatch(line); matches != nil {
		return "login_failure", parsedFields{
			dstUser:       matches[1],
			srcIP:         matches[2],
			srcPort:       matches[3],
			clientVersion: clientVersion,
		}, true
	}

	// 2. Standard Accepted password/publickey (success)
	if matches := acceptRe.FindStringSubmatch(line); matches != nil {
		return "login_success", parsedFields{
			dstUser:       matches[1],
			srcIP:         matches[2],
			srcPort:       matches[3],
			clientVersion: clientVersion,
		}, true
	}

	// 3. PAM password check failed
	if matches := pamFailRe.FindStringSubmatch(line); matches != nil {
		// Extract IP from the line
		ipRe := regexp.MustCompile(`rhost=(\S+)`)
		ipMatches := ipRe.FindStringSubmatch(line)
		ip := "unknown"
		if len(ipMatches) > 1 {
			ip = ipMatches[1]
		}
		return "login_failure", parsedFields{
			dstUser:       matches[1],
			srcIP:         ip,
			srcPort:       "unknown",
			clientVersion: clientVersion,
		}, true
	}

	// 4. PAM authentication failure
	if matches := authFailRe.FindStringSubmatch(line); matches != nil {
		// matches[1] = rhost (IP), matches[2] = user
		return "login_failure", parsedFields{
			dstUser:       matches[2],
			srcIP:         matches[1],
			srcPort:       "unknown",
			clientVersion: clientVersion,
		}, true
	}

	// 5. Connection closed (hydra)
	if matches := connClosedRe.FindStringSubmatch(line); matches != nil {
		return "login_failure", parsedFields{
			dstUser:       matches[1],
			srcIP:         matches[2],
			srcPort:       matches[3],
			clientVersion: clientVersion,
		}, true
	}

	// 6. Disconnected (hydra)
	if matches := disconnectedRe.FindStringSubmatch(line); matches != nil {
		return "login_failure", parsedFields{
			dstUser:       matches[1],
			srcIP:         matches[2],
			srcPort:       matches[3],
			clientVersion: clientVersion,
		}, true
	}

	return "", parsedFields{}, false
}

// generateAlert creates a NormalizedEvent from the parsed fields.
func (n SSHNormalizer) generateAlert(rawLog string, eventType string, fields parsedFields, hostname string) (*models.NormalizedEvent, error) {
	alert := models.NewNormalizedEvent()

	// Set timestamp
	alert.Timestamp = time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00")

	// Agent
	alert.Agent.ID = "000"
	alert.Agent.Name = hostname
	alert.Agent.IP = "127.0.0.1"

	// Manager
	alert.Manager.Name = "SEIMlite"

	// Location
	alert.Location = "/var/log/auth.log"

	// Full log
	alert.FullLog = rawLog

	// Decoder
	alert.Decoder.Name = "sshd"

	// Data
	alert.Data.SrcIP = fields.srcIP
	alert.Data.SrcPort = fields.srcPort
	alert.Data.DstUser = fields.dstUser

	// ===== NEW FIELDS =====
	alert.Data.Username = fields.dstUser
	alert.Data.ClientVersion = fields.clientVersion
	// Check if the user exists in /etc/passwd (cached)
	alert.Data.IsValidUser = isValidSystemUser(fields.dstUser)
	// GeoCountry remains "Local" for now (will be populated later via IP lookup)
	alert.Data.GeoCountry = "Local"
	// ======================

	// Rule based on event type
	if eventType == "login_failure" {
		alert.Rule.Level = 5
		alert.Rule.Description = "sshd: authentication failure"
		alert.Rule.ID = "5710"
		alert.Rule.Groups = []string{"syslog", "sshd", "authentication_failed"}
	} else if eventType == "login_success" {
		alert.Rule.Level = 3
		alert.Rule.Description = "sshd: authentication success"
		alert.Rule.ID = "5715"
		alert.Rule.Groups = []string{"syslog", "sshd", "authentication_success"}
	} else {
		alert.Rule.Level = 0
		alert.Rule.Description = "sshd: unknown event"
		alert.Rule.ID = "0000"
		alert.Rule.Groups = []string{"syslog", "sshd"}
	}

	return alert, nil
}

// processLine handles a single raw log line, parses it, and sends it to the event channel.
func (n SSHNormalizer) processLine(line string, out *os.File, hostname string, pretty bool, eventChan chan<- *models.NormalizedEvent) {
	eventType, fields, ok := parseSSHLog(line)
	if !ok {
		return
	}

	// Skip duplicate log lines (optional: if you see duplicate events, add a simple dedup here)

	alert, err := n.generateAlert(line, eventType, fields, hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating alert: %v\n", err)
		return
	}

	// Send to correlation engine
	eventChan <- alert

	// Print and write to file
	var jsonData []byte
	if pretty {
		jsonData, _ = json.MarshalIndent(alert, "", "  ")
	} else {
		jsonData, _ = json.Marshal(alert)
	}
	fmt.Println(string(jsonData))
	out.Write(jsonData)
	out.Write([]byte("\n"))
}

// Start begins the SSH normalizer.
func (n SSHNormalizer) Start(pretty bool, eventChan chan<- *models.NormalizedEvent) error {
	outputFile := "normalized_ssh.log"
	out, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open output file: %w", err)
	}
	defer out.Close()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}

	// Seed user cache on startup
	refreshUserCache()

	// Try to tail /var/log/auth.log
	file, err := os.Open("/var/log/auth.log")
	if err != nil {
		fmt.Println("SSH: /var/log/auth.log not found. Falling back to journalctl -u ssh")
		return n.streamFromJournal(out, hostname, pretty, eventChan)
	}
	defer file.Close()

	file.Seek(0, 2)
	reader := bufio.NewReader(file)
	fmt.Println("SSH normalizer started: tailing /var/log/auth.log")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		line = strings.TrimSuffix(line, "\n")
		n.processLine(line, out, hostname, pretty, eventChan)
	}
}

// streamFromJournal is the fallback for systems without auth.log.
func (n SSHNormalizer) streamFromJournal(out *os.File, hostname string, pretty bool, eventChan chan<- *models.NormalizedEvent) error {
	cmd := exec.Command("journalctl", "-f", "-o", "json", "-u", "ssh")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if msg, ok := entry["MESSAGE"].(string); ok {
			n.processLine(msg, out, hostname, pretty, eventChan)
		}
	}
	return scanner.Err()
}
