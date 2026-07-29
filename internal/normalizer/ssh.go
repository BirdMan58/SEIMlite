package normalizer

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"SEIMlite/internal/models"
)

type SSHNormalizer struct{}

func (n SSHNormalizer) ServiceName() string {
	return "ssh"
}

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

// ---- parsing helpers ----

type parsedFields struct {
	srcIP   string
	srcPort string
	dstUser string
}

var (
	failRe   = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from (\S+) port (\d+)`)
	acceptRe = regexp.MustCompile(`Accepted (?:password|publickey) for (\S+) from (\S+) port (\d+)`)
)

func (n SSHNormalizer) parseSSHLog(line string) (eventType string, fields parsedFields, ok bool) {
	if !strings.Contains(line, "sshd") && !strings.Contains(line, "ssh") {
		return "", parsedFields{}, false
	}
	if matches := failRe.FindStringSubmatch(line); matches != nil {
		return "authentication_failed", parsedFields{
			dstUser: matches[1],
			srcIP:   matches[2],
			srcPort: matches[3],
		}, true
	}
	if matches := acceptRe.FindStringSubmatch(line); matches != nil {
		return "authentication_success", parsedFields{
			dstUser: matches[1],
			srcIP:   matches[2],
			srcPort: matches[3],
		}, true
	}
	return "", parsedFields{}, false
}

func (n SSHNormalizer) generateAlert(rawLog string, eventType string, fields parsedFields, hostname string) (models.NormalizedEvent, error) {
	now := time.Now().UTC()
	timestamp := now.Format("2006-01-02T15:04:05.000Z07:00")

	alert := models.NormalizedEvent{
		Timestamp: timestamp,
		FullLog:   rawLog,
		Location:  "/var/log/auth.log",
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
			Name: "sshd",
		},
	}

	alert.Data.SrcIP = fields.srcIP
	alert.Data.SrcPort = fields.srcPort
	alert.Data.DstUser = fields.dstUser

	switch eventType {
	case "authentication_failed":
		alert.Rule.Level = 5
		alert.Rule.Description = "sshd: authentication failure"
		alert.Rule.ID = "5710"
		alert.Rule.Groups = []string{"syslog", "sshd", "authentication_failed"}
	case "authentication_success":
		alert.Rule.Level = 3
		alert.Rule.Description = "sshd: authentication success"
		alert.Rule.ID = "5715"
		alert.Rule.Groups = []string{"syslog", "sshd", "authentication_success"}
	default:
		alert.Rule.Level = 0
		alert.Rule.Description = "sshd: unknown event"
		alert.Rule.ID = "0000"
		alert.Rule.Groups = []string{"syslog", "sshd"}
	}
	return alert, nil
}

func (n SSHNormalizer) processLine(line string, out *os.File, hostname string, pretty bool, eventChan chan<- *models.NormalizedEvent) {
	eventType, fields, ok := n.parseSSHLog(line)
	if !ok {
		return
	}
	alert, err := n.generateAlert(line, eventType, fields, hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating alert: %v\n", err)
		return
	}

	eventChan <- &alert

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
