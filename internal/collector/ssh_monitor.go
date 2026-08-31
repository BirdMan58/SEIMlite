package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"SEIMlite/internal/config"
	"SEIMlite/internal/models"
	"SEIMlite/internal/storage"
)

type ProcessInfo struct {
	PID        int
	PPID       int
	Name       string
	Cmdline    string
	RSSBytes   uint64
	CPUPercent float64
}

// Known shells
var shellBinaries = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true,
	"fish": true, "csh": true, "tcsh": true, "ash": true,
}

// System, admin, and monitoring processes ignored from unauthorized execution alerts
var systemIgnoredProcesses = map[string]bool{
	"sshd": true, "SEIMlite": true, "seimlite": true, "sudo": true,
	"journalctl": true, "systemd": true, "systemd-journal": true,
	"systemctl": true, "sftp-server": true, "scp": true, "rsync": true,
}

type SSHMonitor struct {
	eventChan   chan<- *models.NormalizedEvent
	lastCPUs    map[int]uint64
	lastTime    time.Time
	alertedPIDs map[string]time.Time
}

func NewSSHMonitor(eventChan chan<- *models.NormalizedEvent) *SSHMonitor {
	return &SSHMonitor{
		eventChan:   eventChan,
		lastCPUs:    make(map[int]uint64),
		lastTime:    time.Now(),
		alertedPIDs: make(map[string]time.Time),
	}
}

func (m *SSHMonitor) Start() {
	fmt.Println("[MONITOR] SSH Process & Resource Enforcement Monitor started.")
	for {
		cfg := config.GetConfig().SSH
		intervalSec := cfg.ProcessMonitorIntervalSec
		if intervalSec <= 0 {
			intervalSec = 3
		}

		m.checkProcesses(cfg)

		time.Sleep(time.Duration(intervalSec) * time.Second)
	}
}

func (m *SSHMonitor) checkProcesses(cfg config.SSHConfig) {
	procs, err := getAllProcesses()
	if err != nil {
		return
	}

	// Clean up stale alertedPIDs
	now := time.Now()
	for key, lastTime := range m.alertedPIDs {
		if now.Sub(lastTime) > 2*time.Minute {
			delete(m.alertedPIDs, key)
		}
	}

	// Find sshd PIDs
	sshdPIDs := make(map[int]bool)
	for _, p := range procs {
		if strings.Contains(strings.ToLower(p.Name), "sshd") {
			sshdPIDs[p.PID] = true
		}
	}

	if len(sshdPIDs) == 0 {
		return
	}

	// Build process tree (children of sshd)
	sshChildren := make([]ProcessInfo, 0)
	for _, p := range procs {
		// If PPID is in sshdPIDs or parent chain leads to sshd
		if isChildOfSSH(p, procs, sshdPIDs) {
			sshChildren = append(sshChildren, p)
		}
	}

	// Evaluate each process under SSH
	for _, proc := range sshChildren {
		ramMB := float64(proc.RSSBytes) / (1024 * 1024)

		// 1. RAM Usage Check
		if cfg.MaxRAMMB > 0 && ramMB > cfg.MaxRAMMB {
			msg := fmt.Sprintf("SSH process %s (PID %d) exceeded RAM limit: %.2f MB used (Max: %.2f MB)", proc.Name, proc.PID, ramMB, cfg.MaxRAMMB)
			m.emitViolation("sshd: resource limit exceeded", msg, proc, ramMB, proc.CPUPercent, cfg.AutoKillViolators)
		}

		// 2. CPU Usage Check
		if cfg.MaxCPUPercent > 0 && proc.CPUPercent > cfg.MaxCPUPercent {
			msg := fmt.Sprintf("SSH process %s (PID %d) exceeded CPU limit: %.1f%% used (Max: %.1f%%)", proc.Name, proc.PID, proc.CPUPercent, cfg.MaxCPUPercent)
			m.emitViolation("sshd: resource limit exceeded", msg, proc, ramMB, proc.CPUPercent, cfg.AutoKillViolators)
		}

		cleanName := filepath.Base(proc.Name)
		isShell := shellBinaries[cleanName] || shellBinaries[strings.TrimPrefix(cleanName, "-")]
		isSystemProc := systemIgnoredProcesses[cleanName] || strings.Contains(strings.ToLower(proc.Name), "sshd") || strings.Contains(strings.ToLower(cleanName), "seimlite")

		// 3. Child Shell Check
		if !cfg.AllowChildShell && isShell {
			msg := fmt.Sprintf("Unauthorized child shell '%s' (PID %d) spawned under SSH session: %s", cleanName, proc.PID, proc.Cmdline)
			m.emitViolation("sshd: unauthorized child shell spawned", msg, proc, ramMB, proc.CPUPercent, cfg.AutoKillViolators)
		}

		// 4. Child Process Check (if general child processes forbidden)
		if !cfg.AllowChildProcess && !isShell && !isSystemProc {
			msg := fmt.Sprintf("Unauthorized child process '%s' (PID %d) spawned under SSH session", proc.Name, proc.PID)
			m.emitViolation("sshd: unauthorized process execution", msg, proc, ramMB, proc.CPUPercent, cfg.AutoKillViolators)
		}

		// 5. Blacklisted Process Check
		for _, blocked := range cfg.BlockedChildProcesses {
			if blocked != "" && (cleanName == blocked || strings.Contains(strings.ToLower(proc.Cmdline), strings.ToLower(blocked))) {
				msg := fmt.Sprintf("Blocked process/command '%s' (PID %d) executed under SSH: %s", blocked, proc.PID, proc.Cmdline)
				m.emitViolation("sshd: unauthorized process execution", msg, proc, ramMB, proc.CPUPercent, cfg.AutoKillViolators)
				break
			}
		}

		// 6. Whitelisted Process Check (if whitelist specified and non-empty)
		if len(cfg.AllowedChildProcesses) > 0 && !isShell && !isSystemProc {
			allowed := false
			for _, allow := range cfg.AllowedChildProcesses {
				if allow != "" && (cleanName == allow || strings.Contains(strings.ToLower(proc.Cmdline), strings.ToLower(allow))) {
					allowed = true
					break
				}
			}
			if !allowed {
				msg := fmt.Sprintf("Process '%s' (PID %d) not in allowed process whitelist under SSH: %s", cleanName, proc.PID, proc.Cmdline)
				m.emitViolation("sshd: unauthorized process execution", msg, proc, ramMB, proc.CPUPercent, cfg.AutoKillViolators)
			}
		}
	}
}

func isChildOfSSH(p ProcessInfo, allProcs map[int]ProcessInfo, sshdPIDs map[int]bool) bool {
	currPPID := p.PPID
	for depth := 0; depth < 5; depth++ {
		if sshdPIDs[currPPID] {
			return true
		}
		parent, exists := allProcs[currPPID]
		if !exists || parent.PPID == 0 || parent.PPID == currPPID {
			break
		}
		currPPID = parent.PPID
	}
	return false
}

func (m *SSHMonitor) emitViolation(ruleDesc string, msg string, proc ProcessInfo, ramMB float64, cpuPct float64, autoKill bool) {
	violationKey := fmt.Sprintf("%d:%s", proc.PID, ruleDesc)
	if lastAlert, exists := m.alertedPIDs[violationKey]; exists {
		if time.Since(lastAlert) < 60*time.Second {
			// Suppress duplicate alert for the same PID & rule within 60 seconds
			return
		}
	}
	m.alertedPIDs[violationKey] = time.Now()

	fmt.Printf("[MONITOR SECURITY ALERT] %s\n", msg)

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "localhost"
	}

	event := models.NewNormalizedEvent()
	event.Agent.Name = hostname
	event.Agent.IP = "127.0.0.1"
	event.Decoder.Name = "sshd-monitor"
	event.Rule.Level = 5
	event.Rule.Description = ruleDesc
	event.Rule.ID = "5790"
	event.Rule.Groups = []string{"syslog", "sshd", "security_policy"}
	event.FullLog = msg
	event.Data.SrcIP = "127.0.0.1"
	event.Data.DstUser = "ssh-user"
	event.Data.PID = proc.PID
	event.Data.Command = proc.Cmdline
	event.Data.RAMUsageMB = ramMB
	event.Data.CPUPercent = cpuPct

	// Save to storage
	_ = storage.InsertEvent(event)

	// Dispatch to correlation engine
	if m.eventChan != nil {
		m.eventChan <- event
	}

	// Auto-kill if enabled
	if autoKill && proc.PID > 1 {
		fmt.Printf("[MONITOR ENFORCEMENT] Terminating violating process PID %d (%s)...\n", proc.PID, proc.Name)
		p, err := os.FindProcess(proc.PID)
		if err == nil {
			_ = p.Kill()
		}
	}
}

func getAllProcesses() (map[int]ProcessInfo, error) {
	result := make(map[int]ProcessInfo)
	files, err := os.ReadDir("/proc")
	if err != nil {
		return result, err
	}

	pageSize := uint64(os.Getpagesize())

	for _, f := range files {
		if !f.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(f.Name())
		if err != nil {
			continue
		}

		// Read name and PPID from /proc/[pid]/stat
		statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}
		statStr := string(statBytes)
		openParen := strings.Index(statStr, "(")
		closeParen := strings.LastIndex(statStr, ")")
		if openParen == -1 || closeParen == -1 || closeParen <= openParen {
			continue
		}

		procName := statStr[openParen+1 : closeParen]
		afterParen := strings.Fields(statStr[closeParen+1:])
		if len(afterParen) < 2 {
			continue
		}

		ppid, _ := strconv.Atoi(afterParen[1])

		// Read cmdline
		cmdBytes, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		cmdline := strings.ReplaceAll(string(cmdBytes), "\x00", " ")
		if cmdline == "" {
			cmdline = procName
		}

		// Read RAM (statm)
		rssBytes := uint64(0)
		statmBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/statm", pid))
		if err == nil {
			fields := strings.Fields(string(statmBytes))
			if len(fields) >= 2 {
				pages, _ := strconv.ParseUint(fields[1], 10, 64)
				rssBytes = pages * pageSize
			}
		}

		result[pid] = ProcessInfo{
			PID:        pid,
			PPID:       ppid,
			Name:       procName,
			Cmdline:    cmdline,
			RSSBytes:   rssBytes,
			CPUPercent: 0.0,
		}
	}

	return result, nil
}
