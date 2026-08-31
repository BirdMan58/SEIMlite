package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type SSHConfig struct {
	// Resource Limits
	MaxRAMMB      float64 `json:"max_ram_mb"`      // Max RAM per SSH process tree in MB (e.g. 256.0)
	MaxCPUPercent float64 `json:"max_cpu_percent"` // Max CPU percentage (e.g. 80.0)

	// Process & Shell Execution Permissions
	AllowChildProcess     bool     `json:"allow_child_process"`     // Allow SSH session to spawn child processes
	AllowChildShell       bool     `json:"allow_child_shell"`       // Allow interactive child shells (bash, sh, zsh, etc.)
	AllowedChildProcesses []string `json:"allowed_child_processes"` // Whitelisted child processes
	BlockedChildProcesses []string `json:"blocked_child_processes"` // Blacklisted child processes
	AutoKillViolators     bool     `json:"auto_kill_violators"`     // Terminate processes exceeding resource/permission limits

	// Detection Rules & Thresholds
	BruteForceThreshold       int  `json:"brute_force_threshold"`        // Failed attempts before brute force alert (e.g. 5)
	BruteForceWindowSeconds   int  `json:"brute_force_window_seconds"`   // Sliding window in seconds (e.g. 60)
	UserEnumThreshold         int  `json:"user_enum_threshold"`          // Failed attempts with invalid users before enum alert (e.g. 3)
	AlertOnRootLogin          bool `json:"alert_on_root_login"`          // Alert on root login attempt or success
	AlertOnBruteForceSuccess  bool `json:"alert_on_bruteforce_success"`  // Alert when login succeeds after multiple failures
	AlertOnInvalidUser        bool `json:"alert_on_invalid_user"`        // Alert on login attempts for non-existent users
	SessionMonitoring         bool `json:"session_monitoring"`           // Monitor session open/close events
	ProcessMonitorIntervalSec int  `json:"process_monitor_interval_sec"` // Check interval for proc monitor (e.g. 3)
}

type Config struct {
	SSH SSHConfig `json:"ssh"`
}

var (
	GlobalConfig *Config
	configMutex  sync.RWMutex
	ConfigPath   string = "configs/ssh-config.json"
)

func DefaultConfig() *Config {
	return &Config{
		SSH: SSHConfig{
			MaxRAMMB:                  256.0,
			MaxCPUPercent:             80.0,
			AllowChildProcess:         true,
			AllowChildShell:           true,
			AllowedChildProcesses:     []string{"bash", "sh", "sftp-server", "scp", "git-receive-pack", "rsync"},
			BlockedChildProcesses:     []string{"nc", "ncat", "netcat", "socat", "python3", "perl", "curl", "wget", "chmod", "chown"},
			AutoKillViolators:         false,
			BruteForceThreshold:       5,
			BruteForceWindowSeconds:   60,
			UserEnumThreshold:         3,
			AlertOnRootLogin:          true,
			AlertOnBruteForceSuccess:  true,
			AlertOnInvalidUser:        true,
			SessionMonitoring:         true,
			ProcessMonitorIntervalSec: 3,
		},
	}
}

func LoadConfig(path string) (*Config, error) {
	configMutex.Lock()
	defer configMutex.Unlock()

	if path != "" {
		ConfigPath = path
	}

	// If file doesn't exist, create directory and write defaults
	if _, err := os.Stat(ConfigPath); os.IsNotExist(err) {
		cfg := DefaultConfig()
		dir := filepath.Dir(ConfigPath)
		if dir != "." && dir != "" {
			_ = os.MkdirAll(dir, 0755)
		}
		data, err := json.MarshalIndent(cfg, "", "  ")
		if err == nil {
			_ = os.WriteFile(ConfigPath, data, 0644)
		}
		GlobalConfig = cfg
		return cfg, nil
	}

	data, err := os.ReadFile(ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %s: %w", ConfigPath, err)
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file %s: %w", ConfigPath, err)
	}

	GlobalConfig = cfg
	return cfg, nil
}

func SaveConfig(path string, cfg *Config) error {
	configMutex.Lock()
	defer configMutex.Unlock()

	targetPath := path
	if targetPath == "" {
		targetPath = ConfigPath
	}

	dir := filepath.Dir(targetPath)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(targetPath, data, 0644); err != nil {
		return err
	}

	GlobalConfig = cfg
	return nil
}

func GetConfig() *Config {
	configMutex.RLock()
	defer configMutex.RUnlock()
	if GlobalConfig == nil {
		return DefaultConfig()
	}
	return GlobalConfig
}
