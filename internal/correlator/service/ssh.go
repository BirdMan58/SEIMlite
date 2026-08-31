package service

import (
	"fmt"
	"time"

	"SEIMlite/internal/config"
	"SEIMlite/internal/correlator"
	"SEIMlite/internal/models"
)

// SSHBruteforceRule detects repeated failed logins from the same source IP.
type SSHBruteforceRule struct{}

func (r SSHBruteforceRule) Name() string {
	return "ssh_bruteforce"
}

func (r SSHBruteforceRule) Evaluate(ctx *correlator.RuleContext, event *models.NormalizedEvent) (*models.CorrelationAlert, error) {
	if event.Rule.Description != "sshd: authentication failure" {
		return nil, nil
	}

	srcIP := event.Data.SrcIP
	if srcIP == "" || srcIP == "unknown" {
		return nil, nil
	}

	key := "bf:" + srcIP

	cfg := config.GetConfig().SSH
	threshold := cfg.BruteForceThreshold
	if threshold <= 0 {
		threshold = 5
	}
	window := int64(cfg.BruteForceWindowSeconds)
	if window <= 0 {
		window = 60
	}

	now := time.Now().Unix()
	ctx.Windows[key] = append(ctx.Windows[key], now)

	cutoff := now - window
	var recent []int64
	for _, ts := range ctx.Windows[key] {
		if ts >= cutoff {
			recent = append(recent, ts)
		}
	}
	ctx.Windows[key] = recent

	if len(recent) >= threshold {
		delete(ctx.Windows, key)
		alert := models.NewCorrelationAlert()
		alert.Timestamp = now
		alert.Title = "SSH Brute Force Attack Detected"
		alert.Description = fmt.Sprintf("Detected %d failed SSH login attempts from %s within %d seconds (Threshold: %d)", len(recent), srcIP, window, threshold)
		alert.Severity = 4
		alert.SourceIP = srcIP
		alert.RuleID = "ssh_bruteforce"
		return alert, nil
	}

	return nil, nil
}

// SSHSingleFailureRule alerts on individual login failure.
type SSHSingleFailureRule struct{}

func (r SSHSingleFailureRule) Name() string {
	return "ssh_single_failure"
}

func (r SSHSingleFailureRule) Evaluate(ctx *correlator.RuleContext, event *models.NormalizedEvent) (*models.CorrelationAlert, error) {
	if event.Rule.Description != "sshd: authentication failure" {
		return nil, nil
	}
	alert := models.NewCorrelationAlert()
	alert.Timestamp = time.Now().Unix()
	alert.Title = "SSH Login Failure"
	alert.Description = fmt.Sprintf("Failed SSH login attempt from %s for user '%s'", event.Data.SrcIP, event.Data.DstUser)
	alert.Severity = 2
	alert.SourceIP = event.Data.SrcIP
	alert.RuleID = "ssh_single_failure"
	return alert, nil
}

// SSHUserEnumerationRule detects multiple login attempts for invalid/non-existent system users.
type SSHUserEnumerationRule struct{}

func (r SSHUserEnumerationRule) Name() string {
	return "ssh_user_enumeration"
}

func (r SSHUserEnumerationRule) Evaluate(ctx *correlator.RuleContext, event *models.NormalizedEvent) (*models.CorrelationAlert, error) {
	if event.Data.IsValidUser || (event.Rule.Description != "sshd: authentication failure" && event.Rule.Description != "sshd: invalid user login attempt") {
		return nil, nil
	}

	srcIP := event.Data.SrcIP
	if srcIP == "" || srcIP == "unknown" {
		return nil, nil
	}

	key := "enum:" + srcIP

	cfg := config.GetConfig().SSH
	threshold := cfg.UserEnumThreshold
	if threshold <= 0 {
		threshold = 3
	}

	now := time.Now().Unix()
	ctx.Windows[key] = append(ctx.Windows[key], now)

	cutoff := now - 120
	var recent []int64
	for _, ts := range ctx.Windows[key] {
		if ts >= cutoff {
			recent = append(recent, ts)
		}
	}
	ctx.Windows[key] = recent

	if len(recent) >= threshold {
		delete(ctx.Windows, key)
		alert := models.NewCorrelationAlert()
		alert.Timestamp = now
		alert.Title = "SSH User Enumeration Attack"
		alert.Description = fmt.Sprintf("Detected %d login attempts for non-existent users from %s (Target user: '%s')", len(recent), srcIP, event.Data.DstUser)
		alert.Severity = 4
		alert.SourceIP = srcIP
		alert.RuleID = "ssh_user_enumeration"
		return alert, nil
	}

	return nil, nil
}

// SSHRootLoginRule flags root login attempts (success or failure).
type SSHRootLoginRule struct{}

func (r SSHRootLoginRule) Name() string {
	return "ssh_root_login"
}

func (r SSHRootLoginRule) Evaluate(ctx *correlator.RuleContext, event *models.NormalizedEvent) (*models.CorrelationAlert, error) {
	cfg := config.GetConfig().SSH
	if !cfg.AlertOnRootLogin {
		return nil, nil
	}

	if event.Data.DstUser != "root" && !event.Data.IsRoot {
		return nil, nil
	}

	alert := models.NewCorrelationAlert()
	alert.Timestamp = time.Now().Unix()
	alert.SourceIP = event.Data.SrcIP
	alert.RuleID = "ssh_root_login"

	if event.Rule.Description == "sshd: authentication success" {
		alert.Title = "SSH Root Login Successful"
		alert.Description = fmt.Sprintf("Successful root login from %s via %s", event.Data.SrcIP, event.Data.AuthMethod)
		alert.Severity = 5
		return alert, nil
	} else if event.Rule.Description == "sshd: authentication failure" || event.Rule.Description == "sshd: invalid user login attempt" {
		alert.Title = "SSH Root Login Attempt Failed"
		alert.Description = fmt.Sprintf("Failed root login attempt from %s", event.Data.SrcIP)
		alert.Severity = 3
		return alert, nil
	}

	return nil, nil
}

// SSHBruteForceSuccessRule alerts when a successful login occurs from an IP that had recent failed attempts.
type SSHBruteForceSuccessRule struct{}

func (r SSHBruteForceSuccessRule) Name() string {
	return "ssh_bruteforce_success"
}

func (r SSHBruteForceSuccessRule) Evaluate(ctx *correlator.RuleContext, event *models.NormalizedEvent) (*models.CorrelationAlert, error) {
	cfg := config.GetConfig().SSH
	if !cfg.AlertOnBruteForceSuccess {
		return nil, nil
	}

	srcIP := event.Data.SrcIP
	if srcIP == "" || srcIP == "unknown" {
		return nil, nil
	}

	key := "bf_success:" + srcIP
	now := time.Now().Unix()

	if event.Rule.Description == "sshd: authentication failure" {
		ctx.Windows[key] = append(ctx.Windows[key], now)
		return nil, nil
	}

	if event.Rule.Description == "sshd: authentication success" {
		timestamps, exists := ctx.Windows[key]
		if !exists || len(timestamps) == 0 {
			return nil, nil
		}

		cutoff := now - 300 // 5 min window
		failedCount := 0
		for _, ts := range timestamps {
			if ts >= cutoff {
				failedCount++
			}
		}

		if failedCount >= 2 {
			delete(ctx.Windows, key)
			alert := models.NewCorrelationAlert()
			alert.Timestamp = now
			alert.Title = "CRITICAL: Successful SSH Login After Brute Force Attempts"
			alert.Description = fmt.Sprintf("Successful login for user '%s' from %s after %d failed login attempts", event.Data.DstUser, srcIP, failedCount)
			alert.Severity = 5
			alert.SourceIP = srcIP
			alert.RuleID = "ssh_bruteforce_success"
			return alert, nil
		}
	}

	return nil, nil
}

// SSHInvalidUserRule alerts on login attempts to non-existent system users.
type SSHInvalidUserRule struct{}

func (r SSHInvalidUserRule) Name() string {
	return "ssh_invalid_user"
}

func (r SSHInvalidUserRule) Evaluate(ctx *correlator.RuleContext, event *models.NormalizedEvent) (*models.CorrelationAlert, error) {
	cfg := config.GetConfig().SSH
	if !cfg.AlertOnInvalidUser {
		return nil, nil
	}

	if !event.Data.IsValidUser && (event.Rule.Description == "sshd: invalid user login attempt" || event.Rule.Description == "sshd: authentication failure") {
		alert := models.NewCorrelationAlert()
		alert.Timestamp = time.Now().Unix()
		alert.Title = "SSH Invalid User Login Attempt"
		alert.Description = fmt.Sprintf("Attempted SSH login for non-existent system user '%s' from %s", event.Data.DstUser, event.Data.SrcIP)
		alert.Severity = 3
		alert.SourceIP = event.Data.SrcIP
		alert.RuleID = "ssh_invalid_user"
		return alert, nil
	}

	return nil, nil
}

// SSHResourceViolationRule alerts when RAM or CPU usage exceeds configured limits.
type SSHResourceViolationRule struct{}

func (r SSHResourceViolationRule) Name() string {
	return "ssh_resource_violation"
}

func (r SSHResourceViolationRule) Evaluate(ctx *correlator.RuleContext, event *models.NormalizedEvent) (*models.CorrelationAlert, error) {
	if event.Rule.Description != "sshd: resource limit exceeded" {
		return nil, nil
	}

	alert := models.NewCorrelationAlert()
	alert.Timestamp = time.Now().Unix()
	alert.Title = "SSH Resource Limit Exceeded"
	alert.Description = event.FullLog
	alert.Severity = 4
	alert.SourceIP = "local"
	alert.RuleID = "ssh_resource_violation"
	return alert, nil
}

// SSHUnauthorizedProcessRule alerts when unauthorized child processes or shells are executed under SSH.
type SSHUnauthorizedProcessRule struct{}

func (r SSHUnauthorizedProcessRule) Name() string {
	return "ssh_unauthorized_process"
}

func (r SSHUnauthorizedProcessRule) Evaluate(ctx *correlator.RuleContext, event *models.NormalizedEvent) (*models.CorrelationAlert, error) {
	if event.Rule.Description != "sshd: unauthorized process execution" && event.Rule.Description != "sshd: unauthorized child shell spawned" {
		return nil, nil
	}

	alert := models.NewCorrelationAlert()
	alert.Timestamp = time.Now().Unix()
	alert.Title = "SSH Security Policy Violation"
	alert.Description = event.FullLog
	alert.Severity = 4
	alert.SourceIP = "local"
	alert.RuleID = "ssh_unauthorized_process"
	return alert, nil
}
