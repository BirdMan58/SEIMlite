package service

import (
	"fmt"
	"time"

	"SEIMlite/internal/correlator"
	"SEIMlite/internal/models"
)

const (
	sshThreshold = 5
	sshWindow    = 60 // seconds
)

type SSHBruteforceRule struct{}

func (r SSHBruteforceRule) Name() string {
	return "ssh_bruteforce"
}

func (r SSHBruteforceRule) Evaluate(ctx *correlator.RuleContext, event *models.NormalizedEvent) (*models.CorrelationAlert, error) {
	// 1. Only care about SSH failures
	if event.Rule.Description != "sshd: authentication failure" {
		return nil, nil
	}

	srcIP := event.Data.SrcIP
	if srcIP == "" {
		return nil, nil
	}

	now := time.Now().Unix()

	// 2. Add timestamp to the sliding window
	ctx.Windows[srcIP] = append(ctx.Windows[srcIP], now)

	// 3. Clean up old timestamps (keep only those within the window)
	cutoff := now - sshWindow
	var recent []int64
	for _, ts := range ctx.Windows[srcIP] {
		if ts >= cutoff {
			recent = append(recent, ts)
		}
	}
	ctx.Windows[srcIP] = recent

	// 4. Check if threshold is met
	if len(recent) >= sshThreshold {
		// Clear the window for this IP to prevent re-triggering immediately
		delete(ctx.Windows, srcIP)

		return &models.CorrelationAlert{
			Timestamp:   now,
			Title:       "SSH Brute Force Attack",
			Description: fmt.Sprintf("Detected %d failed SSH login attempts from %s in %d seconds", len(recent), srcIP, sshWindow),
			Severity:    4,
			SourceIP:    srcIP,
		}, nil
	}

	return nil, nil
}

type SSHSingleFailureRule struct{}

func (r SSHSingleFailureRule) Name() string {
	return "ssh_single_failure"
}

func (r SSHSingleFailureRule) Evaluate(ctx *correlator.RuleContext, event *models.NormalizedEvent) (*models.CorrelationAlert, error) {
	if event.Rule.Description != "sshd: authentication failure" {
		return nil, nil
	}
	return &models.CorrelationAlert{
		Timestamp:   time.Now().Unix(),
		Title:       "SSH Login Failure",
		Description: fmt.Sprintf("Failed SSH login attempt from %s for user %s", event.Data.SrcIP, event.Data.DstUser),
		Severity:    2,
		SourceIP:    event.Data.SrcIP,
	}, nil
}
