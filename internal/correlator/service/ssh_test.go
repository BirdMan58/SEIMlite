package service

import (
	"testing"

	"SEIMlite/internal/config"
	"SEIMlite/internal/correlator"
	"SEIMlite/internal/models"
)

func TestSSHConfigAndRules(t *testing.T) {
	// Initialize default config
	cfg := config.DefaultConfig()
	cfg.SSH.BruteForceThreshold = 3
	cfg.SSH.UserEnumThreshold = 2
	cfg.SSH.AlertOnRootLogin = true
	cfg.SSH.AlertOnBruteForceSuccess = true
	_ = config.SaveConfig("configs/test_ssh_config.json", cfg)

	ctx := &correlator.RuleContext{
		Windows: make(map[string][]int64),
	}

	// 1. Test SSHBruteforceRule
	bfRule := SSHBruteforceRule{}
	eventFail := models.NewNormalizedEvent()
	eventFail.Rule.Description = "sshd: authentication failure"
	eventFail.Data.SrcIP = "192.168.1.100"
	eventFail.Data.DstUser = "admin"
	eventFail.Data.IsValidUser = true

	// First failure - no alert yet
	alert, _ := bfRule.Evaluate(ctx, eventFail)
	if alert != nil {
		t.Fatalf("Expected no alert on 1st failure, got %v", alert)
	}

	// Second failure - no alert yet
	alert, _ = bfRule.Evaluate(ctx, eventFail)
	if alert != nil {
		t.Fatalf("Expected no alert on 2nd failure, got %v", alert)
	}

	// Third failure - alert!
	alert, _ = bfRule.Evaluate(ctx, eventFail)
	if alert == nil {
		t.Fatalf("Expected brute force alert on 3rd failure")
	}
	if alert.Severity != 4 {
		t.Errorf("Expected severity 4, got %d", alert.Severity)
	}

	// 2. Test SSHRootLoginRule
	rootRule := SSHRootLoginRule{}
	eventRoot := models.NewNormalizedEvent()
	eventRoot.Rule.Description = "sshd: authentication success"
	eventRoot.Data.SrcIP = "10.0.0.5"
	eventRoot.Data.DstUser = "root"
	eventRoot.Data.IsRoot = true
	eventRoot.Data.AuthMethod = "password"

	alert, _ = rootRule.Evaluate(ctx, eventRoot)
	if alert == nil {
		t.Fatalf("Expected alert on root login success")
	}
	if alert.Severity != 5 {
		t.Errorf("Expected severity 5 for root login, got %d", alert.Severity)
	}

	// 3. Test SSHUserEnumerationRule
	enumRule := SSHUserEnumerationRule{}
	eventInvalid := models.NewNormalizedEvent()
	eventInvalid.Rule.Description = "sshd: invalid user login attempt"
	eventInvalid.Data.SrcIP = "172.16.0.50"
	eventInvalid.Data.DstUser = "nonexistent_hacker_user"
	eventInvalid.Data.IsValidUser = false

	alert, _ = enumRule.Evaluate(ctx, eventInvalid) // 1st
	if alert != nil {
		t.Fatalf("Expected no enum alert on 1st invalid user attempt")
	}

	alert, _ = enumRule.Evaluate(ctx, eventInvalid) // 2nd (threshold = 2)
	if alert == nil {
		t.Fatalf("Expected user enumeration alert on 2nd invalid user attempt")
	}
}
