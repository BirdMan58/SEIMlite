package correlator

import "SEIMlite/internal/models"

// RuleContext holds the sliding windows for a specific rule.
type RuleContext struct {
	Windows map[string][]int64 // Key: IP address, Value: slice of timestamps
}

// Rule defines the interface for all correlation rules.
type Rule interface {
	Name() string
	Evaluate(ctx *RuleContext, event *models.NormalizedEvent) (*models.CorrelationAlert, error)
}
