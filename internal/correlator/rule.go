package correlator

import (
	"SEIMlite/internal/eventstore"
	"SEIMlite/internal/models"
)

// RuleContext holds the sliding windows for a specific rule.
type RuleContext struct {
	Windows map[string][]int64
	Store   eventstore.EventStore // added
}

// Rule defines the interface for all correlation rules.
type Rule interface {
	Name() string
	Evaluate(ctx *RuleContext, event *models.NormalizedEvent) (*models.CorrelationAlert, error)
}
