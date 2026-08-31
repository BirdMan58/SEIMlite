package correlator

import (
	"fmt"
	"os"
	"sync"
	"time"

	"SEIMlite/internal/eventstore"
	"SEIMlite/internal/models"
	"SEIMlite/internal/storage"
)

// Add EventStore to the Engine struct
type Engine struct {
	rules      []Rule
	contexts   map[string]*RuleContext
	mu         sync.Mutex
	eventCh    <-chan *models.NormalizedEvent
	notifier   AlertNotifier
	eventStore eventstore.EventStore // new field
}

// NewEngine now accepts an EventStore
func NewEngine(eventCh <-chan *models.NormalizedEvent, notifier AlertNotifier, store eventstore.EventStore) *Engine {
	return &Engine{
		rules:      []Rule{},
		contexts:   make(map[string]*RuleContext),
		eventCh:    eventCh,
		notifier:   notifier,
		eventStore: store,
	}
}

// Register creates a rule context with the event store
func (e *Engine) Register(rule Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
	e.contexts[rule.Name()] = &RuleContext{
		Windows: make(map[string][]int64),
		Store:   e.eventStore, // pass the store to the rule
	}
}

// Start begins the main event loop.
func (e *Engine) Start() {
	fmt.Println("[CORRELATOR] Engine started. Monitoring for threats...")

	// Cleanup goroutine: runs every 60 seconds to free memory
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		for range ticker.C {
			e.cleanup()
		}
	}()

	// Main event loop
	for event := range e.eventCh {
		e.mu.Lock()
		for _, rule := range e.rules {
			ctx := e.contexts[rule.Name()]
			alert, err := rule.Evaluate(ctx, event)
			if err != nil {
				fmt.Printf("[CORRELATOR ERROR] Rule %s: %v\n", rule.Name(), err)
				continue
			}
			if alert != nil {
				// =============================================
				// THE "BLOCKING" PART FOR TESTING
				// =============================================
				fmt.Printf("\n[!!! ALERT !!!] %s\n", alert.Title)
				fmt.Printf("Description: %s\n", alert.Description)
				fmt.Printf("Severity: %d/5\n", alert.Severity)
				if alert.SourceIP != "" && alert.SourceIP != "127.0.0.1" && alert.SourceIP != "localhost" && alert.SourceIP != "local" {
					fmt.Printf("[ACTION] Blocking IP %s (SIMULATED - No actual firewall change)\n", alert.SourceIP)
				}
				fmt.Println("============================================")

				// For actual use, replace the print above with:
				// blocker.BlockIP(alert.SourceIP) // Calls iptables

				if err := storage.InsertAlert(alert); err != nil {
					fmt.Fprintf(os.Stderr, "Error inserting alert into DB: %v\n", err)
				}

				if e.notifier != nil {
					e.notifier.NotifyAlert(alert)
				}
			}
		}
		e.mu.Unlock()
	}
}

// cleanup removes timestamps older than 120 seconds to prevent memory bloat.
func (e *Engine) cleanup() {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now().Unix()
	for _, ctx := range e.contexts {
		for ip, timestamps := range ctx.Windows {
			var recent []int64
			for _, ts := range timestamps {
				if ts > now-120 { // Keep last 2 minutes globally
					recent = append(recent, ts)
				}
			}
			if len(recent) == 0 {
				delete(ctx.Windows, ip)
			} else {
				ctx.Windows[ip] = recent
			}
		}
	}
}
