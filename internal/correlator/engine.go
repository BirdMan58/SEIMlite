package correlator

import (
	"fmt"
	"sync"
	"time"

	"SEIMlite/internal/models"
)

type Engine struct {
	rules    []Rule
	contexts map[string]*RuleContext
	mu       sync.Mutex
	eventCh  <-chan *models.NormalizedEvent
	notifier AlertNotifier
}

func NewEngine(eventCh <-chan *models.NormalizedEvent, notifier AlertNotifier) *Engine {
	return &Engine{
		rules:    []Rule{},
		contexts: make(map[string]*RuleContext),
		eventCh:  eventCh,
		notifier: notifier,
	}
}

// Register adds a rule to the engine.
func (e *Engine) Register(rule Rule) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rules = append(e.rules, rule)
	e.contexts[rule.Name()] = &RuleContext{
		Windows: make(map[string][]int64),
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
				fmt.Printf("[ACTION] Blocking IP %s (SIMULATED - No actual firewall change)\n", alert.SourceIP)
				fmt.Println("============================================")

				// For actual use, replace the print above with:
				// blocker.BlockIP(alert.SourceIP) // Calls iptables

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
