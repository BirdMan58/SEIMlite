package main

import (
	"flag"
	"fmt"
	"time"

	"SEIMlite/internal/api"
	"SEIMlite/internal/correlator"
	"SEIMlite/internal/correlator/service"
	"SEIMlite/internal/discovery"
	"SEIMlite/internal/models"
	"SEIMlite/internal/normalizer"
)

func main() {
	pretty := flag.Bool("pretty", false, "Pretty-print normalized JSON")
	addr := flag.String("addr", ":9000", "Dashboard address")
	flag.Parse()

	fmt.Println("[  STARTED ] SEIMlite initializing...")

	// Create API server and hub
	hub := api.NewHub()
	server := api.NewServer(hub)

	// Event channel
	eventChan := make(chan *models.NormalizedEvent, 1000)

	// Correlation Engine (with notifier)
	engine := correlator.NewEngine(eventChan, server)
	engine.Register(service.SSHBruteforceRule{})    // Alerts on 5 failures
	engine.Register(service.SSHSingleFailureRule{}) // Alerts on every single failure
	go engine.Start()

	// Service Discovery and Normalizers
	fmt.Println("[  STARTED ] Starting service enumeration...")
	time.Sleep(500 * time.Millisecond)

	services := discovery.Discover()

	normalizerRegistry := map[string]func() normalizer.Normalizer{
		"ssh": func() normalizer.Normalizer { return normalizer.SSHNormalizer{} },
	}

	for name, running := range services {
		if running {
			fmt.Printf("[    OK    ] Enumerated service: %-12s\n", name)
			if newNormalizer, exists := normalizerRegistry[name]; exists {
				fmt.Printf("→ Starting %s normalizer...\n", name)
				norm := newNormalizer()
				go func() {
					if err := norm.Start(*pretty, eventChan); err != nil {
						fmt.Printf("Error in %s normalizer: %v\n", name, err)
					}
				}()
			} else {
				fmt.Printf("→ (Normalizer for %s not yet implemented)\n", name)
			}
		} else {
			fmt.Printf("[  SKIPPED ] %-12s service not found\n", name)
		}
		time.Sleep(350 * time.Millisecond)
	}

	fmt.Println("[ COMPLETE ] SEIMlite is fully operational.")
	fmt.Printf("[ DASHBOARD ] Open http://localhost%s\n", *addr)

	// Start HTTP server (blocks)
	if err := server.Start(*addr); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}
