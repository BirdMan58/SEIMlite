// internal/eventstore/store.go
package eventstore

import (
	"errors"
	"time"

	"SEIMlite/internal/models"
)

// EventStore defines the interface for querying historical events from the database.
type EventStore interface {
	// CountFailuresSince returns the number of login failures for a given IP
	// within the last 'duration' seconds.
	CountFailuresSince(ip string, duration time.Duration) (int, error)

	// CountFailuresInWindow returns the total number of login failures for an IP
	// within the given window, but only if no sub-window (2-minute slice) exceeds
	// maxSubWindowFailures. If a sub-window exceeds the limit, it returns
	// ErrSubWindowLimitExceeded.
	CountFailuresInWindow(ip string, window time.Duration, maxSubWindowFailures int) (int, error)

	// GetLastSuccessfulLogin returns the most recent successful login event
	// for a given username.
	GetLastSuccessfulLogin(username string) (*models.NormalizedEvent, error)

	// GetDistinctServicesForSubnet returns the number of distinct services
	// (e.g., ssh, nginx, nextcloud) that have been accessed from the given
	// subnet within the last 'since' duration.
	GetDistinctServicesForSubnet(subnet string, since time.Duration) (int, error)
}

// ErrSubWindowLimitExceeded indicates that a sub-window burst was detected.
var ErrSubWindowLimitExceeded = errors.New("sub-window limit exceeded")
