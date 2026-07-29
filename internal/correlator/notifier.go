package correlator

import "SEIMlite/internal/models"

// AlertNotifier is implemented by components that want to receive alerts
// from the correlation engine (e.g., the API server for WebSocket broadcast).
type AlertNotifier interface {
	NotifyAlert(alert *models.CorrelationAlert)
}
