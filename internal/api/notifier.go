package api

import "SEIMlite/internal/models"

type AlertNotifier interface {
	NotifyAlert(alert *models.CorrelationAlert)
}
