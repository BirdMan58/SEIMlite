package normalizer

import "SEIMlite/internal/models"

type Normalizer interface {
	// Start runs the normalizer. It sends parsed events to eventChan.
	Start(pretty bool, eventChan chan<- *models.NormalizedEvent) error
	ServiceName() string
}
