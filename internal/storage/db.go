// internal/storage/db.go
package storage

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver

	"SEIMlite/internal/eventstore"
	"SEIMlite/internal/models"
)

// ============================================================
// GLOBAL DB HANDLE
// ============================================================

var db *sql.DB

// InitDB opens the SQLite database and creates tables if they don't exist.
func InitDB(dbPath string) error {
	var err error
	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	if err := createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}
	return nil
}

// CloseDB closes the database connection.
func CloseDB() error {
	if db != nil {
		return db.Close()
	}
	return nil
}

// GetDB returns the global database handle.
func GetDB() *sql.DB {
	return db
}

// ============================================================
// TABLE CREATION
// ============================================================

func createTables() error {
	eventsTable := `
	CREATE TABLE IF NOT EXISTS events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp INTEGER NOT NULL,
		source TEXT NOT NULL,
		event_type TEXT NOT NULL,
		src_ip TEXT,
		dst_user TEXT,
		severity INTEGER,
		raw_data TEXT,
		full_log TEXT,
		location TEXT,
		decoder TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
	CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_events_dst_user ON events(dst_user);
	CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);
	`

	alertsTable := `
	CREATE TABLE IF NOT EXISTS alerts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp INTEGER NOT NULL,
		title TEXT NOT NULL,
		description TEXT NOT NULL,
		severity INTEGER NOT NULL,
		source_ip TEXT,
		rule_id TEXT,
		requires_ack INTEGER DEFAULT 0,
		event_ids TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);
	`

	_, err := db.Exec(eventsTable)
	if err != nil {
		return err
	}
	_, err = db.Exec(alertsTable)
	return err
}

// ============================================================
// EVENT INSERTION
// ============================================================

// InsertEvent stores a normalized event in the database.
func InsertEvent(event *models.NormalizedEvent) error {
	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	t, err := time.Parse(time.RFC3339, event.Timestamp)
	if err != nil {
		return fmt.Errorf("invalid timestamp format: %w", err)
	}
	timestamp := t.Unix()

	query := `
	INSERT INTO events
	(timestamp, source, event_type, src_ip, dst_user, severity, raw_data, full_log, location, decoder)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err = db.Exec(query,
		timestamp,
		event.Decoder.Name,     // source = decoder name
		event.Rule.Description, // event_type (we can refine later)
		event.Data.SrcIP,
		event.Data.DstUser,
		event.Rule.Level,
		"{}", // raw_data placeholder
		event.FullLog,
		event.Location,
		event.Decoder.Name,
	)
	if err != nil {
		return fmt.Errorf("failed to insert event: %w", err)
	}
	return nil
}

// ============================================================
// ALERT OPERATIONS
// ============================================================

// InsertAlert stores a correlation alert in the database.
func InsertAlert(alert *models.CorrelationAlert) error {
	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	eventIDsJSON := "[]"
	if len(alert.EventIDs) > 0 {
		eventIDsJSON = fmt.Sprintf("[%v]", alert.EventIDs)
	}

	query := `
	INSERT INTO alerts
	(timestamp, title, description, severity, source_ip, rule_id, requires_ack, event_ids)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query,
		alert.Timestamp,
		alert.Title,
		alert.Description,
		alert.Severity,
		alert.SourceIP,
		alert.RuleID,
		alert.RequiresAck,
		eventIDsJSON,
	)
	if err != nil {
		return fmt.Errorf("failed to insert alert: %w", err)
	}
	return nil
}

// GetRecentAlerts returns the most recent alerts (up to limit).
func GetRecentAlerts(limit int) ([]*models.CorrelationAlert, error) {
	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}
	query := `
	SELECT timestamp, title, description, severity, source_ip, rule_id, requires_ack
	FROM alerts
	ORDER BY timestamp DESC
	LIMIT ?
	`
	rows, err := db.Query(query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query alerts: %w", err)
	}
	defer rows.Close()

	var alerts []*models.CorrelationAlert
	for rows.Next() {
		var a models.CorrelationAlert
		var ack int
		err := rows.Scan(&a.Timestamp, &a.Title, &a.Description, &a.Severity, &a.SourceIP, &a.RuleID, &ack)
		if err != nil {
			return nil, err
		}
		a.RequiresAck = ack == 1
		alerts = append(alerts, &a)
	}
	return alerts, nil
}

// ============================================================
// EVENT STORE IMPLEMENTATION
// ============================================================

// SQLiteEventStore implements eventstore.EventStore.
type SQLiteEventStore struct {
	db *sql.DB
}

func NewEventStore(db *sql.DB) *SQLiteEventStore {
	return &SQLiteEventStore{db: db}
}

func (s *SQLiteEventStore) CountFailuresSince(ip string, duration time.Duration) (int, error) {
	now := time.Now().Unix()
	since := now - int64(duration.Seconds())
	query := `SELECT COUNT(*) FROM events WHERE src_ip = ? AND event_type = 'login_failure' AND timestamp >= ?`
	var count int
	err := s.db.QueryRow(query, ip, since).Scan(&count)
	return count, err
}

func (s *SQLiteEventStore) CountFailuresInWindow(ip string, window time.Duration, maxSubWindowFailures int) (int, error) {
	now := time.Now().Unix()
	start := now - int64(window.Seconds())

	var total int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM events WHERE src_ip = ? AND event_type = 'login_failure' AND timestamp >= ? AND timestamp <= ?`,
		ip, start, now).Scan(&total)
	if err != nil {
		return 0, err
	}
	if total == 0 {
		return 0, nil
	}

	const subWindow = 120
	rows, err := s.db.Query(`
		SELECT COUNT(*)
		FROM events
		WHERE src_ip = ? AND event_type = 'login_failure' AND timestamp >= ? AND timestamp <= ?
		GROUP BY (timestamp / ?)`,
		ip, start, now, subWindow)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	for rows.Next() {
		var c int
		if err := rows.Scan(&c); err != nil {
			return 0, err
		}
		if c >= maxSubWindowFailures {
			return 0, eventstore.ErrSubWindowLimitExceeded // use eventstore error
		}
	}
	return total, nil
}

// GetLastSuccessfulLogin returns the most recent successful login for a user.
func (s *SQLiteEventStore) GetLastSuccessfulLogin(username string) (*models.NormalizedEvent, error) {
	query := `
	SELECT timestamp, source, event_type, src_ip, dst_user, severity, full_log, location, decoder
	FROM events
	WHERE dst_user = ? AND event_type = 'login_success'
	ORDER BY timestamp DESC
	LIMIT 1
	`
	var ts int64
	var source, eventType, srcIP, dstUser, fullLog, location, decoder string
	var severity int
	err := s.db.QueryRow(query, username).Scan(&ts, &source, &eventType, &srcIP, &dstUser, &severity, &fullLog, &location, &decoder)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	event := &models.NormalizedEvent{
		Timestamp: time.Unix(ts, 0).UTC().Format("2006-01-02T15:04:05.000Z07:00"),
		FullLog:   fullLog,
		Location:  location,
	}
	event.Data.SrcIP = srcIP
	event.Data.DstUser = dstUser
	event.Data.Username = dstUser
	event.Rule.Description = fmt.Sprintf("%s: %s", source, eventType)
	event.Rule.Level = severity
	event.Decoder.Name = decoder
	return event, nil
}

// GetDistinctServicesForSubnet counts distinct services accessed from a subnet prefix.
func (s *SQLiteEventStore) GetDistinctServicesForSubnet(subnet string, since time.Duration) (int, error) {
	now := time.Now().Unix()
	start := now - int64(since.Seconds())
	if !strings.HasSuffix(subnet, ".") && !strings.Contains(subnet, "/") {
		subnet = subnet + "."
	}
	query := `SELECT COUNT(DISTINCT source) FROM events WHERE src_ip LIKE ? AND timestamp >= ?`
	var count int
	err := s.db.QueryRow(query, subnet+"%", start).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}
