// Package abuseipdb provides a SQLite-backed cache for AbuseIPDB blocked IP addresses.
// It fetches the blacklist from the AbuseIPDB API and stores it locally so that
// incoming traffic can be checked without hitting the API on every request.
package abuseipdb

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	_ "modernc.org/sqlite" // SQLite driver
)


const (
	// DefaultDBPath is the default path for the SQLite database file.
	DefaultDBPath = "abuseipdb_cache.db"

	// AbuseIPDBBlacklistURL is the AbuseIPDB v2 blacklist endpoint.
	AbuseIPDBBlacklistURL = "https://api.abuseipdb.com/api/v2/blacklist"

	// DefaultConfidenceMinimum is the minimum confidence score (0-100) to include an IP.
	DefaultConfidenceMinimum = 90

	// DefaultLimit is the maximum number of IPs to fetch from the API.
	DefaultLimit = 10000
)

// BlockedIP represents a single entry in the AbuseIPDB cache.
type BlockedIP struct {
	IPAddress            string    `json:"ipAddress"`
	AbuseConfidenceScore int       `json:"abuseConfidenceScore"`
	CountryCode          string    `json:"countryCode"`
	UsageType            string    `json:"usageType"`
	ISP                  string    `json:"isp"`
	Domain               string    `json:"domain"`
	TotalReports         int       `json:"totalReports"`
	NumDistinctUsers     int       `json:"numDistinctUsers"`
	LastReportedAt       string    `json:"lastReportedAt"`
	CachedAt             time.Time `json:"cachedAt"`
}

// FetchStatus holds the result of the last cache refresh operation.
type FetchStatus struct {
	LastUpdated  time.Time `json:"last_updated"`
	TotalCached  int       `json:"total_cached"`
	APIKeySet    bool      `json:"api_key_set"`
	LastError    string    `json:"last_error,omitempty"`
	UpdateInProgress bool  `json:"update_in_progress"`
}

// Cache is the AbuseIPDB SQLite-backed IP cache.
type Cache struct {
	db        *sql.DB
	apiKey    string
	mu        sync.RWMutex
	status    FetchStatus
	dbPath    string
	updating  bool
}

// NewCache creates (or opens) the SQLite database and initialises the schema.
func NewCache(dbPath string) (*Cache, error) {
	if dbPath == "" {
		dbPath = DefaultDBPath
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb: open db: %w", err)
	}

	// Enable WAL mode for better concurrent read performance.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("abuseipdb: WAL pragma: %w", err)
	}

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("abuseipdb: schema init: %w", err)
	}

	c := &Cache{
		db:     db,
		dbPath: dbPath,
	}

	// Load the last-updated timestamp and cached count from the database.
	count, updatedAt := c.loadMeta()
	c.status.TotalCached = count
	if !updatedAt.IsZero() {
		c.status.LastUpdated = updatedAt
	}

	// Priority order for API key:
	//   1. ABUSEIPDB_KEY environment variable (highest priority)
	//   2. Key previously saved to the SQLite database
	apiKey := os.Getenv("ABUSEIPDB_KEY")
	if apiKey == "" {
		// Try to load a previously saved key from the DB.
		apiKey = c.loadKeyFromDB()
	}
	if apiKey != "" {
		c.apiKey = apiKey
		c.status.APIKeySet = true
		if os.Getenv("ABUSEIPDB_KEY") != "" {
			fmt.Println("[AbuseIPDB] API key loaded from ABUSEIPDB_KEY environment variable")
		} else {
			fmt.Println("[AbuseIPDB] API key loaded from persistent database")
		}
	}

	return c, nil
}


// SetAPIKey configures the AbuseIPDB API key used for fetching the blacklist.
// The key is persisted to the SQLite database so it survives restarts.
// Pass an empty string to clear the key.
func (c *Cache) SetAPIKey(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.apiKey = key
	c.status.APIKeySet = key != ""
	// Persist to DB (best-effort — errors are logged but not returned).
	if err := c.saveKeyToDB(key); err != nil {
		fmt.Printf("[AbuseIPDB] WARNING: could not persist API key: %v\n", err)
	}
}


// GetAPIKey returns the current API key (masked for safety).
func (c *Cache) GetAPIKey() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.apiKey == "" {
		return ""
	}
	if len(c.apiKey) <= 8 {
		return "****"
	}
	return c.apiKey[:4] + "****" + c.apiKey[len(c.apiKey)-4:]
}

// IsBlocked reports whether the given IP address is in the local cache.
func (c *Cache) IsBlocked(ip string) (bool, *BlockedIP) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var entry BlockedIP
	row := c.db.QueryRow(`
		SELECT ip_address, abuse_confidence_score, country_code, usage_type, isp, domain,
		       total_reports, num_distinct_users, last_reported_at, cached_at
		FROM blocked_ips WHERE ip_address = ?`, ip)

	var cachedAt string
	err := row.Scan(
		&entry.IPAddress, &entry.AbuseConfidenceScore, &entry.CountryCode,
		&entry.UsageType, &entry.ISP, &entry.Domain,
		&entry.TotalReports, &entry.NumDistinctUsers,
		&entry.LastReportedAt, &cachedAt,
	)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, nil
	}
	entry.CachedAt, _ = time.Parse(time.RFC3339, cachedAt)
	return true, &entry
}

// GetStatus returns the current status of the cache.
func (c *Cache) GetStatus() FetchStatus {
	c.mu.RLock()
	defer c.mu.RUnlock()
	s := c.status
	s.UpdateInProgress = c.updating
	return s
}

// GetAll returns all cached blocked IPs (up to a limit).
func (c *Cache) GetAll(limit int) ([]BlockedIP, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if limit <= 0 {
		limit = 500
	}
	rows, err := c.db.Query(`
		SELECT ip_address, abuse_confidence_score, country_code, usage_type, isp, domain,
		       total_reports, num_distinct_users, last_reported_at, cached_at
		FROM blocked_ips ORDER BY abuse_confidence_score DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []BlockedIP
	for rows.Next() {
		var entry BlockedIP
		var cachedAt string
		if err := rows.Scan(
			&entry.IPAddress, &entry.AbuseConfidenceScore, &entry.CountryCode,
			&entry.UsageType, &entry.ISP, &entry.Domain,
			&entry.TotalReports, &entry.NumDistinctUsers,
			&entry.LastReportedAt, &cachedAt,
		); err != nil {
			continue
		}
		entry.CachedAt, _ = time.Parse(time.RFC3339, cachedAt)
		results = append(results, entry)
	}
	return results, rows.Err()
}

// RefreshCache fetches the AbuseIPDB blacklist and populates the local SQLite cache.
// It is safe to call concurrently; a second call while one is in progress is a no-op.
func (c *Cache) RefreshCache() error {
	c.mu.Lock()
	if c.updating {
		c.mu.Unlock()
		return fmt.Errorf("abuseipdb: update already in progress")
	}
	if c.apiKey == "" {
		c.mu.Unlock()
		return fmt.Errorf("abuseipdb: API key not configured")
	}
	apiKey := c.apiKey
	c.updating = true
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		c.updating = false
		c.mu.Unlock()
	}()

	fmt.Println("[AbuseIPDB] Fetching blacklist from API...")

	entries, err := fetchBlacklist(apiKey, DefaultConfidenceMinimum, DefaultLimit)
	if err != nil {
		c.mu.Lock()
		c.status.LastError = err.Error()
		c.mu.Unlock()
		return fmt.Errorf("abuseipdb: fetch: %w", err)
	}

	if err := c.persistEntries(entries); err != nil {
		c.mu.Lock()
		c.status.LastError = err.Error()
		c.mu.Unlock()
		return fmt.Errorf("abuseipdb: persist: %w", err)
	}

	now := time.Now()
	c.mu.Lock()
	c.status.LastUpdated = now
	c.status.TotalCached = len(entries)
	c.status.LastError = ""
	c.mu.Unlock()

	fmt.Printf("[AbuseIPDB] Cache refreshed: %d IPs stored at %s\n", len(entries), now.Format(time.RFC3339))
	return nil
}

// ---- internal helpers ----

func initSchema(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS blocked_ips (
			ip_address             TEXT PRIMARY KEY,
			abuse_confidence_score INTEGER NOT NULL DEFAULT 0,
			country_code           TEXT    NOT NULL DEFAULT '',
			usage_type             TEXT    NOT NULL DEFAULT '',
			isp                    TEXT    NOT NULL DEFAULT '',
			domain                 TEXT    NOT NULL DEFAULT '',
			total_reports          INTEGER NOT NULL DEFAULT 0,
			num_distinct_users     INTEGER NOT NULL DEFAULT 0,
			last_reported_at       TEXT    NOT NULL DEFAULT '',
			cached_at              TEXT    NOT NULL
		);
		CREATE TABLE IF NOT EXISTS cache_meta (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
	`)
	return err
}

// loadMeta reads the cached count and last-updated timestamp from the meta table.
func (c *Cache) loadMeta() (count int, updatedAt time.Time) {
	c.db.QueryRow("SELECT COUNT(*) FROM blocked_ips").Scan(&count) //nolint:errcheck
	var ts string
	if err := c.db.QueryRow("SELECT value FROM cache_meta WHERE key='last_updated'").Scan(&ts); err == nil {
		updatedAt, _ = time.Parse(time.RFC3339, ts)
	}
	return count, updatedAt
}

// loadKeyFromDB retrieves the API key that was previously saved to the database.
// Returns an empty string if no key has been saved.
func (c *Cache) loadKeyFromDB() string {
	var key string
	c.db.QueryRow("SELECT value FROM cache_meta WHERE key='api_key'").Scan(&key) //nolint:errcheck
	return key
}

// saveKeyToDB persists the API key to the cache_meta table.
// Pass an empty string to delete the stored key.
func (c *Cache) saveKeyToDB(key string) error {
	if key == "" {
		_, err := c.db.Exec("DELETE FROM cache_meta WHERE key='api_key'")
		return err
	}
	_, err := c.db.Exec(
		"INSERT OR REPLACE INTO cache_meta (key, value) VALUES ('api_key', ?)", key)
	return err
}


// persistEntries replaces the entire cached table with fresh data inside a transaction.
func (c *Cache) persistEntries(entries []BlacklistEntry) error {
	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.Exec("DELETE FROM blocked_ips"); err != nil {
		return err
	}

	stmt, err := tx.Prepare(`
		INSERT INTO blocked_ips
			(ip_address, abuse_confidence_score, country_code, usage_type, isp, domain,
			 total_reports, num_distinct_users, last_reported_at, cached_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now().UTC().Format(time.RFC3339)
	for _, e := range entries {
		_, err := stmt.Exec(
			e.IPAddress, e.AbuseConfidenceScore, e.CountryCode,
			e.UsageType, e.ISP, e.Domain,
			e.TotalReports, e.NumDistinctUsers,
			e.LastReportedAt, now,
		)
		if err != nil {
			return err
		}
	}

	// Update meta
	if _, err := tx.Exec(`INSERT OR REPLACE INTO cache_meta (key, value) VALUES ('last_updated', ?)`,
		now); err != nil {
		return err
	}

	return tx.Commit()
}

// BlacklistEntry is the raw struct returned by the AbuseIPDB API.
type BlacklistEntry struct {
	IPAddress            string `json:"ipAddress"`
	AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
	CountryCode          string `json:"countryCode"`
	UsageType            string `json:"usageType"`
	ISP                  string `json:"isp"`
	Domain               string `json:"domain"`
	TotalReports         int    `json:"totalReports"`
	NumDistinctUsers     int    `json:"numDistinctUsers"`
	LastReportedAt       string `json:"lastReportedAt"`
}

type apiResponse struct {
	Data []BlacklistEntry `json:"data"`
	Meta struct {
		GeneratedAt string `json:"generatedAt"`
	} `json:"meta"`
}

// fetchBlacklist calls the AbuseIPDB v2 blacklist endpoint and returns the entries.
func fetchBlacklist(apiKey string, confidenceMin, limit int) ([]BlacklistEntry, error) {
	req, err := http.NewRequest("GET", AbuseIPDBBlacklistURL, nil)
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Set("confidenceMinimum", fmt.Sprintf("%d", confidenceMin))
	q.Set("limit", fmt.Sprintf("%d", limit))
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Key", apiKey)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AbuseIPDB returned HTTP %d", resp.StatusCode)
	}

	var result apiResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return result.Data, nil
}
