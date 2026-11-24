// Package storage provides the single-binary embedded SQLite (WAL) persistence
// layer for Osmium Server. It is compiled with CGO_ENABLED=0 via
// modernc.org/sqlite and is strictly excluded from osmium-agent.
package storage

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"

	"github.com/indexyz/osmium/internal/audit"
	"github.com/indexyz/osmium/internal/authn"
	"github.com/indexyz/osmium/internal/authz"
)

// SQLiteStore implements authz.Persister, authn.SessionStore, and fast local
// indexed audit storage on top of a single WAL-mode SQLite file.
type SQLiteStore struct {
	writeMu sync.Mutex
	wdb     *sql.DB
	rdb     *sql.DB
}

// OpenSQLite opens (or creates) the embedded SQLite WAL database at path.
func OpenSQLite(path string) (*SQLiteStore, error) {
	if path == "" {
		return nil, errors.New("storage: sqlite path is required")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("storage: mkdir %s: %w", dir, err)
		}
	}
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)&_pragma=temp_store(MEMORY)"
	wdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("storage: open writer: %w", err)
	}
	wdb.SetMaxOpenConns(1)
	wdb.SetMaxIdleConns(1)
	if err := wdb.Ping(); err != nil {
		_ = wdb.Close()
		return nil, fmt.Errorf("storage: ping writer: %w", err)
	}

	rdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		_ = wdb.Close()
		return nil, fmt.Errorf("storage: open reader: %w", err)
	}
	rdb.SetMaxOpenConns(8)
	rdb.SetMaxIdleConns(4)

	s := &SQLiteStore{wdb: wdb, rdb: rdb}
	if err := s.migrate(); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// Close closes reader and writer pools cleanly.
func (s *SQLiteStore) Close() error {
	if s == nil {
		return nil
	}
	return errors.Join(s.rdb.Close(), s.wdb.Close())
}

func (s *SQLiteStore) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS policy_meta (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
	id TEXT PRIMARY KEY,
	display_name TEXT NOT NULL,
	agent_id TEXT NOT NULL UNIQUE,
	client_cert_cn TEXT NOT NULL UNIQUE,
	disabled INTEGER NOT NULL DEFAULT 0,
	doc_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS host_labels (
	host_id TEXT NOT NULL,
	k TEXT NOT NULL,
	v TEXT NOT NULL,
	PRIMARY KEY (host_id, k),
	FOREIGN KEY (host_id) REFERENCES hosts(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_host_labels_kv ON host_labels(k, v, host_id);

CREATE TABLE IF NOT EXISTS grants (
	id TEXT PRIMARY KEY,
	ord INTEGER NOT NULL,
	doc_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS web_sessions (
	key_hash TEXT PRIMARY KEY,
	user_id TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	doc_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_web_sessions_exp ON web_sessions(expires_at);

CREATE TABLE IF NOT EXISTS cli_tokens (
	key_hash TEXT PRIMARY KEY,
	token_id TEXT NOT NULL UNIQUE,
	user_id TEXT NOT NULL,
	expires_at INTEGER NOT NULL,
	last_used_at INTEGER NOT NULL DEFAULT 0,
	doc_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_cli_tokens_exp ON cli_tokens(expires_at);

CREATE TABLE IF NOT EXISTS audit_events (
	seq INTEGER PRIMARY KEY AUTOINCREMENT,
	id TEXT NOT NULL,
	ts_ns INTEGER NOT NULL,
	actor TEXT NOT NULL,
	user_lower TEXT NOT NULL,
	action TEXT NOT NULL,
	result TEXT NOT NULL,
	target TEXT NOT NULL,
	session_id TEXT NOT NULL,
	doc_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts_ns, seq);
CREATE INDEX IF NOT EXISTS idx_audit_action_ts ON audit_events(action, ts_ns, seq);
CREATE INDEX IF NOT EXISTS idx_audit_actor_ts ON audit_events(actor, ts_ns, seq);
CREATE INDEX IF NOT EXISTS idx_audit_user_ts ON audit_events(user_lower, ts_ns, seq);
CREATE INDEX IF NOT EXISTS idx_audit_session_ts ON audit_events(session_id, ts_ns, seq);
CREATE INDEX IF NOT EXISTS idx_audit_target_ts ON audit_events(target, ts_ns, seq);
`
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.wdb.Exec(schema)
	return err
}

// HasPolicy reports whether the database already contains a persisted policy.
func (s *SQLiteStore) HasPolicy() (bool, error) {
	var v string
	err := s.rdb.QueryRow(`SELECT value FROM policy_meta WHERE key = 'scope'`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// LoadDocument reads the full policy Document from SQLite.
func (s *SQLiteStore) LoadDocument() (authz.Document, bool, error) {
	var doc authz.Document
	var scope string
	err := s.rdb.QueryRow(`SELECT value FROM policy_meta WHERE key = 'scope'`).Scan(&scope)
	if errors.Is(err, sql.ErrNoRows) {
		return doc, false, nil
	}
	if err != nil {
		return doc, false, err
	}
	doc.Scope = scope

	loadMetaJSON := func(key string, dst any) error {
		var raw string
		err := s.rdb.QueryRow(`SELECT value FROM policy_meta WHERE key = ?`, key).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		return json.Unmarshal([]byte(raw), dst)
	}
	if err := loadMetaJSON("admins", &doc.Admins); err != nil {
		return doc, false, err
	}
	if err := loadMetaJSON("disabled_users", &doc.DisabledUsers); err != nil {
		return doc, false, err
	}
	if err := loadMetaJSON("host_ca_public_keys", &doc.HostCAPublicKeys); err != nil {
		return doc, false, err
	}

	hRows, err := s.rdb.Query(`SELECT doc_json FROM hosts ORDER BY id ASC`)
	if err != nil {
		return doc, false, err
	}
	defer hRows.Close()
	for hRows.Next() {
		var raw string
		if err := hRows.Scan(&raw); err != nil {
			return doc, false, err
		}
		var h authz.Host
		if err := json.Unmarshal([]byte(raw), &h); err != nil {
			return doc, false, err
		}
		doc.Hosts = append(doc.Hosts, &h)
	}
	if err := hRows.Err(); err != nil {
		return doc, false, err
	}

	gRows, err := s.rdb.Query(`SELECT doc_json FROM grants ORDER BY ord ASC, id ASC`)
	if err != nil {
		return doc, false, err
	}
	defer gRows.Close()
	for gRows.Next() {
		var raw string
		if err := gRows.Scan(&raw); err != nil {
			return doc, false, err
		}
		var g authz.Grant
		if err := json.Unmarshal([]byte(raw), &g); err != nil {
			return doc, false, err
		}
		doc.Grants = append(doc.Grants, g)
	}
	if err := gRows.Err(); err != nil {
		return doc, false, err
	}
	return doc, true, nil
}

// SaveDocument atomically replaces the entire persisted policy document.
func (s *SQLiteStore) SaveDocument(doc authz.Document) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.wdb.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	setMeta := func(k string, v any) error {
		var val string
		if str, ok := v.(string); ok {
			val = str
		} else {
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			val = string(b)
		}
		_, err := tx.Exec(`INSERT INTO policy_meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, k, val)
		return err
	}
	if err := setMeta("scope", doc.Scope); err != nil {
		return err
	}
	if err := setMeta("admins", doc.Admins); err != nil {
		return err
	}
	if err := setMeta("disabled_users", doc.DisabledUsers); err != nil {
		return err
	}
	if err := setMeta("host_ca_public_keys", doc.HostCAPublicKeys); err != nil {
		return err
	}

	if _, err := tx.Exec(`DELETE FROM host_labels`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM hosts`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM grants`); err != nil {
		return err
	}

	hostStmt, err := tx.Prepare(`INSERT INTO hosts(id, display_name, agent_id, client_cert_cn, disabled, doc_json) VALUES(?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer hostStmt.Close()
	labelStmt, err := tx.Prepare(`INSERT INTO host_labels(host_id, k, v) VALUES(?, ?, ?)`)
	if err != nil {
		return err
	}
	defer labelStmt.Close()

	for _, h := range doc.Hosts {
		raw, err := json.Marshal(h)
		if err != nil {
			return err
		}
		dis := 0
		if h.Disabled {
			dis = 1
		}
		if _, err := hostStmt.Exec(h.ID, h.DisplayName, h.Agent.ID, h.Agent.ClientCertCN, dis, string(raw)); err != nil {
			return err
		}
		for k, v := range h.PolicyLabels {
			if _, err := labelStmt.Exec(h.ID, k, v); err != nil {
				return err
			}
		}
	}

	grantStmt, err := tx.Prepare(`INSERT INTO grants(id, ord, doc_json) VALUES(?, ?, ?)`)
	if err != nil {
		return err
	}
	defer grantStmt.Close()
	for i, g := range doc.Grants {
		gid := g.ID
		if gid == "" {
			gid = fmt.Sprintf("grant-%d", i)
		}
		raw, err := json.Marshal(g)
		if err != nil {
			return err
		}
		if _, err := grantStmt.Exec(gid, i, string(raw)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// UpsertHost persists a single host and its labels inside one transaction.
func (s *SQLiteStore) UpsertHost(h *authz.Host) error {
	raw, err := json.Marshal(h)
	if err != nil {
		return err
	}
	dis := 0
	if h.Disabled {
		dis = 1
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.wdb.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO hosts(id, display_name, agent_id, client_cert_cn, disabled, doc_json) VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET display_name=excluded.display_name, agent_id=excluded.agent_id, client_cert_cn=excluded.client_cert_cn, disabled=excluded.disabled, doc_json=excluded.doc_json`,
		h.ID, h.DisplayName, h.Agent.ID, h.Agent.ClientCertCN, dis, string(raw)); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM host_labels WHERE host_id = ?`, h.ID); err != nil {
		return err
	}
	for k, v := range h.PolicyLabels {
		if _, err := tx.Exec(`INSERT INTO host_labels(host_id, k, v) VALUES(?, ?, ?)`, h.ID, k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteHost removes one host (and cascades its labels).
func (s *SQLiteStore) DeleteHost(hostID string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.wdb.Exec(`DELETE FROM hosts WHERE id = ?`, hostID)
	return err
}

// UpsertGrant persists a single grant rule.
func (s *SQLiteStore) UpsertGrant(g authz.Grant) error {
	raw, err := json.Marshal(g)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err = s.wdb.Exec(`INSERT INTO grants(id, ord, doc_json) VALUES(?, COALESCE((SELECT ord FROM grants WHERE id = ?), COALESCE((SELECT MAX(ord)+1 FROM grants), 0)), ?)
		ON CONFLICT(id) DO UPDATE SET doc_json=excluded.doc_json`, g.ID, g.ID, string(raw))
	return err
}

// DeleteGrant removes one grant rule by ID.
func (s *SQLiteStore) DeleteGrant(grantID string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.wdb.Exec(`DELETE FROM grants WHERE id = ?`, grantID)
	return err
}

// SaveHostCAs persists the trusted SSH Host CA public keys.
func (s *SQLiteStore) SaveHostCAs(keys []string) error {
	b, err := json.Marshal(keys)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err = s.wdb.Exec(`INSERT INTO policy_meta(key, value) VALUES('host_ca_public_keys', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(b))
	return err
}

// SaveDisabledUsers persists the disabled_users selector list.
func (s *SQLiteStore) SaveDisabledUsers(disabled []authz.SubjectSelector) error {
	b, err := json.Marshal(disabled)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err = s.wdb.Exec(`INSERT INTO policy_meta(key, value) VALUES('disabled_users', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, string(b))
	return err
}

// --- authn.SessionStore ---

func (s *SQLiteStore) LoadWebSessions(now time.Time) (map[string]*authn.WebSession, error) {
	rows, err := s.rdb.Query(`SELECT key_hash, doc_json FROM web_sessions WHERE expires_at > ?`, now.UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]*authn.WebSession)
	for rows.Next() {
		var k, raw string
		if err := rows.Scan(&k, &raw); err != nil {
			return nil, err
		}
		var ws authn.WebSession
		if err := json.Unmarshal([]byte(raw), &ws); err != nil {
			continue
		}
		out[k] = &ws
	}
	return out, rows.Err()
}

func (s *SQLiteStore) SaveWebSession(keyHex string, ws *authn.WebSession) error {
	raw, err := json.Marshal(ws)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err = s.wdb.Exec(`INSERT INTO web_sessions(key_hash, user_id, expires_at, doc_json) VALUES(?, ?, ?, ?)
		ON CONFLICT(key_hash) DO UPDATE SET expires_at=excluded.expires_at, doc_json=excluded.doc_json`,
		keyHex, ws.User.ID, ws.ExpiresAt.UnixNano(), string(raw))
	return err
}

func (s *SQLiteStore) DeleteWebSession(keyHex string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.wdb.Exec(`DELETE FROM web_sessions WHERE key_hash = ?`, keyHex)
	return err
}

func (s *SQLiteStore) LoadCLITokens(now time.Time) (map[string]*authn.CLIToken, error) {
	rows, err := s.rdb.Query(`SELECT key_hash, last_used_at, doc_json FROM cli_tokens WHERE expires_at > ?`, now.UnixNano())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]*authn.CLIToken)
	for rows.Next() {
		var k, raw string
		var usedNs int64
		if err := rows.Scan(&k, &usedNs, &raw); err != nil {
			return nil, err
		}
		var ct authn.CLIToken
		if err := json.Unmarshal([]byte(raw), &ct); err != nil {
			continue
		}
		if usedNs > 0 {
			ct.LastUsedAt = time.Unix(0, usedNs).UTC()
		}
		out[k] = &ct
	}
	return out, rows.Err()
}

func (s *SQLiteStore) SaveCLIToken(keyHex string, ct *authn.CLIToken) error {
	raw, err := json.Marshal(ct)
	if err != nil {
		return err
	}
	var usedNs int64
	if !ct.LastUsedAt.IsZero() {
		usedNs = ct.LastUsedAt.UnixNano()
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err = s.wdb.Exec(`INSERT INTO cli_tokens(key_hash, token_id, user_id, expires_at, last_used_at, doc_json) VALUES(?, ?, ?, ?, ?, ?)
		ON CONFLICT(key_hash) DO UPDATE SET expires_at=excluded.expires_at, last_used_at=excluded.last_used_at, doc_json=excluded.doc_json`,
		keyHex, ct.ID, ct.User.ID, ct.ExpiresAt.UnixNano(), usedNs, string(raw))
	return err
}

func (s *SQLiteStore) TouchCLIToken(keyHex string, usedAt time.Time) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.wdb.Exec(`UPDATE cli_tokens SET last_used_at = ? WHERE key_hash = ?`, usedAt.UnixNano(), keyHex)
	return err
}

func (s *SQLiteStore) DeleteCLIToken(keyHex string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.wdb.Exec(`DELETE FROM cli_tokens WHERE key_hash = ?`, keyHex)
	return err
}

func (s *SQLiteStore) PruneAuth(now time.Time) error {
	ns := now.UnixNano()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if _, err := s.wdb.Exec(`DELETE FROM web_sessions WHERE expires_at <= ?`, ns); err != nil {
		return err
	}
	_, err := s.wdb.Exec(`DELETE FROM cli_tokens WHERE expires_at <= ?`, ns)
	return err
}

// --- Indexed audit events ---

// InsertAuditBatch inserts a batch of audit events in a single WAL transaction.
func (s *SQLiteStore) InsertAuditBatch(events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	tx, err := s.wdb.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO audit_events(id, ts_ns, actor, user_lower, action, result, target, session_id, doc_json) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, ev := range events {
		raw, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		if _, err := stmt.Exec(ev.ID, ev.Time.UTC().UnixNano(), ev.Actor, strings.ToLower(ev.User), ev.Action, ev.Result, ev.Target, ev.SessionID, string(raw)); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func encodeAuditCursor(seq int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte("db|" + strconv.FormatInt(seq, 10)))
}

func decodeAuditCursor(raw string) (int64, error) {
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return 0, fmt.Errorf("%w: cursor", audit.ErrBadQuery)
	}
	prefix, rest, ok := strings.Cut(string(b), "|")
	if !ok || prefix != "db" {
		return 0, fmt.Errorf("%w: cursor", audit.ErrBadQuery)
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%w: cursor", audit.ErrBadQuery)
	}
	return n, nil
}

// SearchAudit answers audit.Query directly from the SQLite index in O(log N).
func (s *SQLiteStore) SearchAudit(ctx context.Context, q audit.Query) (audit.Page, bool, error) {
	var conds []string
	var args []any

	conds = append(conds, "ts_ns >= ?", "ts_ns < ?")
	args = append(args, q.From.UTC().UnixNano(), q.To.UTC().UnixNano())

	if q.Cursor != "" {
		seq, err := decodeAuditCursor(q.Cursor)
		if err != nil {
			return audit.Page{}, true, err
		}
		conds = append(conds, "seq > ?")
		args = append(args, seq)
	}
	if q.Action != "" {
		conds = append(conds, "action = ?")
		args = append(args, q.Action)
	}
	if q.Actor != "" {
		conds = append(conds, "actor = ?")
		args = append(args, q.Actor)
	}
	if q.User != "" {
		conds = append(conds, "(user_lower = ? OR actor = ?)")
		args = append(args, strings.ToLower(q.User), "user:"+q.User)
	}
	if q.SessionID != "" {
		conds = append(conds, "session_id = ?")
		args = append(args, q.SessionID)
	}
	if q.Target != "" {
		conds = append(conds, "target = ?")
		args = append(args, q.Target)
	}

	// Fetch Limit+1 rows to know definitively whether another page exists.
	sqlQuery := `SELECT seq, doc_json FROM audit_events WHERE ` + strings.Join(conds, " AND ") + ` ORDER BY ts_ns ASC, seq ASC LIMIT ?`
	args = append(args, q.Limit+1)

	rows, err := s.rdb.QueryContext(ctx, sqlQuery, args...)
	if err != nil {
		return audit.Page{}, true, err
	}
	defer rows.Close()

	var page audit.Page
	var lastSeq int64
	hasMore := false
	for rows.Next() {
		var seq int64
		var raw string
		if err := rows.Scan(&seq, &raw); err != nil {
			return audit.Page{}, true, err
		}
		if len(page.Events) >= q.Limit {
			hasMore = true
			break
		}
		var ev audit.Event
		if err := json.Unmarshal([]byte(raw), &ev); err != nil {
			continue
		}
		page.Events = append(page.Events, ev)
		lastSeq = seq
	}
	if err := rows.Err(); err != nil {
		return audit.Page{}, true, err
	}
	if hasMore && lastSeq > 0 {
		page.Next = encodeAuditCursor(lastSeq)
	}
	return page, true, nil
}

// PruneAudit removes indexed audit events older than cutoff.
func (s *SQLiteStore) PruneAudit(cutoff time.Time) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	_, err := s.wdb.Exec(`DELETE FROM audit_events WHERE ts_ns < ?`, cutoff.UTC().UnixNano())
	return err
}
