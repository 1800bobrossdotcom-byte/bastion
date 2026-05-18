use anyhow::Result;
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: Option<i64>,
    pub ts: DateTime<Utc>,
    pub source: String,
    pub severity: String,
    pub kind: String,
    pub summary: String,
    pub details_json: String,
    #[serde(default)]
    pub prev_hash: String,
    #[serde(default)]
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorConfig {
    pub kind: String,
    pub name: String,
    pub enabled: bool,
    pub secret: String,
    pub config_json: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainStatus {
    pub ok: bool,
    pub count: u64,
    pub broken_at: Option<i64>,
    pub head: String,
}

/// Length-prefixed SHA-256 over the canonical event tuple plus prev_hash.
/// Length prefixes prevent boundary-collision attacks where two different
/// fields concatenate to the same byte sequence as one different field.
fn event_hash(
    prev_hash: &str,
    ts: &str,
    source: &str,
    severity: &str,
    kind: &str,
    summary: &str,
    details_json: &str,
) -> String {
    let mut h = Sha256::new();
    for field in [prev_hash, ts, source, severity, kind, summary, details_json] {
        h.update((field.len() as u64).to_le_bytes());
        h.update(field.as_bytes());
    }
    hex::encode(h.finalize())
}

pub struct Store {
    conn: Mutex<Connection>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    pub fn init_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ts TEXT NOT NULL,
              source TEXT NOT NULL,
              severity TEXT NOT NULL,
              kind TEXT NOT NULL,
              summary TEXT NOT NULL,
              details_json TEXT NOT NULL,
              prev_hash TEXT NOT NULL DEFAULT '',
              hash TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);
            CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);

            CREATE TABLE IF NOT EXISTS seen (
              scope TEXT NOT NULL,
              key   TEXT NOT NULL,
              first_seen TEXT NOT NULL,
              PRIMARY KEY(scope, key)
            );

            CREATE TABLE IF NOT EXISTS fim_baseline (
              path TEXT PRIMARY KEY,
              sha256 TEXT NOT NULL,
              size INTEGER NOT NULL,
              mtime TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS canaries (
              path TEXT PRIMARY KEY,
              sha256 TEXT NOT NULL,
              hmac TEXT NOT NULL,
              created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS highwater (
              key TEXT PRIMARY KEY,
              value INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS proc_fp (
              exe TEXT NOT NULL,
              fp TEXT NOT NULL,
              first_seen TEXT NOT NULL,
              PRIMARY KEY(exe, fp)
            );

            CREATE TABLE IF NOT EXISTS trusted_fp (
              fp TEXT PRIMARY KEY,
              exe TEXT NOT NULL,
              reason TEXT NOT NULL DEFAULT '',
              added_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS trusted_exe (
              exe TEXT PRIMARY KEY,
              reason TEXT NOT NULL DEFAULT '',
              added_at TEXT NOT NULL
            );",
        )?;
                conn.execute_batch(
                        "CREATE TABLE IF NOT EXISTS connectors (
                            kind TEXT PRIMARY KEY,
                            name TEXT NOT NULL,
                            enabled INTEGER NOT NULL,
                            secret TEXT NOT NULL,
                            config_json TEXT NOT NULL,
                            updated_at TEXT NOT NULL
                        );",
                )?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS triage (
                event_id INTEGER PRIMARY KEY,
                resolved_at TEXT NOT NULL,
                note TEXT NOT NULL DEFAULT ''
            );",
        )?;
        // Best-effort migration for older DBs that pre-date the merkle columns.
        let _ = conn.execute("ALTER TABLE events ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''", []);
        let _ = conn.execute("ALTER TABLE events ADD COLUMN hash TEXT NOT NULL DEFAULT ''", []);
        Ok(())
    }

    pub fn insert_event(&self, ev: &Event) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let prev_hash: String = conn
            .query_row(
                "SELECT hash FROM events ORDER BY id DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap_or_default();
        let ts_s = ev.ts.to_rfc3339();
        let hash = event_hash(
            &prev_hash,
            &ts_s,
            &ev.source,
            &ev.severity,
            &ev.kind,
            &ev.summary,
            &ev.details_json,
        );
        conn.execute(
            "INSERT INTO events(ts, source, severity, kind, summary, details_json, prev_hash, hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                ts_s,
                ev.source,
                ev.severity,
                ev.kind,
                ev.summary,
                ev.details_json,
                prev_hash,
                hash,
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    /// Returns true if (scope, key) was newly inserted.
    pub fn mark_seen(&self, scope: &str, key: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "INSERT OR IGNORE INTO seen(scope, key, first_seen) VALUES (?1, ?2, ?3)",
            params![scope, key, Utc::now().to_rfc3339()],
        )?;
        Ok(n == 1)
    }

    pub fn recent_events(&self, limit: i64) -> Result<Vec<Event>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, ts, source, severity, kind, summary, details_json, prev_hash, hash
             FROM events ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            let ts_str: String = r.get(1)?;
            Ok(Event {
                id: Some(r.get(0)?),
                ts: DateTime::parse_from_rfc3339(&ts_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                source: r.get(2)?,
                severity: r.get(3)?,
                kind: r.get(4)?,
                summary: r.get(5)?,
                details_json: r.get(6)?,
                prev_hash: r.get(7)?,
                hash: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn event_by_id(&self, id: i64) -> Result<Option<Event>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT id, ts, source, severity, kind, summary, details_json, prev_hash, hash
                 FROM events WHERE id = ?1",
                params![id],
                |r| {
                    let ts_str: String = r.get(1)?;
                    Ok(Event {
                        id: Some(r.get(0)?),
                        ts: DateTime::parse_from_rfc3339(&ts_str)
                            .map(|d| d.with_timezone(&Utc))
                            .unwrap_or_else(|_| Utc::now()),
                        source: r.get(2)?,
                        severity: r.get(3)?,
                        kind: r.get(4)?,
                        summary: r.get(5)?,
                        details_json: r.get(6)?,
                        prev_hash: r.get(7)?,
                        hash: r.get(8)?,
                    })
                },
            )
            .ok();
        Ok(row)
    }

    /// Walk events oldest-to-newest, recomputing each hash and verifying
    /// `prev_hash` chains correctly. Returns the first broken id, if any.
    pub fn verify_chain(&self) -> Result<ChainStatus> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, ts, source, severity, kind, summary, details_json, prev_hash, hash
             FROM events ORDER BY id ASC",
        )?;
        let mut rows = stmt.query([])?;
        let mut expected_prev = String::new();
        let mut count: u64 = 0;
        let mut head = String::new();
        while let Some(r) = rows.next()? {
            let id: i64 = r.get(0)?;
            let ts: String = r.get(1)?;
            let source: String = r.get(2)?;
            let severity: String = r.get(3)?;
            let kind: String = r.get(4)?;
            let summary: String = r.get(5)?;
            let details_json: String = r.get(6)?;
            let prev_hash: String = r.get(7)?;
            let stored_hash: String = r.get(8)?;
            if prev_hash != expected_prev {
                return Ok(ChainStatus { ok: false, count, broken_at: Some(id), head });
            }
            let computed = event_hash(&prev_hash, &ts, &source, &severity, &kind, &summary, &details_json);
            if computed != stored_hash {
                return Ok(ChainStatus { ok: false, count, broken_at: Some(id), head });
            }
            expected_prev = stored_hash.clone();
            head = stored_hash;
            count += 1;
        }
        Ok(ChainStatus { ok: true, count, broken_at: None, head })
    }

    pub fn register_canary(&self, path: &str, sha256: &str, hmac: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO canaries(path, sha256, hmac, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![path, sha256, hmac, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn list_canaries(&self) -> Result<Vec<(String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT path, sha256 FROM canaries")?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    /// Total number of events in the chain. Used by the boot scan rollup
    /// to compute drift count (events_after - events_before).
    pub fn event_count(&self) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?;
        Ok(n)
    }

    /// Cheap chain head lookup (no full verification).
    pub fn chain_tip(&self) -> Result<(i64, String)> {
        let conn = self.conn.lock().unwrap();
        let row: Option<(i64, String)> = conn
            .query_row(
                "SELECT id, hash FROM events ORDER BY id DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .ok();
        Ok(row.unwrap_or((0, String::new())))
    }

    /// Events with id strictly greater than `after_id`, ascending, capped.
    pub fn events_after(&self, after_id: i64, limit: i64) -> Result<Vec<Event>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, ts, source, severity, kind, summary, details_json, prev_hash, hash
             FROM events WHERE id > ?1 ORDER BY id ASC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![after_id, limit], |r| {
            let ts_str: String = r.get(1)?;
            Ok(Event {
                id: Some(r.get(0)?),
                ts: DateTime::parse_from_rfc3339(&ts_str)
                    .map(|d| d.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                source: r.get(2)?,
                severity: r.get(3)?,
                kind: r.get(4)?,
                summary: r.get(5)?,
                details_json: r.get(6)?,
                prev_hash: r.get(7)?,
                hash: r.get(8)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // ---- FIM helpers ----

    pub fn fim_get(&self, path: &str) -> Result<Option<(String, i64, String)>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT sha256, size, mtime FROM fim_baseline WHERE path = ?1",
                params![path],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?, r.get::<_, String>(2)?)),
            )
            .ok();
        Ok(row)
    }

    pub fn fim_upsert(&self, path: &str, sha256: &str, size: i64, mtime: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO fim_baseline(path, sha256, size, mtime) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(path) DO UPDATE SET sha256=excluded.sha256, size=excluded.size, mtime=excluded.mtime",
            params![path, sha256, size, mtime],
        )?;
        Ok(())
    }

    pub fn fim_delete(&self, path: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM fim_baseline WHERE path = ?1", params![path])?;
        Ok(())
    }

    pub fn fim_paths_under(&self, prefix: &str) -> Result<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let like = format!("{}%", prefix);
        let mut stmt = conn.prepare("SELECT path FROM fim_baseline WHERE path LIKE ?1")?;
        let rows = stmt.query_map(params![like], |r| r.get::<_, String>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    // ---- highwater (event-log bookmarks) ----

    pub fn get_highwater(&self, key: &str) -> Result<Option<u64>> {
        let conn = self.conn.lock().unwrap();
        let row: Option<i64> = conn
            .query_row("SELECT value FROM highwater WHERE key = ?1", params![key], |r| r.get(0))
            .ok();
        Ok(row.map(|v| v as u64))
    }

    pub fn set_highwater(&self, key: &str, value: u64) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO highwater(key, value) VALUES(?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value as i64],
        )?;
        Ok(())
    }

    // ---- process behavioral fingerprint (N4) ----

    /// Returns true if this (exe, fp) pair was newly inserted.
    pub fn proc_fp_seen(&self, exe: &str, fp: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let n = conn.execute(
            "INSERT OR IGNORE INTO proc_fp(exe, fp, first_seen) VALUES(?1, ?2, ?3)",
            params![exe, fp, Utc::now().to_rfc3339()],
        )?;
        Ok(n == 1)
    }

    pub fn proc_fp_count_for(&self, exe: &str) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM proc_fp WHERE exe = ?1", params![exe], |r| r.get(0))
            .unwrap_or(0);
        Ok(n)
    }

    // ---- trust list (auto-suppress known-good) ----

    pub fn trust_fp(&self, fp: &str, exe: &str, reason: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO trusted_fp(fp, exe, reason, added_at) VALUES(?1, ?2, ?3, ?4)",
            params![fp, exe, reason, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn trust_exe(&self, exe: &str, reason: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO trusted_exe(exe, reason, added_at) VALUES(?1, ?2, ?3)",
            params![exe, reason, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn untrust_fp(&self, fp: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM trusted_fp WHERE fp = ?1", params![fp])?;
        Ok(())
    }

    pub fn untrust_exe(&self, exe: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM trusted_exe WHERE exe = ?1", params![exe])?;
        Ok(())
    }

    pub fn fp_is_trusted(&self, fp: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM trusted_fp WHERE fp = ?1", params![fp], |r| r.get(0))
            .unwrap_or(0);
        Ok(n > 0)
    }

    pub fn exe_is_trusted(&self, exe: &str) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM trusted_exe WHERE exe = ?1", params![exe], |r| r.get(0))
            .unwrap_or(0);
        Ok(n > 0)
    }

    pub fn list_trusted_fp(&self) -> Result<Vec<(String, String, String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT fp, exe, reason, added_at FROM trusted_fp ORDER BY added_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn list_trusted_exe(&self) -> Result<Vec<(String, String, String)>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT exe, reason, added_at FROM trusted_exe ORDER BY added_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn upsert_connector(
        &self,
        kind: &str,
        name: &str,
        enabled: bool,
        secret: &str,
        config_json: &str,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO connectors(kind, name, enabled, secret, config_json, updated_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(kind) DO UPDATE SET
               name=excluded.name,
               enabled=excluded.enabled,
               secret=excluded.secret,
               config_json=excluded.config_json,
               updated_at=excluded.updated_at",
            params![kind, name, enabled as i64, secret, config_json, Utc::now().to_rfc3339()],
        )?;
        Ok(())
    }

    pub fn connector_by_kind(&self, kind: &str) -> Result<Option<ConnectorConfig>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT kind, name, enabled, secret, config_json, updated_at FROM connectors WHERE kind = ?1",
                params![kind],
                |r| {
                    Ok(ConnectorConfig {
                        kind: r.get(0)?,
                        name: r.get(1)?,
                        enabled: r.get::<_, i64>(2)? != 0,
                        secret: r.get(3)?,
                        config_json: r.get(4)?,
                        updated_at: r.get(5)?,
                    })
                },
            )
            .ok();
        Ok(row)
    }

    pub fn list_connectors(&self) -> Result<Vec<ConnectorConfig>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT kind, name, enabled, secret, config_json, updated_at FROM connectors ORDER BY updated_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(ConnectorConfig {
                kind: r.get(0)?,
                name: r.get(1)?,
                enabled: r.get::<_, i64>(2)? != 0,
                secret: r.get(3)?,
                config_json: r.get(4)?,
                updated_at: r.get(5)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn triage_resolve(&self, ids: &[i64], note: &str) -> Result<usize> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let now = Utc::now().to_rfc3339();
        let mut n = 0usize;
        {
            let mut stmt = tx.prepare(
                "INSERT INTO triage(event_id, resolved_at, note) VALUES (?1, ?2, ?3)
                 ON CONFLICT(event_id) DO UPDATE SET resolved_at = excluded.resolved_at, note = excluded.note",
            )?;
            for id in ids {
                n += stmt.execute(params![id, now, note])?;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    pub fn triage_unresolve(&self, ids: &[i64]) -> Result<usize> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let mut n = 0usize;
        {
            let mut stmt = tx.prepare("DELETE FROM triage WHERE event_id = ?1")?;
            for id in ids {
                n += stmt.execute(params![id])?;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    pub fn triage_list(&self) -> Result<Vec<i64>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT event_id FROM triage ORDER BY event_id DESC")?;
        let rows = stmt.query_map([], |r| r.get::<_, i64>(0))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn db_path(&self) -> Option<String> {
        let conn = self.conn.lock().unwrap();
        let p: Option<String> = conn
            .query_row("PRAGMA database_list", [], |r| r.get::<_, String>(2))
            .ok();
        p
    }
}

pub fn now_event(source: &str, severity: &str, kind: &str, summary: String, details: serde_json::Value) -> Event {
    Event {
        id: None,
        ts: Utc::now(),
        source: source.into(),
        severity: severity.into(),
        kind: kind.into(),
        summary,
        details_json: details.to_string(),
        prev_hash: String::new(),
        hash: String::new(),
    }
}
