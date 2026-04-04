use std::path::Path;

use conan_core::{finding::Finding, ConanError};
use rusqlite::{params, Connection};

use crate::migrations;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self, ConanError> {
        let conn = Connection::open(path).map_err(|e| ConanError::Database(e.to_string()))?;
        migrations::run(&conn).map_err(|e| ConanError::Database(e.to_string()))?;
        Ok(Self { conn })
    }

    /// Open an in-memory database (useful for tests and one-shot scans).
    pub fn in_memory() -> Result<Self, ConanError> {
        let conn = Connection::open_in_memory().map_err(|e| ConanError::Database(e.to_string()))?;
        migrations::run(&conn).map_err(|e| ConanError::Database(e.to_string()))?;
        Ok(Self { conn })
    }

    pub fn insert_finding(&self, finding: &Finding) -> Result<(), ConanError> {
        let raw_event = serde_json::to_string(&finding.event)
            .map_err(|e| ConanError::Serialization(e.to_string()))?;
        let dlp_json = serde_json::to_string(&finding.dlp_matches)
            .map_err(|e| ConanError::Serialization(e.to_string()))?;

        self.conn.execute(
            "INSERT OR REPLACE INTO findings
             (id, timestamp, source, service_id, service_name, risk_score, risk_level, dlp_matches, detail, raw_event)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                finding.id.to_string(),
                finding.timestamp.to_rfc3339(),
                finding.event.source.to_string(),
                finding.signature_id,
                finding.service_name,
                finding.risk_score.0,
                format!("{}", finding.risk_level),
                dlp_json,
                finding.detail,
                raw_event,
            ],
        ).map_err(|e| ConanError::Database(e.to_string()))?;

        Ok(())
    }

    /// Query findings, optionally filtered by hours ago.
    pub fn query_findings(
        &self,
        since_hours: Option<u32>,
    ) -> Result<Vec<serde_json::Value>, ConanError> {
        let sql = if let Some(h) = since_hours {
            format!(
                "SELECT id, timestamp, source, service_name, risk_score, risk_level, detail
                 FROM findings
                 WHERE datetime(timestamp) >= datetime('now', '-{h} hours')
                 ORDER BY timestamp DESC"
            )
        } else {
            "SELECT id, timestamp, source, service_name, risk_score, risk_level, detail
             FROM findings ORDER BY timestamp DESC LIMIT 1000"
                .to_string()
        };

        let mut stmt = self
            .conn
            .prepare(&sql)
            .map_err(|e| ConanError::Database(e.to_string()))?;

        let rows = stmt
            .query_map([], |row| {
                Ok(serde_json::json!({
                    "id":           row.get::<_, String>(0)?,
                    "timestamp":    row.get::<_, String>(1)?,
                    "source":       row.get::<_, String>(2)?,
                    "service_name": row.get::<_, Option<String>>(3)?,
                    "risk_score":   row.get::<_, u8>(4)?,
                    "risk_level":   row.get::<_, String>(5)?,
                    "detail":       row.get::<_, String>(6)?,
                }))
            })
            .map_err(|e| ConanError::Database(e.to_string()))?;

        rows.map(|r| r.map_err(|e| ConanError::Database(e.to_string())))
            .collect()
    }

    /// Query findings inserted after the given RFC3339 timestamp, ascending order.
    pub fn query_findings_since(
        &self,
        since_timestamp: &str,
    ) -> Result<Vec<serde_json::Value>, ConanError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, timestamp, source, service_name, risk_score, risk_level, detail
                 FROM findings
                 WHERE timestamp > ?1
                 ORDER BY timestamp ASC",
            )
            .map_err(|e| ConanError::Database(e.to_string()))?;

        let rows = stmt
            .query_map([since_timestamp], |row| {
                Ok(serde_json::json!({
                    "id":           row.get::<_, String>(0)?,
                    "timestamp":    row.get::<_, String>(1)?,
                    "source":       row.get::<_, String>(2)?,
                    "service_name": row.get::<_, Option<String>>(3)?,
                    "risk_score":   row.get::<_, u8>(4)?,
                    "risk_level":   row.get::<_, String>(5)?,
                    "detail":       row.get::<_, String>(6)?,
                }))
            })
            .map_err(|e| ConanError::Database(e.to_string()))?;

        rows.map(|r| r.map_err(|e| ConanError::Database(e.to_string())))
            .collect()
    }

    pub fn finding_count_today(&self) -> Result<u32, ConanError> {
        self.conn
            .query_row(
                "SELECT COUNT(*) FROM findings WHERE date(timestamp) = date('now')",
                [],
                |row| row.get(0),
            )
            .map_err(|e| ConanError::Database(e.to_string()))
    }
}
