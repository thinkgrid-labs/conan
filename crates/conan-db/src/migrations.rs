use rusqlite::Connection;

pub fn run(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        PRAGMA journal_mode=WAL;
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS findings (
            id           TEXT PRIMARY KEY,
            timestamp    TEXT NOT NULL,
            source       TEXT NOT NULL,
            service_id   TEXT,
            service_name TEXT,
            risk_score   INTEGER NOT NULL,
            risk_level   TEXT NOT NULL,
            dlp_matches  TEXT NOT NULL DEFAULT '[]',
            detail       TEXT NOT NULL,
            raw_event    TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS findings_timestamp ON findings(timestamp);
        CREATE INDEX IF NOT EXISTS findings_risk_level ON findings(risk_level);
        CREATE INDEX IF NOT EXISTS findings_service_id ON findings(service_id);

        CREATE TABLE IF NOT EXISTS signature_meta (
            id           TEXT PRIMARY KEY,
            version      TEXT NOT NULL,
            last_updated TEXT NOT NULL
        );
        ",
    )
}
