use conan_core::{
    event::{Event, EventPayload, Source},
    finding::{DlpMatch, DlpSeverity, Finding},
};
use conan_db::Store;

fn net_event() -> Event {
    Event::new(
        Source::Network,
        EventPayload::NetworkConnection {
            remote_host: "api.openai.com".to_string(),
            remote_ip: None,
            port: 443,
            protocol: "tcp".to_string(),
            http_headers: None,
            body_snippet: None,
        },
    )
}

fn finding(detail: &str) -> Finding {
    Finding::new(net_event(), None, vec![], detail.to_string())
}

// ── open ─────────────────────────────────────────────────────────────────────

#[test]
fn open_in_memory_succeeds() {
    assert!(Store::in_memory().is_ok());
}

#[test]
fn open_on_disk_creates_db_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("findings.db");
    assert!(Store::open(&path).is_ok());
    assert!(path.exists());
}

// ── insert + query ────────────────────────────────────────────────────────────

#[test]
fn insert_and_query_all() {
    let store = Store::in_memory().unwrap();
    store.insert_finding(&finding("test detail")).unwrap();

    let rows = store.query_findings(None).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["detail"], "test detail");
    assert_eq!(rows[0]["source"], "net");
}

#[test]
fn query_by_hours_includes_recent_finding() {
    let store = Store::in_memory().unwrap();
    store.insert_finding(&finding("recent")).unwrap();

    let rows = store.query_findings(Some(1)).unwrap();
    assert_eq!(rows.len(), 1);
}

#[test]
fn insert_multiple_all_queryable() {
    let store = Store::in_memory().unwrap();
    for i in 0..5 {
        store
            .insert_finding(&finding(&format!("finding {i}")))
            .unwrap();
    }
    assert_eq!(store.query_findings(None).unwrap().len(), 5);
}

#[test]
fn query_result_contains_expected_fields() {
    let store = Store::in_memory().unwrap();
    store.insert_finding(&finding("check fields")).unwrap();

    let row = &store.query_findings(None).unwrap()[0];
    assert!(row["id"].is_string());
    assert!(row["timestamp"].is_string());
    assert!(row["risk_score"].is_number());
    assert!(row["risk_level"].is_string());
    assert_eq!(row["detail"], "check fields");
}

// ── count ─────────────────────────────────────────────────────────────────────

#[test]
fn finding_count_starts_at_zero() {
    let store = Store::in_memory().unwrap();
    assert_eq!(store.finding_count_today().unwrap(), 0);
}

#[test]
fn finding_count_increments_on_insert() {
    let store = Store::in_memory().unwrap();
    store.insert_finding(&finding("first")).unwrap();
    store.insert_finding(&finding("second")).unwrap();
    assert_eq!(store.finding_count_today().unwrap(), 2);
}

// ── DLP findings ─────────────────────────────────────────────────────────────

#[test]
fn insert_finding_with_critical_dlp_stored_correctly() {
    let store = Store::in_memory().unwrap();

    let event = Event::new(
        Source::Codebase,
        EventPayload::CodebaseFile {
            file_path: "src/config.js".to_string(),
            line_number: Some(14),
            matched_text: "openai_key".to_string(),
        },
    );
    let dlp = vec![DlpMatch {
        pattern_id: "openai_key".to_string(),
        description: "OpenAI API key detected".to_string(),
        severity: DlpSeverity::Critical,
    }];
    let f = Finding::new(event, None, dlp, "key in source".to_string());
    store.insert_finding(&f).unwrap();

    let rows = store.query_findings(None).unwrap();
    assert_eq!(rows.len(), 1);
    // base=30 (no signature) × 2.0 (critical DLP) = 60 → HIGH
    assert_eq!(rows[0]["risk_level"], "HIGH");
    assert_eq!(rows[0]["source"], "codebase");
}

// ── idempotency ───────────────────────────────────────────────────────────────

#[test]
fn inserting_same_id_twice_does_not_duplicate() {
    let store = Store::in_memory().unwrap();
    let f = finding("once");
    store.insert_finding(&f).unwrap();
    store.insert_finding(&f).unwrap(); // same UUID → INSERT OR REPLACE
    assert_eq!(store.query_findings(None).unwrap().len(), 1);
}
