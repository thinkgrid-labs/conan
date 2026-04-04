use async_trait::async_trait;
use conan_core::{
    error::ConanError,
    event::{Event, EventPayload, Source},
    registry::Registry,
    traits::Ingestor,
};
use std::path::PathBuf;
use tracing::debug;

struct BrowserProfile {
    name: String,
    history_path: PathBuf,
}

fn browser_profiles() -> Vec<BrowserProfile> {
    let home = dirs::home_dir().unwrap_or_default();

    #[cfg(target_os = "macos")]
    let profiles = vec![
        BrowserProfile {
            name: "Chrome".to_string(),
            history_path: home.join("Library/Application Support/Google/Chrome/Default/History"),
        },
        BrowserProfile {
            name: "Firefox".to_string(),
            history_path: home.join("Library/Application Support/Firefox/Profiles"),
        },
        BrowserProfile {
            name: "Brave".to_string(),
            history_path: home
                .join("Library/Application Support/BraveSoftware/Brave-Browser/Default/History"),
        },
    ];

    #[cfg(target_os = "linux")]
    let profiles = vec![
        BrowserProfile {
            name: "Chrome".to_string(),
            history_path: home.join(".config/google-chrome/Default/History"),
        },
        BrowserProfile {
            name: "Firefox".to_string(),
            history_path: home.join(".mozilla/firefox"),
        },
    ];

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let profiles: Vec<BrowserProfile> = vec![];

    profiles
        .into_iter()
        .filter(|p| p.history_path.exists())
        .collect()
}

pub struct BrowserHistoryIngestor {
    pub registry: Registry,
}

impl BrowserHistoryIngestor {
    pub fn new(registry: Registry) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl Ingestor for BrowserHistoryIngestor {
    fn name(&self) -> &'static str {
        "browser"
    }

    async fn ingest(&self) -> Result<Vec<Event>, ConanError> {
        let mut events = vec![];
        let profiles = browser_profiles();

        for profile in &profiles {
            // Chrome/Brave history is a SQLite file — copy it first (locked while browser runs)
            let tmp = std::env::temp_dir().join(format!("conan_history_{}.db", profile.name));
            if let Err(e) = std::fs::copy(&profile.history_path, &tmp) {
                debug!(browser = %profile.name, error = %e, "could not copy browser history, skipping");
                continue;
            }

            if let Ok(conn) = rusqlite::Connection::open(&tmp) {
                let query = "SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 10000";
                if let Ok(mut stmt) = conn.prepare(query) {
                    let rows = stmt.query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0).unwrap_or_default(),
                            row.get::<_, Option<String>>(1).unwrap_or_default(),
                        ))
                    });

                    if let Ok(rows) = rows {
                        for row in rows.flatten() {
                            let (url, title) = row;
                            let host = extract_host(&url);
                            let matches = self.registry.match_domain(&host);
                            if !matches.is_empty() {
                                debug!(browser = %profile.name, url = %url, "matched AI URL in browser history");
                                events.push(Event::new(
                                    Source::BrowserHistory,
                                    EventPayload::BrowserHistory {
                                        url: url.clone(),
                                        title,
                                        browser: profile.name.clone(),
                                    },
                                ));
                            }
                        }
                    }
                }
            }

            let _ = std::fs::remove_file(&tmp);
        }

        Ok(events)
    }
}

fn extract_host(url: &str) -> String {
    url.trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("")
        .split('?')
        .next()
        .unwrap_or("")
        .to_string()
}
