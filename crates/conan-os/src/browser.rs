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
    /// SQL query to fetch (url, title) rows from this browser's history DB.
    query: &'static str,
}

/// Expand Firefox-style profile directories into individual `places.sqlite` paths.
fn expand_firefox_profiles(profiles_dir: &std::path::Path, name: &str) -> Vec<BrowserProfile> {
    let dir = match std::fs::read_dir(profiles_dir) {
        Ok(d) => d,
        Err(_) => return vec![],
    };
    dir.filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| {
            let db = e.path().join("places.sqlite");
            db.exists().then(|| BrowserProfile {
                name: name.to_string(),
                history_path: db,
                query: "SELECT url, title FROM moz_places \
                        WHERE last_visit_date IS NOT NULL \
                        ORDER BY last_visit_date DESC LIMIT 10000",
            })
        })
        .collect()
}

#[allow(unreachable_code)]
fn browser_profiles() -> Vec<BrowserProfile> {
    const CHROME_QUERY: &str =
        "SELECT url, title FROM urls ORDER BY last_visit_time DESC LIMIT 10000";

    #[cfg(target_os = "macos")]
    {
        let home = dirs::home_dir().unwrap_or_default();
        let mut profiles: Vec<BrowserProfile> = vec![
            BrowserProfile {
                name: "Chrome".to_string(),
                history_path: home
                    .join("Library/Application Support/Google/Chrome/Default/History"),
                query: CHROME_QUERY,
            },
            BrowserProfile {
                name: "Brave".to_string(),
                history_path: home.join(
                    "Library/Application Support/BraveSoftware/Brave-Browser/Default/History",
                ),
                query: CHROME_QUERY,
            },
        ]
        .into_iter()
        .filter(|p| p.history_path.exists())
        .collect();

        // Firefox stores history in profile sub-directories
        let ff_dir = home.join("Library/Application Support/Firefox/Profiles");
        profiles.extend(expand_firefox_profiles(&ff_dir, "Firefox"));

        return profiles;
    }

    #[cfg(target_os = "linux")]
    {
        let home = dirs::home_dir().unwrap_or_default();
        let mut profiles: Vec<BrowserProfile> = vec![BrowserProfile {
            name: "Chrome".to_string(),
            history_path: home.join(".config/google-chrome/Default/History"),
            query: CHROME_QUERY,
        }]
        .into_iter()
        .filter(|p| p.history_path.exists())
        .collect();

        let ff_dir = home.join(".mozilla/firefox");
        profiles.extend(expand_firefox_profiles(&ff_dir, "Firefox"));

        return profiles;
    }

    #[cfg(target_os = "windows")]
    {
        let home = dirs::home_dir().unwrap_or_default();
        let mut profiles: Vec<BrowserProfile> = vec![
            BrowserProfile {
                name: "Chrome".to_string(),
                history_path: home
                    .join(r"AppData\Local\Google\Chrome\User Data\Default\History"),
                query: CHROME_QUERY,
            },
            BrowserProfile {
                name: "Edge".to_string(),
                history_path: home
                    .join(r"AppData\Local\Microsoft\Edge\User Data\Default\History"),
                query: CHROME_QUERY,
            },
            BrowserProfile {
                name: "Brave".to_string(),
                history_path: home.join(
                    r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History",
                ),
                query: CHROME_QUERY,
            },
        ]
        .into_iter()
        .filter(|p| p.history_path.exists())
        .collect();

        let ff_dir = home.join(r"AppData\Roaming\Mozilla\Firefox\Profiles");
        profiles.extend(expand_firefox_profiles(&ff_dir, "Firefox"));

        return profiles;
    }

    vec![]
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
            // Browser history DBs are locked while the browser runs — copy first.
            // Include PID in the temp filename to avoid races between concurrent scans.
            let tmp = std::env::temp_dir().join(format!(
                "conan_history_{}_{}.db",
                profile.name,
                std::process::id()
            ));
            if let Err(e) = std::fs::copy(&profile.history_path, &tmp) {
                debug!(browser = %profile.name, error = %e, "could not copy browser history, skipping");
                continue;
            }

            if let Ok(conn) = rusqlite::Connection::open(&tmp) {
                if let Ok(mut stmt) = conn.prepare(profile.query) {
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
