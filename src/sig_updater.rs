use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub const SIGNATURE_FILES: &[&str] = &[
    "anthropic.yaml",
    "azure-openai.yaml",
    "cohere.yaml",
    "google-ai.yaml",
    "groq.yaml",
    "huggingface.yaml",
    "localai.yaml",
    "mistral.yaml",
    "ollama.yaml",
    "openai.yaml",
    "perplexity.yaml",
];

pub const UPSTREAM_BASE: &str =
    "https://raw.githubusercontent.com/thinkgrid-labs/conan/main/signatures";

/// Persisted to `~/.conan/sig_update_state.json`.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct SigUpdateState {
    /// Unix timestamp (seconds) of the last successful auto-update.
    pub last_updated_at: u64,
}

impl SigUpdateState {
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join("sig_update_state.json");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, data_dir: &Path) -> anyhow::Result<()> {
        let path = data_dir.join("sig_update_state.json");
        std::fs::write(path, serde_json::to_string_pretty(self)?)?;
        Ok(())
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Run a signature update if auto-update is enabled and the interval has elapsed.
/// Returns `true` if an update was attempted.
pub async fn maybe_update(
    cfg: &crate::config::ConanConfig,
    data_dir: &Path,
    sig_dir: &Path,
) -> bool {
    let sig_cfg = match &cfg.signatures {
        Some(s) => s,
        None => return false,
    };

    if sig_cfg.auto_update != Some(true) {
        return false;
    }

    let interval_hours = sig_cfg.update_interval_hours.unwrap_or(24);
    let interval_secs = interval_hours * 3600;
    let state = SigUpdateState::load(data_dir);
    let now = now_secs();

    if now.saturating_sub(state.last_updated_at) < interval_secs {
        return false;
    }

    let base = sig_cfg.upstream_base.as_deref().unwrap_or(UPSTREAM_BASE);

    tracing::info!(interval_hours, upstream = base, "auto-updating signatures");

    match fetch_and_write(sig_dir, base).await {
        Ok((ok, fail)) => {
            tracing::info!(ok, fail, "signature auto-update complete");
            // Save state even if some files failed — prevents hammering on partial failures
            let updated = SigUpdateState {
                last_updated_at: now,
            };
            if let Err(e) = updated.save(data_dir) {
                tracing::warn!("failed to save sig update state: {e}");
            }
        }
        Err(e) => {
            tracing::warn!("signature auto-update failed: {e}");
        }
    }

    true
}

/// Fetch all signature files from `upstream_base` and write them to `sig_dir`.
///
/// Returns `(ok, fail)` counts. Validates each YAML before writing.
/// Errors only on hard failures (HTTP client init, I/O); per-file failures are counted.
pub async fn fetch_and_write(
    sig_dir: &Path,
    upstream_base: &str,
) -> anyhow::Result<(usize, usize)> {
    std::fs::create_dir_all(sig_dir)?;

    let client = reqwest::Client::builder()
        .user_agent(concat!("conan/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let mut ok = 0usize;
    let mut fail = 0usize;

    for filename in SIGNATURE_FILES {
        let url = format!("{upstream_base}/{filename}");
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => match resp.text().await {
                Ok(body) => {
                    if let Err(e) = serde_yaml::from_str::<conan_core::registry::Signature>(&body) {
                        eprintln!("  ✗ {filename}: invalid YAML from upstream ({e})");
                        tracing::warn!("{filename}: invalid YAML from upstream: {e}");
                        fail += 1;
                    } else {
                        std::fs::write(sig_dir.join(filename), &body)?;
                        eprintln!("  ✓ {filename}");
                        ok += 1;
                    }
                }
                Err(e) => {
                    eprintln!("  ✗ {filename}: read error ({e})");
                    tracing::warn!("{filename}: read error — {e}");
                    fail += 1;
                }
            },
            Ok(resp) => {
                eprintln!("  ✗ {filename}: HTTP {}", resp.status());
                tracing::warn!("{filename}: HTTP {}", resp.status());
                fail += 1;
            }
            Err(e) => {
                eprintln!("  ✗ {filename}: {e}");
                tracing::warn!("{filename}: {e}");
                fail += 1;
            }
        }
    }

    Ok((ok, fail))
}
