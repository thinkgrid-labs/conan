use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConanConfig {
    pub webhook: Option<WebhookConfig>,
    pub daemon: Option<DaemonConfig>,
    pub signatures: Option<SigConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    pub url: String,
    /// Minimum seconds between repeated webhook fires for the same service. Default 30.
    pub debounce_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Seconds between scan cycles. Default 300.
    pub scan_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigConfig {
    pub upstream_base: Option<String>,
}

impl ConanConfig {
    pub fn load(data_dir: &Path) -> anyhow::Result<Self> {
        let path = data_dir.join("config.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = std::fs::read_to_string(&path)?;
        let mut cfg: Self = toml::from_str(&content)?;

        // Env var overrides
        if let Ok(url) = std::env::var("CONAN_WEBHOOK_URL") {
            cfg.webhook
                .get_or_insert_with(|| WebhookConfig {
                    url: String::new(),
                    debounce_secs: None,
                })
                .url = url;
        }
        Ok(cfg)
    }
}
