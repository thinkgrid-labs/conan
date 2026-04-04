use conan_core::finding::Finding;
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::config::WebhookConfig;

pub struct WebhookClient {
    url: String,
    debounce: Duration,
    last_fired: HashMap<String, Instant>,
}

impl WebhookClient {
    pub fn from_config(cfg: &WebhookConfig) -> Self {
        Self {
            url: cfg.url.clone(),
            debounce: Duration::from_secs(cfg.debounce_secs.unwrap_or(30)),
            last_fired: HashMap::new(),
        }
    }

    /// Fire the webhook for all findings that pass debounce.
    /// Uses a per-service-id debounce key.
    pub async fn fire(&mut self, findings: &[Finding]) {
        if self.url.is_empty() {
            return;
        }

        let now = Instant::now();
        let to_send: Vec<_> = findings
            .iter()
            .filter(|f| {
                let key = f
                    .signature_id
                    .clone()
                    .unwrap_or_else(|| "unknown".to_string());
                match self.last_fired.get(&key) {
                    Some(t) if now.duration_since(*t) < self.debounce => false,
                    _ => true,
                }
            })
            .collect();

        if to_send.is_empty() {
            return;
        }

        // Update debounce timestamps
        for f in &to_send {
            let key = f
                .signature_id
                .clone()
                .unwrap_or_else(|| "unknown".to_string());
            self.last_fired.insert(key, now);
        }

        let payload = build_payload(&to_send);
        let url = self.url.clone();
        let to_send_owned: Vec<Finding> = to_send.iter().map(|f| (*f).clone()).collect();

        tokio::spawn(async move {
            let client = match reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::warn!("webhook: failed to build client: {e}");
                    return;
                }
            };
            match client.post(&url).json(&payload).send().await {
                Ok(r) if r.status().is_success() => {
                    tracing::debug!("webhook: delivered ({} findings)", to_send_owned.len());
                }
                Ok(r) => tracing::warn!("webhook: server returned {}", r.status()),
                Err(e) => tracing::warn!("webhook: delivery failed: {e}"),
            }
        });
    }
}

fn build_payload(findings: &[&Finding]) -> serde_json::Value {
    let items: Vec<_> = findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "id": f.id,
                "timestamp": f.timestamp,
                "risk_level": f.risk_level.to_string(),
                "risk_score": f.risk_score.0,
                "service": f.service_name,
                "detail": f.detail,
            })
        })
        .collect();

    serde_json::json!({
        "tool": "conan",
        "version": env!("CARGO_PKG_VERSION"),
        "findings": items,
    })
}
