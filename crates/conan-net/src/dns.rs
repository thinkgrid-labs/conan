/// Checks /etc/hosts and does forward DNS lookups for all known AI service domains.
use async_trait::async_trait;
use conan_core::{
    error::ConanError,
    event::{Event, EventPayload, Source},
    registry::Registry,
    traits::Ingestor,
};
use std::net::ToSocketAddrs;
use tracing::debug;

pub struct DnsIngestor {
    pub registry: Registry,
}

impl DnsIngestor {
    pub fn new(registry: Registry) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl Ingestor for DnsIngestor {
    fn name(&self) -> &'static str {
        "dns"
    }

    async fn ingest(&self) -> Result<Vec<Event>, ConanError> {
        let mut events = vec![];
        let mut resolved: std::collections::HashSet<String> = std::collections::HashSet::new();

        for sig in self.registry.all() {
            for domain in &sig.domains {
                if resolved.contains(domain) {
                    continue;
                }
                resolved.insert(domain.clone());

                // Attempt a DNS lookup — if it resolves, the domain is reachable
                let addr_str = format!("{domain}:443");
                let reachable = tokio::task::spawn_blocking({
                    let addr_str = addr_str.clone();
                    move || addr_str.to_socket_addrs().is_ok()
                })
                .await
                .unwrap_or(false);

                if reachable {
                    debug!(domain = %domain, "AI domain resolves (reachable)");
                    events.push(Event::new(
                        Source::Network,
                        EventPayload::NetworkConnection {
                            remote_host: domain.clone(),
                            remote_ip: None,
                            port: 443,
                            protocol: "dns".to_string(),
                            http_headers: None,
                            body_snippet: None,
                        },
                    ));
                }
            }
        }

        Ok(events)
    }
}
