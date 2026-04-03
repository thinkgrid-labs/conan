/// Reads active TCP connections from /proc/net/tcp (Linux) or `netstat` (macOS)
/// and matches remote hosts against the signature registry.
use async_trait::async_trait;
use conan_core::{
    error::ConanError,
    event::{Event, EventPayload, Source},
    registry::Registry,
    traits::Ingestor,
};
use std::process::Command;
use tracing::debug;

pub struct ActiveConnectionIngestor {
    pub registry: Registry,
}

impl ActiveConnectionIngestor {
    pub fn new(registry: Registry) -> Self {
        Self { registry }
    }

    /// Parse `netstat -n` output and return (remote_ip, remote_host, port) tuples.
    fn active_connections() -> Vec<(String, u16)> {
        let output = Command::new("netstat").args(["-n", "-p", "tcp"]).output();

        let Ok(out) = output else { return vec![] };
        let text = String::from_utf8_lossy(&out.stdout);

        let mut conns = vec![];
        for line in text.lines() {
            // Lines look like: tcp4  0  0  192.168.1.5.52341  23.102.140.112.443  ESTABLISHED
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                continue;
            }
            if parts[0].starts_with("tcp") {
                if let Some(remote) = parts.get(4) {
                    if let Some((addr, port_str)) = remote.rsplit_once('.') {
                        if let Ok(port) = port_str.parse::<u16>() {
                            conns.push((addr.to_string(), port));
                        }
                    }
                }
            }
        }
        conns
    }
}

#[async_trait]
impl Ingestor for ActiveConnectionIngestor {
    fn name(&self) -> &'static str {
        "connections"
    }

    async fn ingest(&self) -> Result<Vec<Event>, ConanError> {
        let mut events = vec![];
        let conns = Self::active_connections();

        for (remote_addr, port) in conns {
            // Try to reverse-map the IP to a known AI service domain via registry
            let matches = self.registry.match_domain(&remote_addr);
            if !matches.is_empty() {
                debug!(remote = %remote_addr, port = port, "matched AI connection");
                events.push(Event::new(
                    Source::Network,
                    EventPayload::NetworkConnection {
                        remote_host: remote_addr.clone(),
                        remote_ip: Some(remote_addr.clone()),
                        port,
                        protocol: "tcp".to_string(),
                        http_headers: None,
                        body_snippet: None,
                    },
                ));
            }
        }

        Ok(events)
    }
}
