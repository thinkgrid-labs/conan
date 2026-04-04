use async_trait::async_trait;
use conan_core::{
    error::ConanError,
    event::{Event, EventPayload, Source},
    registry::Registry,
    traits::Ingestor,
};
use std::collections::HashSet;
use tracing::{debug, warn};

/// Live packet capture ingestor.
///
/// Requires libpcap (Linux: `apt install libpcap-dev`, macOS: ships with Xcode CLI tools)
/// and elevated privileges (`sudo` or `CAP_NET_RAW`).
///
/// Captures TCP traffic on ports 80/443 for the specified duration and emits:
/// - `NetworkConnection` events for any host matching the signature registry
/// - `NetworkConnection` events carrying an `Authorization` header (even without a
///   registry match) so the DLP pipeline can inspect the token in transit
pub struct PcapIngestor {
    pub registry: Registry,
    /// Override the network interface. `None` uses the system default.
    pub interface: Option<String>,
    /// How long to capture before returning. Default: 10 seconds.
    pub capture_secs: u64,
}

impl PcapIngestor {
    pub fn new(registry: Registry) -> Self {
        Self {
            registry,
            interface: None,
            capture_secs: 10,
        }
    }

    pub fn with_interface(mut self, iface: &str) -> Self {
        self.interface = Some(iface.to_string());
        self
    }

    pub fn with_duration(mut self, secs: u64) -> Self {
        self.capture_secs = secs;
        self
    }
}

#[async_trait]
impl Ingestor for PcapIngestor {
    fn name(&self) -> &'static str {
        "pcap"
    }

    async fn ingest(&self) -> Result<Vec<Event>, ConanError> {
        let registry = self.registry.clone();
        let interface = self.interface.clone();
        let capture_secs = self.capture_secs;

        // pcap 2.x: Capture<Active> is Send + Sync, safe for spawn_blocking.
        tokio::task::spawn_blocking(move || capture_loop(registry, interface, capture_secs))
            .await
            .map_err(|e| ConanError::NetworkCapture(e.to_string()))?
    }
}

// ── capture loop ──────────────────────────────────────────────────────────────

fn capture_loop(
    registry: Registry,
    interface: Option<String>,
    capture_secs: u64,
) -> Result<Vec<Event>, ConanError> {
    use pcap::{Capture, Device};

    let device = match interface {
        Some(ref iface) => Device::from(iface.as_str()),
        None => Device::lookup()
            .map_err(|e| ConanError::NetworkCapture(e.to_string()))?
            .ok_or_else(|| {
                ConanError::NetworkCapture("no default network device found".to_string())
            })?,
    };

    let mut cap = Capture::from_device(device)
        .map_err(|e| ConanError::NetworkCapture(e.to_string()))?
        .promisc(false)
        .snaplen(65535)
        .timeout(200) // ms — keeps the loop responsive to the deadline
        .open()
        .map_err(|e| {
            let msg = e.to_string();
            if msg.to_lowercase().contains("permission")
                || msg.to_lowercase().contains("operation not permitted")
                || msg.to_lowercase().contains("access is denied")
            {
                ConanError::NetworkCapture(
                    "permission denied — \
                     on Linux: sudo setcap cap_net_raw+eip $(which conan); \
                     on macOS: run with sudo"
                        .to_string(),
                )
            } else {
                ConanError::NetworkCapture(msg)
            }
        })?;

    cap.filter("tcp port 80 or tcp port 443", true)
        .map_err(|e| ConanError::NetworkCapture(e.to_string()))?;

    let start = std::time::Instant::now();
    let deadline = std::time::Duration::from_secs(capture_secs);
    let mut events: Vec<Event> = vec![];
    let mut seen: HashSet<String> = HashSet::new();

    while start.elapsed() < deadline {
        match cap.next_packet() {
            Ok(packet) => {
                if let Some(event) = parse_packet(&registry, packet.data) {
                    // Deduplicate by host:port within a single capture window
                    let key = match &event.payload {
                        EventPayload::NetworkConnection {
                            remote_host, port, ..
                        } => format!("{remote_host}:{port}"),
                        _ => continue,
                    };
                    if seen.insert(key.clone()) {
                        debug!(connection = %key, "pcap: new AI connection");
                        events.push(event);
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                warn!("pcap: read error: {e}");
                break;
            }
        }
    }

    Ok(events)
}

// ── packet parsing ────────────────────────────────────────────────────────────

fn parse_packet(registry: &Registry, data: &[u8]) -> Option<Event> {
    let (dst_ip, dst_port, payload) = extract_tcp_payload(data)?;
    if payload.is_empty() {
        return None;
    }
    match dst_port {
        80 | 8080 => parse_http(registry, payload, &dst_ip, dst_port),
        443 | 8443 => parse_tls_sni(registry, payload, &dst_ip, dst_port),
        _ => None,
    }
}

/// Walk Ethernet → IP → TCP and return `(dst_ip, dst_port, tcp_payload)`.
fn extract_tcp_payload(data: &[u8]) -> Option<(String, u16, &[u8])> {
    // Ethernet header: dst(6) src(6) ethertype(2) = 14 bytes
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);

    let (ip_hdr_end, dst_ip, proto) = match ethertype {
        0x0800 => {
            // IPv4
            let ip = data.get(14..)?;
            if ip.len() < 20 {
                return None;
            }
            let ihl = (ip[0] & 0x0f) as usize * 4;
            let proto = ip[9];
            let dst = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
            (14 + ihl, dst, proto)
        }
        0x86DD => {
            // IPv6: fixed 40-byte header
            let ip = data.get(14..)?;
            if ip.len() < 40 {
                return None;
            }
            let next_hdr = ip[6];
            let dst = format!(
                "{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:\
                 {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                ip[24],
                ip[25],
                ip[26],
                ip[27],
                ip[28],
                ip[29],
                ip[30],
                ip[31],
                ip[32],
                ip[33],
                ip[34],
                ip[35],
                ip[36],
                ip[37],
                ip[38],
                ip[39]
            );
            (14 + 40, dst, next_hdr)
        }
        _ => return None,
    };

    if proto != 6 {
        return None; // not TCP
    }

    let tcp = data.get(ip_hdr_end..)?;
    if tcp.len() < 20 {
        return None;
    }

    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    let payload = data.get(ip_hdr_end + data_offset..)?;

    Some((dst_ip, dst_port, payload))
}

// ── HTTP parser ───────────────────────────────────────────────────────────────

fn parse_http(registry: &Registry, payload: &[u8], dst_ip: &str, port: u16) -> Option<Event> {
    let text = std::str::from_utf8(payload).ok()?;
    let first_line = text.lines().next()?;

    // Require a valid HTTP method on the request line
    if !matches!(
        first_line.split_whitespace().next(),
        Some("GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS")
    ) {
        return None;
    }

    let mut host = String::new();
    let mut headers = serde_json::Map::new();

    for line in text.lines().skip(1) {
        if line.is_empty() {
            break; // blank line = end of headers
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_lowercase();
            let val = v.trim().to_string();
            if key == "host" {
                host = val.clone();
            }
            headers.insert(key, serde_json::Value::String(val));
        }
    }

    if host.is_empty() {
        host = dst_ip.to_string();
    }

    let matches_registry = !registry.match_domain(&host).is_empty();
    let has_auth = headers.contains_key("authorization");

    // Only emit if we recognize the service or there's a token in-flight
    if !matches_registry && !has_auth {
        return None;
    }

    Some(Event::new(
        Source::Network,
        EventPayload::NetworkConnection {
            remote_host: host,
            remote_ip: Some(dst_ip.to_string()),
            port,
            protocol: "http".to_string(),
            http_headers: if headers.is_empty() {
                None
            } else {
                Some(serde_json::Value::Object(headers))
            },
            body_snippet: None,
        },
    ))
}

// ── TLS SNI parser ────────────────────────────────────────────────────────────

fn parse_tls_sni(registry: &Registry, payload: &[u8], dst_ip: &str, port: u16) -> Option<Event> {
    let sni = extract_tls_sni(payload)?;
    if registry.match_domain(&sni).is_empty() {
        return None;
    }
    Some(Event::new(
        Source::Network,
        EventPayload::NetworkConnection {
            remote_host: sni,
            remote_ip: Some(dst_ip.to_string()),
            port,
            protocol: "https".to_string(),
            http_headers: None,
            body_snippet: None,
        },
    ))
}

/// Extract the SNI hostname from a TLS ClientHello record.
///
/// TLS record: content_type(1=0x16) version(2) length(2)
/// Handshake:  type(1=0x01) length(3) body
/// ClientHello body: version(2) random(32) session_id_len(1) session_id(var)
///                   cipher_suites_len(2) cipher_suites(var)
///                   compression_len(1) compression(var)
///                   extensions_len(2) extensions(var)
/// SNI extension: type=0x0000, data = list_len(2) name_type(1=0x00) name_len(2) name
pub fn extract_tls_sni(data: &[u8]) -> Option<String> {
    if data.len() < 5 || data[0] != 0x16 {
        return None; // not a TLS Handshake record
    }

    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    let handshake = data.get(5..5 + record_len)?;

    if handshake.first() != Some(&0x01) {
        return None; // not ClientHello
    }

    // Skip handshake header (type=1, length=3)
    let hello = handshake.get(4..)?;
    if hello.len() < 35 {
        return None;
    }

    let mut pos = 2 + 32; // skip client_version(2) + random(32)

    let session_id_len = *hello.get(pos)? as usize;
    pos += 1 + session_id_len;

    let cs_len = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
    pos += 2 + cs_len;

    let comp_len = *hello.get(pos)? as usize;
    pos += 1 + comp_len;

    // Skip extensions_len(2)
    pos += 2;

    // Walk extensions
    while pos + 4 <= hello.len() {
        let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let ext_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI: list_len(2) name_type(1) name_len(2) name(var)
            let ext = hello.get(pos..pos + ext_len)?;
            if ext.len() < 5 || ext[2] != 0x00 {
                return None;
            }
            let name_len = u16::from_be_bytes([ext[3], ext[4]]) as usize;
            return std::str::from_utf8(ext.get(5..5 + name_len)?)
                .ok()
                .map(|s| s.to_string());
        }

        pos += ext_len;
    }

    None
}

// ── unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_tls_data() {
        assert!(extract_tls_sni(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn rejects_short_data() {
        assert!(extract_tls_sni(&[0x16, 0x03, 0x01]).is_none());
    }

    #[test]
    fn rejects_non_handshake_record() {
        // content_type = 0x17 (application data, not handshake)
        let data = [0x17u8, 0x03, 0x03, 0x00, 0x01, 0x00];
        assert!(extract_tls_sni(&data).is_none());
    }

    #[test]
    fn http_parse_rejects_non_http_payload() {
        // Random binary data should not produce an event
        let registry = conan_core::registry::Registry::new();
        assert!(parse_http(&registry, b"\x00\x01\x02garbage", "1.2.3.4", 80).is_none());
    }

    #[test]
    fn http_parse_extracts_host_header() {
        let mut registry = conan_core::registry::Registry::new();
        registry.insert(conan_core::registry::Signature {
            id: "openai".to_string(),
            name: "OpenAI".to_string(),
            version: "1.0.0".to_string(),
            risk_base: 60,
            domains: vec!["api.openai.com".to_string()],
            ip_ranges: vec![],
            process_names: vec![],
            dlp_patterns: vec![],
            http_patterns: conan_core::registry::HttpPatterns::default(),
            tags: vec![],
            privacy_policy_url: None,
        });

        let raw = b"POST /v1/chat/completions HTTP/1.1\r\nHost: api.openai.com\r\nContent-Type: application/json\r\n\r\n";
        let event = parse_http(&registry, raw, "23.102.140.112", 80);
        assert!(event.is_some());
        if let Some(EventPayload::NetworkConnection {
            remote_host,
            protocol,
            ..
        }) = event.map(|e| e.payload)
        {
            assert_eq!(remote_host, "api.openai.com");
            assert_eq!(protocol, "http");
        }
    }

    #[test]
    fn http_parse_emits_for_authorization_header_even_without_registry_match() {
        let registry = conan_core::registry::Registry::new(); // empty
        let raw =
            b"POST /api HTTP/1.1\r\nHost: unknown.internal\r\nAuthorization: Bearer sk-abc\r\n\r\n";
        assert!(parse_http(&registry, raw, "10.0.0.1", 80).is_some());
    }
}
