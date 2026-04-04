use async_trait::async_trait;
use conan_core::{
    event::{Event, EventPayload},
    finding::{DlpMatch, DlpSeverity, Finding},
    traits::{Analyzer, ScanContext},
};
use regex::Regex;
use tracing::debug;

pub struct CoreAnalyzer;

#[async_trait]
impl Analyzer for CoreAnalyzer {
    async fn analyze(&self, events: Vec<Event>, ctx: &ScanContext) -> Vec<Finding> {
        let mut findings = vec![];

        for event in events {
            let (signature, dlp_matches) = match_event(&event, ctx);

            if signature.is_none() && dlp_matches.is_empty() {
                continue;
            }

            let detail = build_detail(&event, signature.as_ref().map(|s| s.name.as_str()));
            let finding = Finding::new(event, signature.as_ref(), dlp_matches, detail);
            debug!(id = %finding.id, risk = %finding.risk_score.0, "finding created");
            findings.push(finding);
        }

        findings
    }
}

fn match_event(
    event: &Event,
    ctx: &ScanContext,
) -> (Option<conan_core::registry::Signature>, Vec<DlpMatch>) {
    let mut dlp_matches = vec![];

    let (matched_sig, text_to_scan) = match &event.payload {
        EventPayload::NetworkConnection { remote_host, .. } => {
            let sigs = ctx.registry.match_domain(remote_host);
            let sig = sigs.into_iter().next().cloned();
            (sig, None::<String>)
        }
        EventPayload::Process { name, cmdline, .. } => {
            let sigs = ctx.registry.match_process(name);
            let sig = sigs.into_iter().next().cloned();
            (sig, Some(cmdline.clone()))
        }
        EventPayload::ShellHistory { command, .. } => {
            // Match the first token (binary name) against registry process names
            let bin = command
                .split_whitespace()
                .next()
                .unwrap_or("")
                .rsplit('/')
                .next()
                .unwrap_or("");
            let sigs = ctx.registry.match_process(bin);
            let sig = sigs.into_iter().next().cloned();
            (sig, Some(command.clone()))
        }
        EventPayload::BrowserHistory { url, .. } => {
            let host = extract_host(url);
            let sigs = ctx.registry.match_domain(&host);
            let sig = sigs.into_iter().next().cloned();
            (sig, None)
        }
        EventPayload::CodebaseFile { matched_text, .. } => {
            // Codebase events are pre-classified by conan-os
            let dlp = DlpMatch {
                pattern_id: matched_text.clone(),
                description: format!("Pattern '{}' found in source file", matched_text),
                severity: DlpSeverity::Critical,
            };
            dlp_matches.push(dlp);
            (None, None)
        }
    };

    // Run DLP patterns from the matched signature against any available text
    if let (Some(sig), Some(text)) = (&matched_sig, &text_to_scan) {
        for pattern in &sig.dlp_patterns {
            if let Ok(re) = Regex::new(&pattern.pattern) {
                if re.is_match(text) {
                    dlp_matches.push(DlpMatch {
                        pattern_id: pattern.id.clone(),
                        description: format!("DLP match: {}", pattern.id),
                        severity: match pattern.severity.as_str() {
                            "critical" => DlpSeverity::Critical,
                            "high" => DlpSeverity::High,
                            _ => DlpSeverity::Low,
                        },
                    });
                }
            }
        }
    }

    (matched_sig, dlp_matches)
}

fn build_detail(event: &Event, service: Option<&str>) -> String {
    let svc = service.unwrap_or("unknown service");
    match &event.payload {
        EventPayload::NetworkConnection {
            remote_host, port, ..
        } => {
            format!("{svc} — connection to {remote_host}:{port}")
        }
        EventPayload::Process { name, pid, .. } => {
            format!("{svc} — process '{name}' running (pid {pid})")
        }
        EventPayload::ShellHistory { command, shell, .. } => {
            format!("{svc} — found in {shell} history: `{command}`")
        }
        EventPayload::BrowserHistory { url, browser, .. } => {
            format!("{svc} — visited via {browser}: {url}")
        }
        EventPayload::CodebaseFile {
            file_path,
            line_number,
            matched_text,
        } => {
            let line = line_number.map(|l| format!(":{l}")).unwrap_or_default();
            format!("DLP match '{matched_text}' in {file_path}{line}")
        }
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
