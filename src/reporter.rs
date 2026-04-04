use conan_core::finding::Finding;

pub fn pretty(findings: &[Finding]) -> String {
    if findings.is_empty() {
        return "No findings.".to_string();
    }

    let mut out = String::new();
    for f in findings {
        let level = format!("{}", f.risk_level);
        let service = f.service_name.as_deref().unwrap_or("unknown");
        let dlp = if f.dlp_matches.is_empty() {
            String::new()
        } else {
            format!(
                " [DLP: {}]",
                f.dlp_matches
                    .iter()
                    .map(|d| d.pattern_id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        out.push_str(&format!("[{level:<8}]  {service:<20}  {}{dlp}\n", f.detail));
    }
    out
}

pub fn json(findings: &[Finding]) -> String {
    serde_json::to_string_pretty(findings).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}

pub fn markdown(findings: &[Finding]) -> String {
    let mut out = String::from("# Conan Scan Report\n\n");
    out.push_str("| Risk | Service | Detail |\n");
    out.push_str("|------|---------|--------|\n");
    for f in findings {
        let level = format!("{}", f.risk_level);
        let service = f.service_name.as_deref().unwrap_or("unknown");
        out.push_str(&format!("| {level} | {service} | {} |\n", f.detail));
    }
    out
}
