use conan_core::finding::{Finding, RiskLevel};

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
        let policy = format!("{}", f.policy_action);
        let rule_hint = f
            .matched_rule
            .as_deref()
            .map(|r| format!(" (rule: {r})"))
            .unwrap_or_default();
        out.push_str(&format!(
            "[{level:<8}] [{policy:<7}]{rule_hint}  {service:<20}  {}{dlp}\n",
            f.detail
        ));
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

pub fn html(findings: &[Finding]) -> String {
    let rows: String = findings
        .iter()
        .map(|f| {
            let level = format!("{}", f.risk_level);
            let color = match f.risk_level {
                RiskLevel::Critical => "#f44336",
                RiskLevel::High => "#ff9800",
                RiskLevel::Medium => "#ffc107",
                RiskLevel::Low => "#4caf50",
            };
            let service = f.service_name.as_deref().unwrap_or("unknown");
            let detail = html_escape(&f.detail);
            let ts = f.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string();
            format!(
                r#"<tr><td style="background:{color};color:#fff;font-weight:bold;padding:4px 8px">{level}</td><td>{service}</td><td>{detail}</td><td style="color:#888;font-size:0.9em">{ts}</td></tr>"#
            )
        })
        .collect();

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Conan Scan Report</title>
<style>
body{{font-family:system-ui,sans-serif;margin:2rem;background:#fafafa;color:#222}}
h1{{font-size:1.4rem;margin-bottom:0.25rem}}
.meta{{color:#666;font-size:0.9rem;margin-bottom:1.5rem}}
table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 4px rgba(0,0,0,.1)}}
th{{background:#333;color:#fff;padding:8px 12px;text-align:left;font-size:0.85rem}}
td{{padding:8px 12px;border-bottom:1px solid #eee;font-size:0.9rem}}
tr:last-child td{{border-bottom:none}}
</style>
</head>
<body>
<h1>Conan AI Governance Report</h1>
<div class="meta">Generated: {} &bull; {} finding(s)</div>
<table>
<thead><tr><th>Risk</th><th>Service</th><th>Detail</th><th>Timestamp</th></tr></thead>
<tbody>{}</tbody>
</table>
</body>
</html>"#,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        findings.len(),
        rows
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
