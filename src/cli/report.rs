use anyhow::Result;
use clap::{Args, ValueEnum};

#[derive(Debug, Clone, ValueEnum)]
pub enum ReportFormat {
    Pretty,
    Json,
    Markdown,
    Html,
}

#[derive(Args, Debug)]
pub struct ReportArgs {
    /// Show findings from the last N hours. (e.g. 24)
    #[arg(long)]
    pub last: Option<u32>,

    /// Stream new findings live (polls the DB every second).
    #[arg(long)]
    pub live: bool,

    /// Output format.
    #[arg(long, value_enum, default_value = "pretty")]
    pub format: ReportFormat,
}

pub async fn run(args: ReportArgs) -> Result<()> {
    let data_dir = crate::data_dir()?;
    let db_path = data_dir.join("findings.db");

    if !db_path.exists() {
        println!("No findings database found. Run `conan scan` first.");
        return Ok(());
    }

    let store = conan_db::Store::open(&db_path)?;

    if args.live {
        return run_live(store).await;
    }

    let findings = store.query_findings(args.last)?;

    if findings.is_empty() {
        println!("No findings.");
        return Ok(());
    }

    match args.format {
        ReportFormat::Pretty => print_pretty(&findings),
        ReportFormat::Json => println!("{}", serde_json::to_string_pretty(&findings)?),
        ReportFormat::Markdown => print_markdown(&findings),
        ReportFormat::Html => {
            // Build Finding structs from JSON rows for the HTML reporter
            let typed: Vec<conan_core::finding::Finding> = findings
                .iter()
                .filter_map(|v| serde_json::from_value(v.clone()).ok())
                .collect();
            // Fall back to value-based HTML if deserialization partially fails
            if typed.len() == findings.len() {
                println!("{}", crate::reporter::html(&typed));
            } else {
                println!("{}", html_from_values(&findings));
            }
        }
    }

    Ok(())
}

async fn run_live(store: conan_db::Store) -> Result<()> {
    let mut last_ts = chrono::Utc::now().to_rfc3339();
    println!("[live] watching for new findings (Ctrl-C to stop)...");

    loop {
        tokio::select! {
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(1)) => {
                let new = store.query_findings_since(&last_ts)?;
                for row in &new {
                    let level = row["risk_level"].as_str().unwrap_or("?");
                    let service = row["service_name"].as_str().unwrap_or("unknown");
                    let detail = row["detail"].as_str().unwrap_or("");
                    let ts = row["timestamp"].as_str().unwrap_or("");
                    println!("[{level:<8}]  {service:<20} {detail}  ({ts})");
                    if let Some(ts_val) = row["timestamp"].as_str() {
                        last_ts = ts_val.to_string();
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\n[live] stopped.");
                break;
            }
        }
    }
    Ok(())
}

fn print_pretty(findings: &[serde_json::Value]) {
    for f in findings {
        let level = f["risk_level"].as_str().unwrap_or("?");
        let service = f["service_name"].as_str().unwrap_or("unknown");
        let detail = f["detail"].as_str().unwrap_or("");
        let ts = f["timestamp"].as_str().unwrap_or("");
        println!("[{level:<8}]  {service:<20} {detail}  ({ts})");
    }
}

fn print_markdown(findings: &[serde_json::Value]) {
    println!("# Conan Scan Report\n");
    println!("| Risk | Service | Detail |");
    println!("|------|---------|--------|");
    for f in findings {
        let level = f["risk_level"].as_str().unwrap_or("?");
        let service = f["service_name"].as_str().unwrap_or("unknown");
        let detail = f["detail"].as_str().unwrap_or("");
        println!("| {level} | {service} | {detail} |");
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn html_from_values(findings: &[serde_json::Value]) -> String {
    let rows: String = findings
        .iter()
        .map(|f| {
            let level = f["risk_level"].as_str().unwrap_or("?");
            let color = match level {
                "CRITICAL" => "#f44336",
                "HIGH" => "#ff9800",
                "MEDIUM" => "#ffc107",
                _ => "#4caf50",
            };
            let service = html_escape(f["service_name"].as_str().unwrap_or("unknown"));
            let detail = html_escape(f["detail"].as_str().unwrap_or(""));
            let ts = html_escape(f["timestamp"].as_str().unwrap_or(""));
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
<div class="meta">{} finding(s)</div>
<table>
<thead><tr><th>Risk</th><th>Service</th><th>Detail</th><th>Timestamp</th></tr></thead>
<tbody>{}</tbody>
</table>
</body>
</html>"#,
        findings.len(),
        rows
    )
}
