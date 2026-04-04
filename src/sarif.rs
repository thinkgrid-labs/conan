use conan_core::{
    event::EventPayload,
    finding::{Finding, RiskLevel},
};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLog<'a> {
    #[serde(rename = "$schema")]
    schema: &'a str,
    version: &'a str,
    runs: Vec<SarifRun<'a>>,
}

#[derive(Serialize)]
struct SarifRun<'a> {
    tool: SarifTool<'a>,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool<'a> {
    driver: ToolComponent<'a>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ToolComponent<'a> {
    name: &'a str,
    version: &'a str,
    information_uri: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: String,
    message: TextMessage,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct TextMessage {
    text: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: PhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PhysicalLocation {
    artifact_location: ArtifactLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<Region>,
}

#[derive(Serialize)]
struct ArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Region {
    start_line: u32,
}

fn risk_to_sarif_level(level: &RiskLevel) -> &'static str {
    match level {
        RiskLevel::Critical | RiskLevel::High => "error",
        RiskLevel::Medium => "warning",
        RiskLevel::Low => "note",
    }
}

fn finding_to_result(f: &Finding) -> SarifResult {
    let rule_id = f
        .signature_id
        .clone()
        .unwrap_or_else(|| "conan/unknown".to_string());
    let level = risk_to_sarif_level(&f.risk_level).to_string();
    let message = TextMessage {
        text: f.detail.clone(),
    };

    let locations = match &f.event.payload {
        EventPayload::CodebaseFile {
            file_path,
            line_number,
            ..
        } => {
            vec![SarifLocation {
                physical_location: PhysicalLocation {
                    artifact_location: ArtifactLocation {
                        uri: file_path.clone(),
                    },
                    region: line_number.map(|l| Region { start_line: l }),
                },
            }]
        }
        _ => vec![],
    };

    SarifResult {
        rule_id,
        level,
        message,
        locations,
    }
}

pub fn sarif(findings: &[Finding]) -> String {
    let log = SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: ToolComponent {
                    name: "conan",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/thinkgrid-labs/conan",
                },
            },
            results: findings.iter().map(finding_to_result).collect(),
        }],
    };

    serde_json::to_string_pretty(&log).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
}
