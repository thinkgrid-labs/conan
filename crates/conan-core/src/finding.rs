use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use crate::risk::RiskLevel;
use crate::{event::Event, registry::Signature, risk::RiskScore};

/// A DLP (Data Loss Prevention) match found in an event payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpMatch {
    pub pattern_id: String,
    pub description: String,
    pub severity: DlpSeverity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DlpSeverity {
    Low,
    High,
    Critical,
}

/// The result of analyzing an event against the registry and policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: uuid::Uuid,
    pub timestamp: DateTime<Utc>,
    pub event: Event,
    /// The matched signature, if any.
    pub signature_id: Option<String>,
    pub service_name: Option<String>,
    pub risk_score: RiskScore,
    pub risk_level: RiskLevel,
    pub dlp_matches: Vec<DlpMatch>,
    pub detail: String,
}

impl Finding {
    pub fn new(event: Event, signature: Option<&Signature>, dlp_matches: Vec<DlpMatch>, detail: String) -> Self {
        let base = signature.map(|s| s.risk_base).unwrap_or(30);
        let has_critical = dlp_matches.iter().any(|d| d.severity == DlpSeverity::Critical);
        let has_high = dlp_matches.iter().any(|d| d.severity == DlpSeverity::High);
        let risk_score = RiskScore::calculate(base, has_critical, has_high, false);
        let risk_level = risk_score.level();

        Self {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            signature_id: signature.map(|s| s.id.clone()),
            service_name: signature.map(|s| s.name.clone()),
            risk_score,
            risk_level,
            dlp_matches,
            detail,
            event,
        }
    }
}
