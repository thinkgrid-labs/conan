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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        event::{EventPayload, Source},
        registry::HttpPatterns,
    };

    fn make_event() -> crate::event::Event {
        crate::event::Event::new(
            Source::Network,
            EventPayload::NetworkConnection {
                remote_host: "api.openai.com".to_string(),
                remote_ip: None,
                port: 443,
                protocol: "tcp".to_string(),
                http_headers: None,
                body_snippet: None,
            },
        )
    }

    fn make_sig(id: &str, risk_base: u8) -> Signature {
        Signature {
            id: id.to_string(),
            name: format!("{id} Service"),
            version: "1.0.0".to_string(),
            risk_base,
            domains: vec![],
            ip_ranges: vec![],
            process_names: vec![],
            dlp_patterns: vec![],
            http_patterns: HttpPatterns::default(),
            tags: vec![],
            privacy_policy_url: None,
        }
    }

    #[test]
    fn no_signature_uses_default_base_risk_30() {
        let f = Finding::new(make_event(), None, vec![], "detail".to_string());
        assert_eq!(f.risk_score.0, 30);
        assert_eq!(f.risk_level, RiskLevel::Medium);
        assert!(f.signature_id.is_none());
        assert!(f.service_name.is_none());
    }

    #[test]
    fn uses_signature_risk_base() {
        let sig = make_sig("openai", 65);
        let f = Finding::new(make_event(), Some(&sig), vec![], "detail".to_string());
        assert_eq!(f.risk_score.0, 65);
        assert_eq!(f.risk_level, RiskLevel::High);
        assert_eq!(f.signature_id.as_deref(), Some("openai"));
        assert_eq!(f.service_name.as_deref(), Some("openai Service"));
    }

    #[test]
    fn critical_dlp_doubles_score() {
        let sig = make_sig("openai", 40);
        let dlp = vec![DlpMatch {
            pattern_id: "openai_key".to_string(),
            description: "key found".to_string(),
            severity: DlpSeverity::Critical,
        }];
        let f = Finding::new(make_event(), Some(&sig), dlp, "detail".to_string());
        // 40 * 2.0 = 80
        assert_eq!(f.risk_score.0, 80);
        assert_eq!(f.risk_level, RiskLevel::Critical);
    }

    #[test]
    fn high_dlp_multiplies_score_by_1_5() {
        let sig = make_sig("openai", 40);
        let dlp = vec![DlpMatch {
            pattern_id: "openai_org_id".to_string(),
            description: "org id found".to_string(),
            severity: DlpSeverity::High,
        }];
        let f = Finding::new(make_event(), Some(&sig), dlp, "detail".to_string());
        // 40 * 1.5 = 60
        assert_eq!(f.risk_score.0, 60);
        assert_eq!(f.risk_level, RiskLevel::High);
    }

    #[test]
    fn each_finding_has_unique_id() {
        let f1 = Finding::new(make_event(), None, vec![], "a".to_string());
        let f2 = Finding::new(make_event(), None, vec![], "b".to_string());
        assert_ne!(f1.id, f2.id);
    }

    #[test]
    fn detail_is_preserved() {
        let f = Finding::new(make_event(), None, vec![], "my detail".to_string());
        assert_eq!(f.detail, "my detail");
    }
}

impl Finding {
    pub fn new(
        event: Event,
        signature: Option<&Signature>,
        dlp_matches: Vec<DlpMatch>,
        detail: String,
    ) -> Self {
        let base = signature.map(|s| s.risk_base).unwrap_or(30);
        let has_critical = dlp_matches
            .iter()
            .any(|d| d.severity == DlpSeverity::Critical);
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
