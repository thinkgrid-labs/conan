use serde::{Deserialize, Serialize};

/// A 0–100 risk score.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct RiskScore(pub u8);

impl RiskScore {
    pub fn level(&self) -> RiskLevel {
        match self.0 {
            0..=25 => RiskLevel::Low,
            26..=50 => RiskLevel::Medium,
            51..=75 => RiskLevel::High,
            _ => RiskLevel::Critical,
        }
    }

    /// Combine base score with DLP and policy multipliers.
    pub fn calculate(base: u8, has_dlp_critical: bool, has_dlp_high: bool, is_unapproved: bool) -> Self {
        let mut score = base as f32;
        if is_unapproved {
            score *= 1.5;
        }
        if has_dlp_critical {
            score *= 2.0;
        } else if has_dlp_high {
            score *= 1.5;
        }
        RiskScore(score.min(100.0) as u8)
    }
}

/// Human-readable risk band derived from RiskScore.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}
