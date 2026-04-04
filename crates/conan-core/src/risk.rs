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
    pub fn calculate(
        base: u8,
        has_dlp_critical: bool,
        has_dlp_high: bool,
        is_unapproved: bool,
    ) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_bands_boundaries() {
        assert_eq!(RiskScore(0).level(), RiskLevel::Low);
        assert_eq!(RiskScore(25).level(), RiskLevel::Low);
        assert_eq!(RiskScore(26).level(), RiskLevel::Medium);
        assert_eq!(RiskScore(50).level(), RiskLevel::Medium);
        assert_eq!(RiskScore(51).level(), RiskLevel::High);
        assert_eq!(RiskScore(75).level(), RiskLevel::High);
        assert_eq!(RiskScore(76).level(), RiskLevel::Critical);
        assert_eq!(RiskScore(100).level(), RiskLevel::Critical);
    }

    #[test]
    fn calculate_base_only() {
        assert_eq!(RiskScore::calculate(40, false, false, false).0, 40);
    }

    #[test]
    fn calculate_dlp_critical_doubles_score() {
        // 40 * 2.0 = 80
        assert_eq!(RiskScore::calculate(40, true, false, false).0, 80);
    }

    #[test]
    fn calculate_dlp_high_multiplies_by_1_5() {
        // 40 * 1.5 = 60
        assert_eq!(RiskScore::calculate(40, false, true, false).0, 60);
    }

    #[test]
    fn calculate_unapproved_multiplies_by_1_5() {
        // 40 * 1.5 = 60
        assert_eq!(RiskScore::calculate(40, false, false, true).0, 60);
    }

    #[test]
    fn calculate_stacks_unapproved_and_dlp_high() {
        // 40 * 1.5 (unapproved) * 1.5 (dlp_high) = 90
        assert_eq!(RiskScore::calculate(40, false, true, true).0, 90);
    }

    #[test]
    fn calculate_caps_at_100() {
        // 80 * 1.5 * 2.0 = 240 → capped at 100
        assert_eq!(RiskScore::calculate(80, true, false, true).0, 100);
    }

    #[test]
    fn dlp_critical_takes_priority_over_high() {
        // Both set: only critical (2x) should apply, not high (1.5x)
        assert_eq!(
            RiskScore::calculate(40, true, true, false).0,
            RiskScore::calculate(40, true, false, false).0
        );
    }

    #[test]
    fn risk_level_display() {
        assert_eq!(RiskLevel::Low.to_string(), "LOW");
        assert_eq!(RiskLevel::Medium.to_string(), "MEDIUM");
        assert_eq!(RiskLevel::High.to_string(), "HIGH");
        assert_eq!(RiskLevel::Critical.to_string(), "CRITICAL");
    }
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
