use serde::{Deserialize, Serialize};

use crate::error::ConanError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PolicyAction {
    Allow,
    Warn,
    Block,
}

impl std::fmt::Display for PolicyAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyAction::Allow => write!(f, "ALLOWED"),
            PolicyAction::Warn => write!(f, "WARN"),
            PolicyAction::Block => write!(f, "BLOCKED"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyTrigger {
    AiDetected,
    DlpMatch,
    Any,
}

/// A single rule in a policy file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub description: Option<String>,
    pub trigger: PolicyTrigger,
    /// Signature IDs that are excluded from this rule (approved list).
    #[serde(default)]
    pub exclude_ids: Vec<String>,
    /// Only match signatures with these tags.
    #[serde(default)]
    pub tags: Vec<String>,
    pub action: PolicyAction,
    #[serde(default)]
    pub notify: Vec<String>,
    /// Only fire this rule if the computed risk score is at or above this value.
    pub min_score: Option<u8>,
    /// When this rule matches, override the finding's risk score with this value.
    pub score_override: Option<u8>,
}

/// Global score-based thresholds applied when no rule matches.
/// Processed in order: block is checked before warn.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PolicyThresholds {
    /// Auto-block any finding whose risk score is >= this value.
    pub block: Option<u8>,
    /// Auto-warn any finding whose risk score is >= this value.
    pub warn: Option<u8>,
}

/// Notification channel configs.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NotificationConfig {
    pub webhook_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Notifications {
    pub slack: Option<NotificationConfig>,
    pub discord: Option<NotificationConfig>,
}

/// The top-level policy file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub version: String,
    /// Default action when no rule and no threshold matches.
    pub mode: PolicyAction,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub notifications: Notifications,
    /// Score-based thresholds evaluated after rules, before falling back to `mode`.
    #[serde(default)]
    pub thresholds: PolicyThresholds,
}

impl Policy {
    pub fn load(path: &std::path::Path) -> Result<Self, ConanError> {
        let content = std::fs::read_to_string(path).map_err(ConanError::Io)?;
        toml::from_str(&content).map_err(|e| ConanError::PolicyParse(e.to_string()))
    }

    /// Evaluate the policy for a finding.
    ///
    /// Returns `(action, matched_rule_id, score_override)`:
    /// - `action` — what to do with this finding
    /// - `matched_rule_id` — the first rule that matched, if any
    /// - `score_override` — if the matched rule carries `score_override`, the
    ///   caller should replace the finding's risk score with this value
    pub fn evaluate(
        &self,
        signature_id: &str,
        tags: &[String],
        has_dlp: bool,
        score: u8,
    ) -> (PolicyAction, Option<String>, Option<u8>) {
        for rule in &self.rules {
            // Trigger check
            let trigger_matches = match rule.trigger {
                PolicyTrigger::AiDetected => true,
                PolicyTrigger::DlpMatch => has_dlp,
                PolicyTrigger::Any => true,
            };
            if !trigger_matches {
                continue;
            }
            // Score threshold: skip rule if the score doesn't meet the minimum
            if let Some(min) = rule.min_score {
                if score < min {
                    continue;
                }
            }
            // Exclusion list
            if rule.exclude_ids.iter().any(|id| id == signature_id) {
                continue;
            }
            // Tag filter
            if !rule.tags.is_empty() && !rule.tags.iter().any(|t| tags.contains(t)) {
                continue;
            }
            return (
                rule.action.clone(),
                Some(rule.id.clone()),
                rule.score_override,
            );
        }

        // No rule matched — check global score thresholds
        if let Some(block_at) = self.thresholds.block {
            if score >= block_at {
                return (PolicyAction::Block, None, None);
            }
        }
        if let Some(warn_at) = self.thresholds.warn {
            if score >= warn_at {
                return (PolicyAction::Warn, None, None);
            }
        }

        (self.mode.clone(), None, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(
        id: &str,
        trigger: PolicyTrigger,
        action: PolicyAction,
        exclude_ids: &[&str],
        tags: &[&str],
    ) -> PolicyRule {
        PolicyRule {
            id: id.to_string(),
            description: None,
            trigger,
            exclude_ids: exclude_ids.iter().map(|s| s.to_string()).collect(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            action,
            notify: vec![],
            min_score: None,
            score_override: None,
        }
    }

    fn policy(mode: PolicyAction, rules: Vec<PolicyRule>) -> Policy {
        Policy {
            version: "1.0".to_string(),
            mode,
            rules,
            notifications: Notifications::default(),
            thresholds: PolicyThresholds::default(),
        }
    }

    #[test]
    fn default_policy_warns_with_no_rules() {
        let p = Policy::default();
        let (action, rule_id, override_score) = p.evaluate("openai", &[], false, 50);
        assert_eq!(action, PolicyAction::Warn);
        assert!(rule_id.is_none());
        assert!(override_score.is_none());
    }

    #[test]
    fn first_matching_rule_wins() {
        let p = policy(
            PolicyAction::Warn,
            vec![
                rule(
                    "block",
                    PolicyTrigger::AiDetected,
                    PolicyAction::Block,
                    &[],
                    &[],
                ),
                rule(
                    "warn",
                    PolicyTrigger::AiDetected,
                    PolicyAction::Warn,
                    &[],
                    &[],
                ),
            ],
        );
        let (action, id, _) = p.evaluate("openai", &[], false, 50);
        assert_eq!(action, PolicyAction::Block);
        assert_eq!(id.as_deref(), Some("block"));
    }

    #[test]
    fn exclude_ids_skips_matching_rule() {
        let p = policy(
            PolicyAction::Warn,
            vec![rule(
                "block-unapproved",
                PolicyTrigger::AiDetected,
                PolicyAction::Block,
                &["openai"],
                &[],
            )],
        );
        let (action, _, _) = p.evaluate("openai", &[], false, 50);
        assert_eq!(action, PolicyAction::Warn);

        let (action, _, _) = p.evaluate("anthropic", &[], false, 50);
        assert_eq!(action, PolicyAction::Block);
    }

    #[test]
    fn tag_filter_only_matches_tagged_signatures() {
        let p = policy(
            PolicyAction::Warn,
            vec![rule(
                "allow-local",
                PolicyTrigger::AiDetected,
                PolicyAction::Allow,
                &[],
                &["local"],
            )],
        );
        let (action, _, _) = p.evaluate("ollama", &["local".to_string()], false, 50);
        assert_eq!(action, PolicyAction::Allow);

        let (action, _, _) = p.evaluate("openai", &["cloud".to_string()], false, 50);
        assert_eq!(action, PolicyAction::Warn);
    }

    #[test]
    fn dlp_trigger_skipped_without_dlp() {
        let p = policy(
            PolicyAction::Warn,
            vec![rule(
                "block-dlp",
                PolicyTrigger::DlpMatch,
                PolicyAction::Block,
                &[],
                &[],
            )],
        );
        let (action, _, _) = p.evaluate("openai", &[], false, 50);
        assert_eq!(action, PolicyAction::Warn);

        let (action, _, _) = p.evaluate("openai", &[], true, 50);
        assert_eq!(action, PolicyAction::Block);
    }

    #[test]
    fn any_trigger_always_fires() {
        let p = policy(
            PolicyAction::Warn,
            vec![rule(
                "catch-all",
                PolicyTrigger::Any,
                PolicyAction::Allow,
                &[],
                &[],
            )],
        );
        let (action, _, _) = p.evaluate("anything", &[], false, 50);
        assert_eq!(action, PolicyAction::Allow);
    }

    #[test]
    fn policy_action_display() {
        assert_eq!(PolicyAction::Allow.to_string(), "ALLOWED");
        assert_eq!(PolicyAction::Warn.to_string(), "WARN");
        assert_eq!(PolicyAction::Block.to_string(), "BLOCKED");
    }

    #[test]
    fn load_from_valid_toml_file() {
        let dir = tempfile::tempdir().unwrap();
        let toml = r#"
version = "1.0"
mode = "warn"

[[rules]]
id = "test-rule"
trigger = "ai_detected"
action = "block"
"#;
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, toml).unwrap();
        let p = Policy::load(&path).unwrap();
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].id, "test-rule");
        assert_eq!(p.rules[0].action, PolicyAction::Block);
    }

    // ── min_score ─────────────────────────────────────────────────────────────

    #[test]
    fn min_score_skips_rule_when_score_below() {
        let mut r = rule(
            "block-critical",
            PolicyTrigger::Any,
            PolicyAction::Block,
            &[],
            &[],
        );
        r.min_score = Some(76);
        let p = policy(PolicyAction::Warn, vec![r]);
        // score 50 < 76 → rule skipped → default warn
        let (action, rule_id, _) = p.evaluate("openai", &[], false, 50);
        assert_eq!(action, PolicyAction::Warn);
        assert!(rule_id.is_none());
    }

    #[test]
    fn min_score_fires_rule_when_score_meets_threshold() {
        let mut r = rule(
            "block-critical",
            PolicyTrigger::Any,
            PolicyAction::Block,
            &[],
            &[],
        );
        r.min_score = Some(76);
        let p = policy(PolicyAction::Warn, vec![r]);
        // score 76 == 76 → rule fires
        let (action, rule_id, _) = p.evaluate("openai", &[], false, 76);
        assert_eq!(action, PolicyAction::Block);
        assert_eq!(rule_id.as_deref(), Some("block-critical"));
    }

    #[test]
    fn min_score_fires_rule_when_score_above_threshold() {
        let mut r = rule(
            "block-critical",
            PolicyTrigger::Any,
            PolicyAction::Block,
            &[],
            &[],
        );
        r.min_score = Some(76);
        let p = policy(PolicyAction::Warn, vec![r]);
        let (action, _, _) = p.evaluate("openai", &[], false, 95);
        assert_eq!(action, PolicyAction::Block);
    }

    // ── score_override ────────────────────────────────────────────────────────

    #[test]
    fn score_override_returned_when_rule_matches() {
        let mut r = rule(
            "escalate",
            PolicyTrigger::AiDetected,
            PolicyAction::Warn,
            &[],
            &[],
        );
        r.score_override = Some(90);
        let p = policy(PolicyAction::Warn, vec![r]);
        let (_, _, override_score) = p.evaluate("openai", &[], false, 40);
        assert_eq!(override_score, Some(90));
    }

    #[test]
    fn no_score_override_when_rule_has_none() {
        let p = policy(
            PolicyAction::Warn,
            vec![rule(
                "plain",
                PolicyTrigger::AiDetected,
                PolicyAction::Warn,
                &[],
                &[],
            )],
        );
        let (_, _, override_score) = p.evaluate("openai", &[], false, 40);
        assert!(override_score.is_none());
    }

    #[test]
    fn score_override_not_returned_when_rule_does_not_match() {
        let mut r = rule(
            "block",
            PolicyTrigger::DlpMatch,
            PolicyAction::Block,
            &[],
            &[],
        );
        r.score_override = Some(99);
        let p = policy(PolicyAction::Warn, vec![r]);
        // no DLP → rule skipped → no override
        let (_, _, override_score) = p.evaluate("openai", &[], false, 40);
        assert!(override_score.is_none());
    }

    // ── thresholds ────────────────────────────────────────────────────────────

    #[test]
    fn threshold_block_fires_when_no_rule_matches_and_score_high() {
        let mut p = policy(PolicyAction::Allow, vec![]);
        p.thresholds.block = Some(80);
        let (action, rule_id, _) = p.evaluate("openai", &[], false, 85);
        assert_eq!(action, PolicyAction::Block);
        assert!(rule_id.is_none());
    }

    #[test]
    fn threshold_block_not_fired_when_score_below() {
        let mut p = policy(PolicyAction::Allow, vec![]);
        p.thresholds.block = Some(80);
        let (action, _, _) = p.evaluate("openai", &[], false, 79);
        assert_eq!(action, PolicyAction::Allow); // falls through to mode
    }

    #[test]
    fn threshold_warn_fires_before_mode() {
        let mut p = policy(PolicyAction::Allow, vec![]);
        p.thresholds.warn = Some(50);
        let (action, _, _) = p.evaluate("openai", &[], false, 60);
        assert_eq!(action, PolicyAction::Warn);
    }

    #[test]
    fn threshold_block_takes_priority_over_warn() {
        let mut p = policy(PolicyAction::Allow, vec![]);
        p.thresholds.block = Some(80);
        p.thresholds.warn = Some(50);
        // score 85 hits both → block wins
        let (action, _, _) = p.evaluate("openai", &[], false, 85);
        assert_eq!(action, PolicyAction::Block);
    }

    #[test]
    fn rule_takes_priority_over_threshold() {
        let mut p = policy(
            PolicyAction::Allow,
            vec![rule(
                "allow-it",
                PolicyTrigger::AiDetected,
                PolicyAction::Allow,
                &[],
                &[],
            )],
        );
        p.thresholds.block = Some(50); // would block at score 60
                                       // rule fires first → allow, threshold not evaluated
        let (action, rule_id, _) = p.evaluate("openai", &[], false, 60);
        assert_eq!(action, PolicyAction::Allow);
        assert_eq!(rule_id.as_deref(), Some("allow-it"));
    }

    #[test]
    fn load_score_fields_from_toml() {
        let dir = tempfile::tempdir().unwrap();
        let toml = r#"
version = "1.0"
mode = "warn"

[thresholds]
block = 90
warn = 60

[[rules]]
id = "block-critical-score"
trigger = "any"
min_score = 76
score_override = 95
action = "block"
"#;
        let path = dir.path().join("policy.toml");
        std::fs::write(&path, toml).unwrap();
        let p = Policy::load(&path).unwrap();
        assert_eq!(p.thresholds.block, Some(90));
        assert_eq!(p.thresholds.warn, Some(60));
        assert_eq!(p.rules[0].min_score, Some(76));
        assert_eq!(p.rules[0].score_override, Some(95));
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            mode: PolicyAction::Warn,
            rules: vec![],
            notifications: Notifications::default(),
            thresholds: PolicyThresholds::default(),
        }
    }
}
