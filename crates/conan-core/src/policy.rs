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
    /// Default mode if no rule matches.
    pub mode: PolicyAction,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub notifications: Notifications,
}

impl Policy {
    pub fn load(path: &std::path::Path) -> Result<Self, ConanError> {
        let content = std::fs::read_to_string(path).map_err(ConanError::Io)?;
        toml::from_str(&content).map_err(|e| ConanError::PolicyParse(e.to_string()))
    }

    /// Evaluate the policy for a detected signature id and tags.
    /// Returns the matching action and which rule matched (if any).
    pub fn evaluate(
        &self,
        signature_id: &str,
        tags: &[String],
        has_dlp: bool,
    ) -> (PolicyAction, Option<String>) {
        for rule in &self.rules {
            let trigger_matches = match rule.trigger {
                PolicyTrigger::AiDetected => true,
                PolicyTrigger::DlpMatch => has_dlp,
                PolicyTrigger::Any => true,
            };
            if !trigger_matches {
                continue;
            }
            if rule.exclude_ids.iter().any(|id| id == signature_id) {
                continue;
            }
            if !rule.tags.is_empty() && !rule.tags.iter().any(|t| tags.contains(t)) {
                continue;
            }
            return (rule.action.clone(), Some(rule.id.clone()));
        }
        (self.mode.clone(), None)
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
        }
    }

    fn policy(mode: PolicyAction, rules: Vec<PolicyRule>) -> Policy {
        Policy {
            version: "1.0".to_string(),
            mode,
            rules,
            notifications: Notifications::default(),
        }
    }

    #[test]
    fn default_policy_warns_with_no_rules() {
        let p = Policy::default();
        let (action, rule_id) = p.evaluate("openai", &[], false);
        assert_eq!(action, PolicyAction::Warn);
        assert!(rule_id.is_none());
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
        let (action, id) = p.evaluate("openai", &[], false);
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
        // excluded → falls through to default warn
        let (action, _) = p.evaluate("openai", &[], false);
        assert_eq!(action, PolicyAction::Warn);

        // not excluded → gets blocked
        let (action, _) = p.evaluate("anthropic", &[], false);
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
        let (action, _) = p.evaluate("ollama", &["local".to_string()], false);
        assert_eq!(action, PolicyAction::Allow);

        let (action, _) = p.evaluate("openai", &["cloud".to_string()], false);
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
        // no DLP → rule skipped, default warn
        let (action, _) = p.evaluate("openai", &[], false);
        assert_eq!(action, PolicyAction::Warn);

        // has DLP → rule fires
        let (action, _) = p.evaluate("openai", &[], true);
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
        let (action, _) = p.evaluate("anything", &[], false);
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
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            version: "1.0".to_string(),
            mode: PolicyAction::Warn,
            rules: vec![],
            notifications: Notifications::default(),
        }
    }
}
