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
