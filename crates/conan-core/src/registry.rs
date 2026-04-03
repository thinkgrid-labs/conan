use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::ConanError;

/// A single DLP pattern defined in a signature file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DlpPattern {
    pub id: String,
    pub pattern: String,
    pub severity: String,
}

/// HTTP-level fingerprints for an AI service.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HttpPatterns {
    #[serde(default)]
    pub user_agents: Vec<String>,
}

/// A signature describing a known AI service.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub id: String,
    pub name: String,
    pub version: String,
    /// 0–100 baseline risk before multipliers.
    pub risk_base: u8,
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub ip_ranges: Vec<String>,
    #[serde(default)]
    pub process_names: Vec<String>,
    #[serde(default)]
    pub dlp_patterns: Vec<DlpPattern>,
    #[serde(default)]
    pub http_patterns: HttpPatterns,
    #[serde(default)]
    pub tags: Vec<String>,
    pub privacy_policy_url: Option<String>,
}

/// In-memory registry of all loaded signatures.
#[derive(Debug, Default)]
pub struct Registry {
    signatures: HashMap<String, Signature>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn load_from_dir(dir: &std::path::Path) -> Result<Self, ConanError> {
        let mut registry = Self::new();

        if !dir.exists() {
            return Ok(registry);
        }

        for entry in std::fs::read_dir(dir).map_err(ConanError::Io)? {
            let entry = entry.map_err(ConanError::Io)?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
                let content = std::fs::read_to_string(&path).map_err(ConanError::Io)?;
                let sig: Signature = serde_yaml::from_str(&content)
                    .map_err(|e| ConanError::SignatureParse(e.to_string()))?;
                registry.insert(sig);
            }
        }

        Ok(registry)
    }

    pub fn insert(&mut self, sig: Signature) {
        self.signatures.insert(sig.id.clone(), sig);
    }

    pub fn get(&self, id: &str) -> Option<&Signature> {
        self.signatures.get(id)
    }

    pub fn all(&self) -> impl Iterator<Item = &Signature> {
        self.signatures.values()
    }

    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }

    /// Find signatures whose domains match the given hostname.
    pub fn match_domain(&self, host: &str) -> Vec<&Signature> {
        self.signatures
            .values()
            .filter(|s| s.domains.iter().any(|d| host == d || host.ends_with(&format!(".{d}"))))
            .collect()
    }

    /// Find signatures whose process names match.
    pub fn match_process(&self, name: &str) -> Vec<&Signature> {
        self.signatures
            .values()
            .filter(|s| s.process_names.iter().any(|p| name.contains(p.as_str())))
            .collect()
    }
}
