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
#[derive(Debug, Default, Clone)]
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
                let content = match std::fs::read_to_string(&path) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(path = %path.display(), "failed to read signature file: {e}");
                        continue;
                    }
                };
                match serde_yaml::from_str::<Signature>(&content) {
                    Ok(sig) => {
                        registry.insert(sig);
                    }
                    Err(e) => {
                        tracing::warn!(path = %path.display(), "invalid signature YAML, skipping: {e}");
                    }
                }
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
            .filter(|s| {
                s.domains
                    .iter()
                    .any(|d| host == d || host.ends_with(&format!(".{d}")))
            })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sig(id: &str, domains: &[&str], processes: &[&str]) -> Signature {
        Signature {
            id: id.to_string(),
            name: id.to_string(),
            version: "1.0.0".to_string(),
            risk_base: 50,
            domains: domains.iter().map(|s| s.to_string()).collect(),
            ip_ranges: vec![],
            process_names: processes.iter().map(|s| s.to_string()).collect(),
            dlp_patterns: vec![],
            http_patterns: HttpPatterns::default(),
            tags: vec![],
            privacy_policy_url: None,
        }
    }

    #[test]
    fn insert_and_get() {
        let mut reg = Registry::new();
        reg.insert(make_sig("openai", &["api.openai.com"], &["openai"]));
        assert!(reg.get("openai").is_some());
        assert!(reg.get("anthropic").is_none());
        assert_eq!(reg.len(), 1);
        assert!(!reg.is_empty());
    }

    #[test]
    fn match_domain_exact() {
        let mut reg = Registry::new();
        reg.insert(make_sig("openai", &["api.openai.com"], &[]));
        let m = reg.match_domain("api.openai.com");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].id, "openai");
    }

    #[test]
    fn match_domain_subdomain() {
        let mut reg = Registry::new();
        reg.insert(make_sig("openai", &["openai.com"], &[]));
        // api.openai.com ends_with(".openai.com") → should match
        assert_eq!(reg.match_domain("api.openai.com").len(), 1);
    }

    #[test]
    fn match_domain_no_match() {
        let mut reg = Registry::new();
        reg.insert(make_sig("openai", &["api.openai.com"], &[]));
        assert!(reg.match_domain("anthropic.com").is_empty());
    }

    #[test]
    fn match_domain_does_not_match_partial_prefix() {
        // "evil-openai.com" must NOT match "openai.com"
        let mut reg = Registry::new();
        reg.insert(make_sig("openai", &["openai.com"], &[]));
        assert!(reg.match_domain("evil-openai.com").is_empty());
    }

    #[test]
    fn match_process_exact() {
        let mut reg = Registry::new();
        reg.insert(make_sig("ollama", &[], &["ollama"]));
        assert_eq!(reg.match_process("ollama").len(), 1);
    }

    #[test]
    fn match_process_no_match() {
        let mut reg = Registry::new();
        reg.insert(make_sig("ollama", &[], &["ollama"]));
        assert!(reg.match_process("nginx").is_empty());
    }

    #[test]
    fn nonexistent_dir_returns_empty_registry() {
        let reg = Registry::load_from_dir(std::path::Path::new("/no/such/path")).unwrap();
        assert!(reg.is_empty());
    }

    #[test]
    fn load_from_dir_parses_yaml_file() {
        use std::io::Write;
        let dir = tempfile::tempdir().unwrap();
        let yaml = r#"
id: test-svc
name: Test Service
version: "1.0.0"
risk_base: 42
domains:
  - test.example.com
process_names:
  - test-cli
tags: [test]
"#;
        let mut f = std::fs::File::create(dir.path().join("test-svc.yaml")).unwrap();
        f.write_all(yaml.as_bytes()).unwrap();

        let reg = Registry::load_from_dir(dir.path()).unwrap();
        assert_eq!(reg.len(), 1);
        let sig = reg.get("test-svc").unwrap();
        assert_eq!(sig.risk_base, 42);
        assert_eq!(sig.domains[0], "test.example.com");
    }

    #[test]
    fn load_from_dir_ignores_non_yaml_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("readme.txt"), "not a signature").unwrap();
        let reg = Registry::load_from_dir(dir.path()).unwrap();
        assert!(reg.is_empty());
    }
}
