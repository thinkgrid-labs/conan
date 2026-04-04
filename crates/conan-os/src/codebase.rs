use async_trait::async_trait;
use conan_core::{
    error::ConanError,
    event::{Event, EventPayload, Source},
    registry::Registry,
    traits::Ingestor,
};
use regex::Regex;
use std::path::PathBuf;
use tracing::debug;
use walkdir::WalkDir;

/// Patterns for common secrets and AI SDK imports.
static DLP_PATTERNS: &[(&str, &str)] = &[
    ("openai_key", r"sk-[A-Za-z0-9]{20,}"),
    ("anthropic_key", r"sk-ant-[A-Za-z0-9\-_]{20,}"),
    ("google_ai_key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("huggingface_key", r"hf_[A-Za-z0-9]{20,}"),
    (
        "generic_api_key",
        r#"(?i)(api[_\-]?key|secret)["\s]*[:=]["\s]*[A-Za-z0-9\-_]{16,}"#,
    ),
];

/// Extensions to scan.
static SCAN_EXTENSIONS: &[&str] = &[
    "js", "ts", "jsx", "tsx", "py", "rb", "go", "rs", "java", "kt", "php", "cs", "env", "toml",
    "yaml", "yml", "json",
];

pub struct CodebaseIngestor {
    pub registry: Registry,
    pub root: PathBuf,
    compiled_patterns: Vec<(String, Regex)>,
}

impl CodebaseIngestor {
    pub fn new(registry: Registry, root: PathBuf) -> Self {
        let compiled_patterns = DLP_PATTERNS
            .iter()
            .filter_map(|(id, pat)| Regex::new(pat).ok().map(|r| (id.to_string(), r)))
            .collect();

        Self {
            registry,
            root,
            compiled_patterns,
        }
    }
}

#[async_trait]
impl Ingestor for CodebaseIngestor {
    fn name(&self) -> &'static str {
        "codebase"
    }

    async fn ingest(&self) -> Result<Vec<Event>, ConanError> {
        let mut events = vec![];

        for entry in WalkDir::new(&self.root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();

            // Skip hidden dirs and known noise dirs relative to the scan root.
            // We strip the root prefix so that absolute path components above
            // the root (e.g. the OS temp dir which starts with ".tmp") do not
            // accidentally cause every file to be skipped.
            let rel = path.strip_prefix(&self.root).unwrap_or(path);
            if rel.components().any(|c| {
                let s = c.as_os_str().to_string_lossy();
                s.starts_with('.') || s == "node_modules" || s == "target" || s == "dist"
            }) {
                continue;
            }

            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !SCAN_EXTENSIONS.contains(&ext) {
                continue;
            }

            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for (line_num, line) in content.lines().enumerate() {
                for (pattern_id, regex) in &self.compiled_patterns {
                    if regex.is_match(line) {
                        debug!(file = %path.display(), line = line_num + 1, pattern = %pattern_id, "DLP match in codebase");
                        events.push(Event::new(
                            Source::Codebase,
                            EventPayload::CodebaseFile {
                                file_path: path.to_string_lossy().to_string(),
                                line_number: Some((line_num + 1) as u32),
                                matched_text: pattern_id.clone(),
                            },
                        ));
                        break; // one event per line
                    }
                }
            }
        }

        Ok(events)
    }
}
