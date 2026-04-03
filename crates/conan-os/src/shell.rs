use async_trait::async_trait;
use conan_core::{
    error::ConanError,
    event::{Event, EventPayload, Source},
    registry::Registry,
    traits::Ingestor,
};
use std::path::PathBuf;
use tracing::debug;

pub struct ShellHistoryIngestor {
    pub registry: Registry,
    pub history_files: Vec<(PathBuf, String)>, // (path, shell_name)
}

impl ShellHistoryIngestor {
    pub fn new(registry: Registry) -> Self {
        let home = dirs::home_dir().unwrap_or_default();
        let history_files = vec![
            (home.join(".bash_history"), "bash".to_string()),
            (home.join(".zsh_history"), "zsh".to_string()),
            (home.join(".local/share/fish/fish_history"), "fish".to_string()),
        ]
        .into_iter()
        .filter(|(p, _)| p.exists())
        .collect();

        Self { registry, history_files }
    }
}

#[async_trait]
impl Ingestor for ShellHistoryIngestor {
    fn name(&self) -> &'static str {
        "shell"
    }

    async fn ingest(&self) -> Result<Vec<Event>, ConanError> {
        let mut events = vec![];

        // Collect all process names from registry for matching
        let known_names: Vec<String> = self
            .registry
            .all()
            .flat_map(|s| s.process_names.iter().cloned())
            .collect();

        for (path, shell) in &self.history_files {
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for line in content.lines() {
                // Strip zsh extended history prefix: `: timestamp:elapsed;command`
                let command = if line.starts_with(": ") {
                    line.split(';').nth(1).unwrap_or(line)
                } else {
                    line
                };

                let command = command.trim();
                if command.is_empty() {
                    continue;
                }

                let matched = known_names.iter().any(|name| {
                    command.split_whitespace().next().map(|cmd| {
                        // Match on the base binary name
                        let bin = cmd.rsplit('/').next().unwrap_or(cmd);
                        bin == name || bin.starts_with(name)
                    }).unwrap_or(false)
                });

                if matched {
                    debug!(shell = %shell, command = %command, "matched AI command in shell history");
                    events.push(Event::new(
                        Source::ShellHistory,
                        EventPayload::ShellHistory {
                            command: command.to_string(),
                            shell: shell.clone(),
                            history_file: path.to_string_lossy().to_string(),
                        },
                    ));
                }
            }
        }

        Ok(events)
    }
}
