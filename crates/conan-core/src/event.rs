use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Where the event originated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Network,
    Process,
    BrowserHistory,
    ShellHistory,
    Codebase,
    CloudLog,
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::Network => write!(f, "net"),
            Source::Process => write!(f, "process"),
            Source::BrowserHistory => write!(f, "browser"),
            Source::ShellHistory => write!(f, "shell"),
            Source::Codebase => write!(f, "codebase"),
            Source::CloudLog => write!(f, "cloud"),
        }
    }
}

/// The data payload carried by an event, varies by source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventPayload {
    /// A network connection or HTTP request to an AI endpoint.
    NetworkConnection {
        remote_host: String,
        remote_ip: Option<String>,
        port: u16,
        protocol: String,
        http_headers: Option<serde_json::Value>,
        body_snippet: Option<String>,
    },
    /// A running process that matches an AI tool.
    Process {
        pid: u32,
        name: String,
        cmdline: String,
        exe_path: Option<String>,
    },
    /// A browser history entry pointing to an AI service.
    BrowserHistory {
        url: String,
        title: Option<String>,
        browser: String,
    },
    /// A shell history line invoking an AI CLI.
    ShellHistory {
        command: String,
        shell: String,
        history_file: String,
    },
    /// A file in a codebase containing a suspicious pattern.
    CodebaseFile {
        file_path: String,
        line_number: Option<u32>,
        matched_text: String,
    },
}

/// A raw observation collected by an ingestor before analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: uuid::Uuid,
    pub source: Source,
    pub timestamp: DateTime<Utc>,
    pub payload: EventPayload,
}

impl Event {
    pub fn new(source: Source, payload: EventPayload) -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            source,
            timestamp: Utc::now(),
            payload,
        }
    }
}
