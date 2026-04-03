use async_trait::async_trait;

use crate::{
    error::ConanError,
    event::Event,
    finding::Finding,
    policy::Policy,
    registry::Registry,
};

/// Context passed to every ingestor during a scan.
pub struct ScanContext {
    pub registry: Registry,
    pub policy: Policy,
}

/// Collects raw events from a data source.
#[async_trait]
pub trait Ingestor: Send + Sync {
    fn name(&self) -> &'static str;
    async fn ingest(&self) -> Result<Vec<Event>, ConanError>;
}

/// Analyzes events against the registry and produces findings.
#[async_trait]
pub trait Analyzer: Send + Sync {
    async fn analyze(&self, events: Vec<Event>, ctx: &ScanContext) -> Vec<Finding>;
}

/// Formats and outputs findings.
pub trait Reporter: Send + Sync {
    fn report(&self, findings: &[Finding]) -> String;
}
