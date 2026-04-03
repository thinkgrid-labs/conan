use async_trait::async_trait;
use conan_core::{
    error::ConanError,
    event::{Event, EventPayload, Source},
    registry::Registry,
    traits::Ingestor,
};
use sysinfo::System;
use tracing::debug;

pub struct ProcessIngestor {
    pub registry: Registry,
}

impl ProcessIngestor {
    pub fn new(registry: Registry) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl Ingestor for ProcessIngestor {
    fn name(&self) -> &'static str {
        "process"
    }

    async fn ingest(&self) -> Result<Vec<Event>, ConanError> {
        let mut sys = System::new_all();
        sys.refresh_all();

        let mut events = vec![];

        for (pid, process) in sys.processes() {
            let name = process.name().to_string();
            let cmdline = process
                .cmd()
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(" ");

            let matches = self.registry.match_process(&name);
            if !matches.is_empty() {
                debug!(pid = %pid, name = %name, "matched AI process");
                let payload = EventPayload::Process {
                    pid: pid.as_u32(),
                    name: name.clone(),
                    cmdline: cmdline.clone(),
                    exe_path: process.exe().map(|p| p.display().to_string()),
                };
                events.push(Event::new(Source::Process, payload));
            }
        }

        Ok(events)
    }
}
