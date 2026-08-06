//! Alarming. A provider's stake depends on this process doing its job, so "log and
//! carry on" is never the answer when the job can't be done — every unmeetable
//! obligation must reach a human. The sink is a trait so tests can assert that the
//! right alarms fire (and production can wire pagers) without touching daemon logic.

use std::sync::Mutex;

/// How bad it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Something is degraded but the daemon is still meeting its obligations
    /// (e.g. a primary blob source is down and a fallback answered).
    Warning,
    /// An obligation is at risk or the store cannot advance (e.g. every blob source
    /// exhausted, or local state disagrees with L1). Requires human attention NOW.
    Critical,
}

pub trait AlarmSink: Send + Sync {
    fn alarm(&self, severity: Severity, message: &str);
}

/// Production sink: structured logs. Operators are expected to route `ERROR`-level
/// records from the `alarm` target to their pager.
pub struct LogAlarm;

impl AlarmSink for LogAlarm {
    fn alarm(&self, severity: Severity, message: &str) {
        match severity {
            Severity::Warning => tracing::warn!(target: "alarm", "{message}"),
            Severity::Critical => tracing::error!(target: "alarm", "{message}"),
        }
    }
}

/// Test sink: records every alarm so behavior tests can assert on them.
#[derive(Default)]
pub struct CapturingAlarm {
    entries: Mutex<Vec<(Severity, String)>>,
}

impl CapturingAlarm {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> Vec<(Severity, String)> {
        self.entries.lock().unwrap().clone()
    }

    pub fn criticals(&self) -> Vec<String> {
        self.entries()
            .into_iter()
            .filter(|(s, _)| *s == Severity::Critical)
            .map(|(_, m)| m)
            .collect()
    }
}

impl AlarmSink for CapturingAlarm {
    fn alarm(&self, severity: Severity, message: &str) {
        self.entries.lock().unwrap().push((severity, message.to_string()));
    }
}
