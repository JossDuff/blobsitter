//! D20 — alarm hygiene and failure backoff: retry loops re-raise conditions forever
//! (they must), but a pager gets ONE page per condition inside the suppression
//! window; and a persistently failing follower slows its own polling instead of
//! hammering rate-limited endpoints thousands of times a day.

use std::time::Duration;

use blobsitter_daemon::alarm::{AlarmSink, CapturingAlarm, DedupAlarm, Severity};
use blobsitter_daemon::follower::backoff_multiplier;

#[test]
fn d20_identical_alarms_page_once_per_window() {
    let inner = std::sync::Arc::new(CapturingAlarm::new());
    let dedup = DedupAlarm::new(ArcSink(inner.clone()), Duration::from_millis(80));

    for _ in 0..20 {
        dedup.alarm(Severity::Critical, "HALT: blobs for declaration 7 unavailable");
    }
    assert_eq!(inner.entries().len(), 1, "one page per condition");

    // Different detail is a different condition and passes through.
    dedup.alarm(Severity::Critical, "HALT: blobs for declaration 8 unavailable");
    assert_eq!(inner.entries().len(), 2);

    // A lapsed window re-pages a still-standing condition.
    std::thread::sleep(Duration::from_millis(100));
    dedup.alarm(Severity::Critical, "HALT: blobs for declaration 7 unavailable");
    assert_eq!(inner.entries().len(), 3);
}

#[test]
fn d20_backoff_doubles_and_caps() {
    assert_eq!(backoff_multiplier(0), 1, "healthy cadence untouched");
    assert_eq!(backoff_multiplier(1), 2);
    assert_eq!(backoff_multiplier(3), 8);
    assert_eq!(backoff_multiplier(5), 32);
    assert_eq!(backoff_multiplier(50), 32, "capped: the daemon never stops retrying");
}

/// Adapter: CapturingAlarm behind an Arc still records for assertions.
struct ArcSink(std::sync::Arc<CapturingAlarm>);

impl AlarmSink for ArcSink {
    fn alarm(&self, severity: Severity, message: &str) {
        self.0.alarm(severity, message);
    }
}
