use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
#[cfg(any(windows, target_os = "linux"))]
use std::time::Duration;
use std::time::Instant;

static START: OnceLock<Instant> = OnceLock::new();
static LAST_MILLIS: AtomicU64 = AtomicU64::new(0);

fn elapsed_millis() -> u64 {
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_millis()).unwrap_or(u64::MAX)
}

pub fn record_activity() {
    LAST_MILLIS.store(elapsed_millis(), Ordering::Release);
}

#[cfg(any(windows, target_os = "linux"))]
pub fn idle_for() -> Duration {
    Duration::from_millis(elapsed_millis().saturating_sub(LAST_MILLIS.load(Ordering::Acquire)))
}
