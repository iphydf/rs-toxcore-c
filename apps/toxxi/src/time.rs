use chrono::{DateTime, FixedOffset, Local, Utc};
use chrono_tz::Tz;
use std::time::{Instant, SystemTime};

pub trait TimeProvider: Send + Sync + std::fmt::Debug {
    fn now(&self) -> Instant;
    fn now_local(&self) -> DateTime<FixedOffset>;
}

#[derive(Debug, Clone)]
pub struct RealTimeProvider {
    timezone: Option<Tz>,
}

impl RealTimeProvider {
    pub fn new(timezone_str: Option<&str>) -> Self {
        let timezone = timezone_str.and_then(|s| s.parse::<Tz>().ok());
        Self { timezone }
    }
}

impl TimeProvider for RealTimeProvider {
    fn now(&self) -> Instant {
        Instant::now()
    }

    fn now_local(&self) -> DateTime<FixedOffset> {
        let now_utc = Utc::now();
        if let Some(tz) = self.timezone {
            now_utc.with_timezone(&tz).fixed_offset()
        } else {
            let local = Local::now();
            local.with_timezone(local.offset())
        }
    }
}

#[derive(Debug)]
pub struct FakeTimeProvider {
    instant: Instant,
    system_time: SystemTime,
}

impl FakeTimeProvider {
    pub fn new(instant: Instant, system_time: SystemTime) -> Self {
        Self {
            instant,
            system_time,
        }
    }
}

impl TimeProvider for FakeTimeProvider {
    fn now(&self) -> Instant {
        self.instant
    }

    fn now_local(&self) -> DateTime<FixedOffset> {
        DateTime::<Utc>::from(self.system_time).fixed_offset()
    }
}
