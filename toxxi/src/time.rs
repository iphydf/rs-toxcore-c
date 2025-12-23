use chrono::{DateTime, FixedOffset, Local, Utc};
use chrono_tz::Tz;
use std::sync::RwLock;
use std::time::{Duration, Instant, SystemTime};

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
    instant: RwLock<Instant>,
    system_time: RwLock<SystemTime>,
    timezone: Option<Tz>,
}

impl FakeTimeProvider {
    pub fn new(instant: Instant, system_time: SystemTime) -> Self {
        Self {
            instant: RwLock::new(instant),
            system_time: RwLock::new(system_time),
            timezone: None,
        }
    }

    pub fn with_timezone(mut self, timezone: Tz) -> Self {
        self.timezone = Some(timezone);
        self
    }

    pub fn advance(&self, duration: Duration) {
        *self.instant.write().unwrap() += duration;
        *self.system_time.write().unwrap() += duration;
    }

    pub fn set_time(&self, instant: Instant, system_time: SystemTime) {
        *self.instant.write().unwrap() = instant;
        *self.system_time.write().unwrap() = system_time;
    }
}

impl TimeProvider for FakeTimeProvider {
    fn now(&self) -> Instant {
        *self.instant.read().unwrap()
    }

    fn now_local(&self) -> DateTime<FixedOffset> {
        let st = *self.system_time.read().unwrap();
        let datetime: DateTime<Utc> = st.into();
        if let Some(tz) = self.timezone {
            datetime.with_timezone(&tz).fixed_offset()
        } else {
            datetime.with_timezone(&Utc).fixed_offset()
        }
    }
}
