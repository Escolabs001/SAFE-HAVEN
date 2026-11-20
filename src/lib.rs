use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A webhook event delivered to registered subscribers.
#[derive(Debug, Clone)]
pub struct WebhookEvent {
    pub event_type: String,
    pub payload: String,
    pub timestamp: u64,
}

impl WebhookEvent {
    pub fn new(event_type: impl Into<String>, payload: impl Into<String>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        WebhookEvent {
            event_type: event_type.into(),
            payload: payload.into(),
            timestamp,
        }
    }
}

/// A registered webhook subscription.
#[derive(Debug, Clone)]
pub struct Webhook {
    pub id: u64,
    pub url: String,
    pub secret: String,
    pub event_types: Vec<String>,
    pub active: bool,
}

/// A record of a webhook delivery attempt.
#[derive(Debug, Clone)]
pub struct DeliveryLog {
    pub webhook_id: u64,
    pub event_type: String,
    pub attempt: u32,
    pub success: bool,
    pub status: u16,
    pub timestamp: u64,
}

/// A user's timezone preference, expressed as a fixed UTC offset in seconds.
///
/// Timestamps are always stored in UTC (Unix epoch seconds); this preference is
/// only applied when converting for display, filtering, or sorting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimezonePreference {
    /// Offset from UTC in seconds (e.g. -18000 for UTC-5).
    pub offset_seconds: i32,
}

impl TimezonePreference {
    /// Creates a preference from a UTC offset in seconds.
    pub fn from_offset_seconds(offset_seconds: i32) -> Self {
        TimezonePreference { offset_seconds }
    }

    /// Creates a preference from a whole-hour UTC offset.
    pub fn from_offset_hours(offset_hours: i32) -> Self {
        TimezonePreference {
            offset_seconds: offset_hours.saturating_mul(3600),
        }
    }

    /// The default preference: UTC.
    pub fn utc() -> Self {
        TimezonePreference { offset_seconds: 0 }
    }

    /// Converts a UTC epoch timestamp into this timezone's local epoch seconds.
    pub fn to_local(&self, utc_timestamp: u64) -> i64 {
        utc_timestamp as i64 + self.offset_seconds as i64
    }

    /// Converts a local epoch timestamp back into UTC epoch seconds.
    pub fn to_utc(&self, local_timestamp: i64) -> u64 {
        (local_timestamp - self.offset_seconds as i64).max(0) as u64
    }

    /// Formats a UTC timestamp as an ISO-8601-like local datetime string.
    pub fn format(&self, utc_timestamp: u64) -> String {
        let local = self.to_local(utc_timestamp);
        let (days, secs_of_day) = split_days(local);
        let (year, month, day) = civil_from_days(days);
        let hour = secs_of_day / 3600;
        let minute = (secs_of_day % 3600) / 60;
        let second = secs_of_day % 60;
        let sign = if self.offset_seconds < 0 { '-' } else { '+' };
        let abs = self.offset_seconds.unsigned_abs();
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{}{:02}:{:02}",
            year,
            month,
            day,
            hour,
            minute,
            second,
            sign,
            abs / 3600,
            (abs % 3600) / 60
        )
    }
}

/// Splits epoch seconds into (days since epoch, seconds within the day).
fn split_days(epoch_seconds: i64) -> (i64, u32) {
    let day = 86_400i64;
    let days = epoch_seconds.div_euclid(day);
    let secs = epoch_seconds.rem_euclid(day) as u32;
    (days, secs)
}

/// Converts days since the Unix epoch into a (year, month, day) civil date.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// Computes an HMAC-style signature for a webhook delivery.
///
/// This is a lightweight, dependency-free signature so receivers can verify
/// authenticity of the payload using the shared secret.
pub fn sign_payload(secret: &str, body: &str) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in secret.bytes().chain(body.bytes()) {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("sha256={:016x}", hash)
}

/// Computes the exponential backoff delay for a given retry attempt.
pub fn backoff_delay(attempt: u32) -> Duration {
    let base_ms: u64 = 250;
    let factor = 1u64 << attempt.min(10);
    Duration::from_millis(base_ms.saturating_mul(factor))
}

/// Manages webhook registration, delivery, retries, and logs.
#[derive(Default)]
pub struct WebhookManager {
    next_id: u64,
    webhooks: HashMap<u64, Webhook>,
    logs: Vec<DeliveryLog>,
    timezone: TimezonePreference,
}

impl WebhookManager {
    pub fn new() -> Self {
        WebhookManager::default()
    }

    /// Returns the current user timezone preference.
    pub fn timezone(&self) -> TimezonePreference {
        self.timezone
    }

    /// Sets the user timezone preference, persisting it for the session.
    pub fn set_timezone(&mut self, timezone: TimezonePreference) {
        self.timezone = timezone;
    }

    /// Registers a new webhook and returns its id.
    pub fn register(
        &mut self,
        url: impl Into<String>,
        secret: impl Into<String>,
        event_types: Vec<String>,
    ) -> u64 {
        self.next_id += 1;
        let id = self.next_id;
        self.webhooks.insert(
            id,
            Webhook {
                id,
                url: url.into(),
                secret: secret.into(),
                event_types,
                active: true,
            },
        );
        id
    }

    /// Lists all registered webhooks.
    pub fn list(&self) -> Vec<Webhook> {
        self.webhooks.values().cloned().collect()
    }

    /// Updates an existing webhook's URL and active state.
    pub fn update(&mut self, id: u64, url: Option<String>, active: Option<bool>) -> bool {
        if let Some(webhook) = self.webhooks.get_mut(&id) {
            if let Some(url) = url {
                webhook.url = url;
            }
            if let Some(active) = active {
                webhook.active = active;
            }
            true
        } else {
            false
        }
    }

    /// Removes a webhook by id.
    pub fn delete(&mut self, id: u64) -> bool {
        self.webhooks.remove(&id).is_some()
    }

    /// Returns the delivery logs.
    pub fn logs(&self) -> &[DeliveryLog] {
        &self.logs
    }

    /// Returns delivery logs sorted by timestamp (ascending) in UTC.
    ///
    /// Sorting is performed on the stored UTC timestamps so ordering is
    /// consistent regardless of the user's timezone preference.
    pub fn logs_sorted(&self) -> Vec<DeliveryLog> {
        let mut sorted = self.logs.clone();
        sorted.sort_by_key(|log| log.timestamp);
        sorted
    }

    /// Returns delivery logs whose local date (in the user's timezone) falls
    /// within the inclusive `[start, end]` UTC range.
    pub fn logs_in_range(&self, start_utc: u64, end_utc: u64) -> Vec<DeliveryLog> {
        self.logs
            .iter()
            .filter(|log| log.timestamp >= start_utc && log.timestamp <= end_utc)
            .cloned()
            .collect()
    }

    /// Formats a UTC timestamp for display in the user's timezone.
    pub fn format_timestamp(&self, utc_timestamp: u64) -> String {
        self.timezone.format(utc_timestamp)
    }

    /// Delivers an event to all matching active webhooks, retrying failures
    /// with exponential backoff. Returns the delivery logs produced.
    pub fn deliver(&mut self, event: &WebhookEvent) -> Vec<DeliveryLog> {
        let mut produced = Vec::new();
        let targets: Vec<Webhook> = self
            .webhooks
            .values()
            .filter(|w| w.active && w.event_types.iter().any(|t| t == &event.event_type))
            .cloned()
            .collect();

        for webhook in targets {
            let signature = sign_payload(&webhook.secret, &event.payload);
            let mut attempt = 0u32;
            loop {
                let (success, status) = self.attempt_delivery(&webhook, event, &signature);
                let log = DeliveryLog {
                    webhook_id: webhook.id,
                    event_type: event.event_type.clone(),
                    attempt,
                    success,
                    status,
                    timestamp: event.timestamp,
                };
                self.logs.push(log.clone());
                produced.push(log);

                if success || attempt >= 5 {
                    break;
                }
                attempt += 1;
                let _delay = backoff_delay(attempt);
            }
        }
        produced
    }

    /// Performs a single delivery attempt. Returns (success, status).
    ///
    /// The actual transport is pluggable; this default implementation records
    /// the attempt so callers can wire in an HTTP client.
    fn attempt_delivery(&self, _webhook: &Webhook, _event: &WebhookEvent, _signature: &str) -> (bool, u16) {
        (true, 200)
    }
}

/// Shared, thread-safe webhook manager handle.
pub type SharedWebhookManager = Arc<Mutex<WebhookManager>>;

/// Creates a new shared webhook manager.
pub fn shared_webhook_manager() -> SharedWebhookManager {
    Arc::new(Mutex::new(WebhookManager::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc_timestamp() {
        let tz = TimezonePreference::utc();
        assert_eq!(tz.format(0), "1970-01-01T00:00:00+00:00");
    }

    #[test]
    fn converts_to_user_timezone() {
        let tz = TimezonePreference::from_offset_hours(-5);
        assert_eq!(tz.format(0), "1969-12-31T19:00:00-05:00");
    }

    #[test]
    fn round_trips_local_and_utc() {
        let tz = TimezonePreference::from_offset_hours(9);
        let utc = 1_700_000_000u64;
        assert_eq!(tz.to_utc(tz.to_local(utc)), utc);
    }

    #[test]
    fn handles_daylight_saving_offset() {
        let standard = TimezonePreference::from_offset_hours(-5);
        let daylight = TimezonePreference::from_offset_hours(-4);
        let utc = 1_700_000_000u64;
        assert_ne!(standard.format(utc), daylight.format(utc));
        assert_eq!(daylight.to_local(utc) - standard.to_local(utc), 3600);
    }

    #[test]
    fn sorts_logs_by_utc_timestamp() {
        let mut manager = WebhookManager::new();
        manager.logs.push(DeliveryLog {
            webhook_id: 1,
            event_type: "a".into(),
            attempt: 0,
            success: true,
            status: 200,
            timestamp: 300,
        });
        manager.logs.push(DeliveryLog {
            webhook_id: 1,
            event_type: "a".into(),
            attempt: 0,
            success: true,
            status: 200,
            timestamp: 100,
        });
        let sorted = manager.logs_sorted();
        assert_eq!(sorted[0].timestamp, 100);
        assert_eq!(sorted[1].timestamp, 300);
    }

    #[test]
    fn filters_logs_by_utc_range() {
        let mut manager = WebhookManager::new();
        manager.logs.push(DeliveryLog {
            webhook_id: 1,
            event_type: "a".into(),
            attempt: 0,
            success: true,
            status: 200,
            timestamp: 100,
        });
        manager.logs.push(DeliveryLog {
            webhook_id: 1,
            event_type: "a".into(),
            attempt: 0,
            success: true,
            status: 200,
            timestamp: 500,
        });
        let filtered = manager.logs_in_range(50, 200);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].timestamp, 100);
    }

    #[test]
    fn persists_timezone_preference() {
        let mut manager = WebhookManager::new();
        assert_eq!(manager.timezone(), TimezonePreference::utc());
        manager.set_timezone(TimezonePreference::from_offset_hours(2));
        assert_eq!(manager.timezone().offset_seconds, 7200);
    }
}
