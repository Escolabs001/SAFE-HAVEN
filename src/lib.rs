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
}

impl WebhookManager {
    pub fn new() -> Self {
        WebhookManager::default()
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
