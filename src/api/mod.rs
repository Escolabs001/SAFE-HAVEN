//! API versioning strategy (issue #974).
//!
//! ## Scheme
//! Versioning is **URL-based**: every route lives under `/api/v{major}`
//! (e.g. `/api/v1/health`, `/api/v2/health`). The major version is the only
//! part of the version that is part of the URL; minor/patch releases are
//! backward compatible and never change the path.
//!
//! ## Supported versions
//! At most two major versions run simultaneously: the current version and the
//! previous one. Requests for any other version are rejected with
//! `400 Bad Request`.
//!
//! ## Deprecation policy
//! When a new major version is released the previous one is marked deprecated
//! and kept available for a **6 month** sunset window. Deprecated responses
//! carry `Deprecation` and `Sunset` headers plus a `Link` header pointing at
//! the migration guide. After the sunset date the version is removed.
//!
//! ## Client version selection
//! Clients select a version through the URL path. As a convenience, clients
//! may also send an `Accept-Version` header (e.g. `Accept-Version: v2`); when
//! present it must match the version in the path.
//!
//! ## Version information in responses
//! Every response includes an `X-API-Version` header with the resolved major
//! version.

use std::collections::HashMap;

/// Current (latest) API major version.
pub const CURRENT_VERSION: u32 = 2;
/// Previous API major version, still served during its sunset window.
pub const PREVIOUS_VERSION: u32 = 1;
/// Length of the deprecation window, in months.
pub const DEPRECATION_WINDOW_MONTHS: u32 = 6;

/// A single supported API version and its lifecycle metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiVersion {
    pub major: u32,
    /// Whether this version is deprecated (i.e. not the current version).
    pub deprecated: bool,
    /// Sunset date (`YYYY-MM-DD`) for deprecated versions.
    pub sunset: Option<&'static str>,
}

impl ApiVersion {
    /// Returns the version metadata for a supported major version, if any.
    pub fn lookup(major: u32) -> Option<ApiVersion> {
        match major {
            CURRENT_VERSION => Some(ApiVersion {
                major,
                deprecated: false,
                sunset: None,
            }),
            PREVIOUS_VERSION => Some(ApiVersion {
                major,
                deprecated: true,
                sunset: Some("2025-06-30"),
            }),
            _ => None,
        }
    }
}

/// Error returned when a request targets an unsupported API version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedVersion(pub String);

impl std::fmt::Display for UnsupportedVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for UnsupportedVersion {}

/// Parses a version segment such as `v2` or `2` into a major version number.
pub fn parse_version(segment: &str) -> Option<u32> {
    let digits = segment.strip_prefix('v').unwrap_or(segment);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Resolves the API version for a request path of the form `/api/v{major}/...`.
///
/// Returns the resolved [`ApiVersion`] or an [`UnsupportedVersion`] error when
/// the path is malformed or targets a version that is no longer served.
pub fn resolve_version(path: &str) -> Result<ApiVersion, UnsupportedVersion> {
    let mut parts = path.trim_start_matches('/').split('/');
    match (parts.next(), parts.next()) {
        (Some("api"), Some(segment)) => match parse_version(segment) {
            Some(major) => ApiVersion::lookup(major).ok_or_else(|| {
                UnsupportedVersion(format!(
                    "unsupported API version v{major}; supported: v{PREVIOUS_VERSION}, v{CURRENT_VERSION}"
                ))
            }),
            None => Err(UnsupportedVersion(format!(
                "invalid API version segment '{segment}'"
            ))),
        },
        _ => Err(UnsupportedVersion(
            "missing API version; expected /api/v{major}/...".to_string(),
        )),
    }
}

/// Validates an optional `Accept-Version` header against the path version.
pub fn check_accept_version(
    version: ApiVersion,
    accept_version: Option<&str>,
) -> Result<(), UnsupportedVersion> {
    if let Some(header) = accept_version {
        match parse_version(header.trim()) {
            Some(major) if major == version.major => Ok(()),
            Some(major) => Err(UnsupportedVersion(format!(
                "Accept-Version v{major} does not match path version v{}",
                version.major
            ))),
            None => Err(UnsupportedVersion(format!(
                "invalid Accept-Version header '{header}'"
            ))),
        }
    } else {
        Ok(())
    }
}

/// Builds the response headers that advertise the resolved API version and,
/// for deprecated versions, the deprecation/sunset information.
pub fn version_headers(version: ApiVersion) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("X-API-Version".to_string(), format!("v{}", version.major));
    if version.deprecated {
        headers.insert("Deprecation".to_string(), "true".to_string());
        if let Some(sunset) = version.sunset {
            headers.insert("Sunset".to_string(), sunset.to_string());
        }
        headers.insert(
            "Link".to_string(),
            format!(
                "</docs/api/v{CURRENT_VERSION}>; rel=\"successor-version\""
            ),
        );
    }
    headers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_supported_versions() {
        assert_eq!(resolve_version("/api/v2/health").unwrap().major, 2);
        assert!(resolve_version("/api/v1/health").unwrap().deprecated);
    }

    #[test]
    fn rejects_unsupported_versions() {
        assert!(resolve_version("/api/v3/health").is_err());
        assert!(resolve_version("/health").is_err());
    }

    #[test]
    fn accept_version_must_match_path() {
        let v = ApiVersion::lookup(2).unwrap();
        assert!(check_accept_version(v, Some("v2")).is_ok());
        assert!(check_accept_version(v, Some("v1")).is_err());
    }

    #[test]
    fn deprecated_versions_advertise_sunset() {
        let headers = version_headers(ApiVersion::lookup(1).unwrap());
        assert_eq!(headers.get("X-API-Version").map(String::as_str), Some("v1"));
        assert!(headers.contains_key("Sunset"));
    }
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

pub const MAX_BULK_ITEMS: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkItem {
    pub id: Option<String>,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkItemError {
    pub index: usize,
    pub id: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkResult {
    pub operation_id: String,
    pub total: usize,
    pub success: usize,
    pub failure: usize,
    pub errors: Vec<BulkItemError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkProgress {
    pub operation_id: String,
    pub total: usize,
    pub processed: usize,
    pub success: usize,
    pub failure: usize,
    pub done: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulkOperation {
    Create,
    Update,
    Delete,
}

impl BulkOperation {
    pub fn as_str(&self) -> &'static str {
        match self {
            BulkOperation::Create => "create",
            BulkOperation::Update => "update",
            BulkOperation::Delete => "delete",
        }
    }
}

pub struct BulkProgressTracker {
    operations: Mutex<HashMap<String, BulkProgress>>,
}

impl BulkProgressTracker {
    pub fn new() -> Self {
        Self {
            operations: Mutex::new(HashMap::new()),
        }
    }

    pub fn start(&self, operation_id: &str, total: usize) {
        let mut ops = self.operations.lock().unwrap();
        ops.insert(
            operation_id.to_string(),
            BulkProgress {
                operation_id: operation_id.to_string(),
                total,
                processed: 0,
                success: 0,
                failure: 0,
                done: false,
            },
        );
    }

    pub fn record(&self, operation_id: &str, success: bool) {
        let mut ops = self.operations.lock().unwrap();
        if let Some(progress) = ops.get_mut(operation_id) {
            progress.processed += 1;
            if success {
                progress.success += 1;
            } else {
                progress.failure += 1;
            }
            if progress.processed >= progress.total {
                progress.done = true;
            }
        }
    }

    pub fn get(&self, operation_id: &str) -> Option<BulkProgress> {
        let ops = self.operations.lock().unwrap();
        ops.get(operation_id).cloned()
    }
}

impl Default for BulkProgressTracker {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_item(op: BulkOperation, index: usize, item: &BulkItem) -> Result<(), BulkItemError> {
    match op {
        BulkOperation::Create => {
            if item.data.is_null() {
                return Err(BulkItemError {
                    index,
                    id: item.id.clone(),
                    message: "item data must not be null".to_string(),
                });
            }
        }
        BulkOperation::Update | BulkOperation::Delete => {
            if item.id.as_deref().map(str::is_empty).unwrap_or(true) {
                return Err(BulkItemError {
                    index,
                    id: item.id.clone(),
                    message: "item id is required".to_string(),
                });
            }
        }
    }
    Ok(())
}

pub fn validate_bulk_request(items: &[BulkItem]) -> Result<(), BulkItemError> {
    if items.is_empty() {
        return Err(BulkItemError {
            index: 0,
            id: None,
            message: "bulk request must contain at least one item".to_string(),
        });
    }
    if items.len() > MAX_BULK_ITEMS {
        return Err(BulkItemError {
            index: MAX_BULK_ITEMS,
            id: None,
            message: format!("bulk request exceeds maximum of {} items", MAX_BULK_ITEMS),
        });
    }
    Ok(())
}

pub fn process_bulk<F>(
    op: BulkOperation,
    operation_id: &str,
    items: &[BulkItem],
    tracker: &BulkProgressTracker,
    mut apply: F,
) -> Result<BulkResult, BulkItemError>
where
    F: FnMut(BulkOperation, &BulkItem) -> Result<(), String>,
{
    validate_bulk_request(items)?;
    tracker.start(operation_id, items.len());

    let mut errors = Vec::new();
    let mut success = 0usize;

    for (index, item) in items.iter().enumerate() {
        let outcome = match validate_item(op, index, item) {
            Ok(()) => apply(op, item),
            Err(err) => Err(err.message),
        };

        match outcome {
            Ok(()) => {
                success += 1;
                tracker.record(operation_id, true);
            }
            Err(message) => {
                errors.push(BulkItemError {
                    index,
                    id: item.id.clone(),
                    message,
                });
                tracker.record(operation_id, false);
            }
        }
    }

    Ok(BulkResult {
        operation_id: operation_id.to_string(),
        total: items.len(),
        success,
        failure: errors.len(),
        errors,
    })
}
