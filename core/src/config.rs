//! Engine configuration: the thresholds for every detection rule.
//!
//! All numbers here are intentionally open and tunable. That is part of the
//! "auditable" promise: there are no secret thresholds. Defaults are chosen
//! conservatively to keep false positives low.

use serde::{Deserialize, Serialize};

/// Score weight for each rule. Separated from thresholds for easy tuning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Weights {
    pub ioc_match: u32,
    pub beaconing: u32,
    pub exfil_volume: u32,
    pub unknown_destination: u32,
    pub zeroclick_followup: u32,
    pub accessibility_abuse: u32,
    pub new_app: u32,
}

impl Default for Weights {
    fn default() -> Self {
        Weights {
            ioc_match: 50,
            beaconing: 30,
            exfil_volume: 25,
            unknown_destination: 15,
            zeroclick_followup: 40,
            accessibility_abuse: 35,
            new_app: 5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub weights: Weights,

    /// Minimum number of connections to the same destination before a beacon
    /// pattern is evaluated.
    pub beacon_min_hits: usize,
    /// Maximum coefficient of variation (stddev/mean) of intervals to count as
    /// "regular like a robot". Smaller is stricter. 0.15 = jitter < 15%.
    pub beacon_max_cv: f64,
    /// Plausible beacon interval range (milliseconds).
    pub beacon_min_interval_ms: u64,
    pub beacon_max_interval_ms: u64,

    /// Time window for summing outbound bytes (milliseconds).
    pub exfil_window_ms: u64,
    /// Outbound byte threshold from a background app within one window.
    pub exfil_threshold_bytes: u64,

    /// How long after inbound media a new connection still counts as a
    /// "zero-click follow-up" (milliseconds).
    pub zeroclick_window_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            weights: Weights::default(),
            beacon_min_hits: 4,
            beacon_max_cv: 0.15,
            beacon_min_interval_ms: 2_000,
            beacon_max_interval_ms: 3_600_000,
            exfil_window_ms: 60_000,
            exfil_threshold_bytes: 2_000_000, // 2 MB from a background app = red flag
            zeroclick_window_ms: 120_000,     // 2 minutes
        }
    }
}

/// Permissions considered sensitive. The combination of these with an
/// Accessibility service is a classic Android spyware fingerprint.
pub const SENSITIVE_PERMISSIONS: &[&str] = &[
    "RECORD_AUDIO",
    "READ_SMS",
    "RECEIVE_SMS",
    "READ_CONTACTS",
    "ACCESS_FINE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
    "CAMERA",
    "READ_CALL_LOG",
    "PROCESS_OUTGOING_CALLS",
];
