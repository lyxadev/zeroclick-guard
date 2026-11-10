//! Core data model: incoming observations, findings, and verdicts.
//!
//! [`Observation`] is the only input shape the engine accepts. It is
//! deliberately platform-agnostic: on Android it is fed by a VpnService, on
//! desktop it can come from pcap, and in tests from the simulator. The engine
//! does not care where observations come from.

use serde::{Deserialize, Serialize};

/// Time in milliseconds since the Unix epoch.
pub type TimestampMs = u64;

fn default_proto() -> String {
    "tcp".to_string()
}

/// A single event observed on the device.
///
/// JSON form (one object per line, JSONL) is distinguished by the `type` field:
/// - `{"type":"flow", ...}`          one outbound network connection
/// - `{"type":"media", ...}`         an app received inbound media (key for zero-click)
/// - `{"type":"app_installed", ...}` a new app was installed
/// - `{"type":"permission", ...}`    a permission was granted to an app
/// - `{"type":"accessibility", ...}` an Accessibility service was enabled for an app
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Observation {
    /// One outbound network flow from an app.
    Flow {
        ts: TimestampMs,
        app: String,
        /// true if the app is in the background (not actively used).
        #[serde(default)]
        app_background: bool,
        dst_ip: String,
        #[serde(default)]
        dst_port: u16,
        #[serde(default)]
        domain: Option<String>,
        /// Bytes sent OUT of the device (exfiltration signal).
        #[serde(default)]
        bytes_out: u64,
        #[serde(default)]
        bytes_in: u64,
        #[serde(default = "default_proto")]
        proto: String,
    },
    /// An app (usually a messenger) auto-received inbound media.
    /// This is the classic entry point for a zero-click attack.
    Media {
        ts: TimestampMs,
        app: String,
        #[serde(default)]
        bytes: u64,
    },
    /// A new app was installed.
    AppInstalled { ts: TimestampMs, app: String },
    /// A permission was granted to an app (e.g. "RECORD_AUDIO").
    Permission {
        ts: TimestampMs,
        app: String,
        permission: String,
    },
    /// An Accessibility service was enabled for an app — often abused by spyware.
    Accessibility { ts: TimestampMs, app: String },
}

impl Observation {
    pub fn ts(&self) -> TimestampMs {
        match self {
            Observation::Flow { ts, .. }
            | Observation::Media { ts, .. }
            | Observation::AppInstalled { ts, .. }
            | Observation::Permission { ts, .. }
            | Observation::Accessibility { ts, .. } => *ts,
        }
    }

    pub fn app(&self) -> &str {
        match self {
            Observation::Flow { app, .. }
            | Observation::Media { app, .. }
            | Observation::AppInstalled { app, .. }
            | Observation::Permission { app, .. }
            | Observation::Accessibility { app, .. } => app,
        }
    }
}

/// Severity level, ordered from lowest to highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// No meaningful indication.
    Clean,
    /// Worth keeping an eye on; not necessarily malicious.
    Low,
    /// Suspicious.
    Medium,
    /// Likely spyware.
    High,
    /// Very strong indication — recommendation: cut off & quarantine.
    Critical,
}

impl Severity {
    /// Map a per-app cumulative score to a severity level.
    /// Deterministic and auditable — no guessing.
    pub fn from_score(score: u32) -> Severity {
        match score {
            0..=9 => Severity::Clean,
            10..=29 => Severity::Low,
            30..=59 => Severity::Medium,
            60..=79 => Severity::High,
            _ => Severity::Critical,
        }
    }

    pub fn label_id(&self) -> &'static str {
        match self {
            Severity::Clean => "SAFE",
            Severity::Low => "WATCH",
            Severity::Medium => "SUSPICIOUS",
            Severity::High => "LIKELY SPYWARE",
            Severity::Critical => "DANGER",
        }
    }
}

/// A single finding produced by a detection rule.
///
/// Every finding carries its own reason (`detail`) and score weight (`score`).
/// There is no "black box": each decision can be traced back to the rule that
/// raised it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub ts: TimestampMs,
    pub app: String,
    /// Stable rule ID (for tests & correlation), e.g. "ioc_match".
    pub rule: String,
    pub title: String,
    pub detail: String,
    pub score: u32,
}

/// Combined verdict for a single app: total score, severity, and all the
/// findings that make it up.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub app: String,
    pub score: u32,
    pub severity: Severity,
    pub findings: Vec<Finding>,
}

impl Verdict {
    /// true if this app warrants automatic blocking/quarantine.
    pub fn should_block(&self) -> bool {
        self.severity >= Severity::High
    }
}
