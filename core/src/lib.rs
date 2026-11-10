//! # zcg-core
//!
//! The core detection engine for **zeroclick-guard** — an anti-spyware &
//! zero-click shield.
//!
//! The engine is **deterministic and rule-based** (not AI): it reads a stream
//! of [`Observation`]s (network connections, inbound media, permissions, etc.),
//! runs a set of transparent rules, and produces score-weighted [`Finding`]s
//! that combine into a per-app [`Verdict`].
//!
//! The engine deliberately does not know where observations come from. On
//! Android it is fed by a VpnService; on desktop it can come from pcap; in
//! tests from a benign simulator. That way the same detection code runs in the
//! product and in the demo — nothing is faked.
//!
//! ## Example
//! ```
//! use zcg_core::{Engine, Config, IocSet, Observation};
//!
//! let mut engine = Engine::new(Config::default(), IocSet::new());
//! let findings = engine.process(Observation::Media {
//!     ts: 10_000,
//!     app: "com.whatsapp".into(),
//!     bytes: 800_000,
//! });
//! assert!(findings.is_empty()); // media alone is not yet suspicious
//! ```

pub mod config;
pub mod engine;
pub mod ioc;
pub mod model;
pub mod netutil;

pub use config::{Config, Weights};
pub use engine::Engine;
pub use ioc::{IocEntry, IocSet};
pub use model::{Finding, Observation, Severity, Verdict};
