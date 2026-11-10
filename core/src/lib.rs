//! # zcg-core
//!
//! Engine deteksi inti untuk **zeroclick-guard** — perisai anti-spyware &
//! zero-click.
//!
//! Engine ini **deterministik dan berbasis aturan** (bukan AI): ia membaca
//! aliran [`Observation`] (koneksi jaringan, media masuk, izin, dll.),
//! menjalankan sekumpulan aturan yang transparan, dan menghasilkan
//! [`Finding`] berbobot skor yang digabung menjadi [`Verdict`] per-aplikasi.
//!
//! Engine ini sengaja tidak tahu dari mana observasi berasal. Di Android ia
//! akan diisi oleh VpnService; di desktop bisa dari pcap; di pengujian dari
//! simulator jinak. Dengan begitu kode deteksi yang sama dipakai di produk
//! maupun di demo — tidak ada yang dipalsukan.
//!
//! ## Contoh
//! ```
//! use zcg_core::{Engine, Config, IocSet, Observation};
//!
//! let mut engine = Engine::new(Config::default(), IocSet::new());
//! let findings = engine.process(Observation::Media {
//!     ts: 10_000,
//!     app: "com.whatsapp".into(),
//!     bytes: 800_000,
//! });
//! assert!(findings.is_empty()); // media saja belum mencurigakan
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
