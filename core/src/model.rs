//! Model data inti: observasi masuk, temuan (finding), dan vonis (verdict).
//!
//! `Observation` adalah satu-satunya bentuk input ke engine. Dia sengaja
//! platform-agnostik: di Android nanti diisi oleh VpnService, di desktop
//! bisa diisi dari pcap atau dari simulator uji. Engine tidak peduli dari
//! mana datangnya.

use serde::{Deserialize, Serialize};

/// Waktu dalam milidetik sejak epoch Unix.
pub type TimestampMs = u64;

fn default_proto() -> String {
    "tcp".to_string()
}

/// Satu kejadian yang diamati di perangkat.
///
/// Format JSON (satu objek per baris, JSONL) dibedakan oleh field `type`:
/// - `{"type":"flow", ...}`          satu koneksi jaringan keluar
/// - `{"type":"media", ...}`         aplikasi menerima media masuk (penting untuk zero-click)
/// - `{"type":"app_installed", ...}` aplikasi baru terpasang
/// - `{"type":"permission", ...}`    izin diberikan ke aplikasi
/// - `{"type":"accessibility", ...}` layanan Accessibility diaktifkan untuk aplikasi
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Observation {
    /// Satu arus (flow) koneksi jaringan keluar dari sebuah aplikasi.
    Flow {
        ts: TimestampMs,
        app: String,
        /// true jika aplikasi sedang di latar belakang (tidak dipakai user).
        #[serde(default)]
        app_background: bool,
        dst_ip: String,
        #[serde(default)]
        dst_port: u16,
        #[serde(default)]
        domain: Option<String>,
        /// Byte yang dikirim KELUAR perangkat (indikator exfiltrasi).
        #[serde(default)]
        bytes_out: u64,
        #[serde(default)]
        bytes_in: u64,
        #[serde(default = "default_proto")]
        proto: String,
    },
    /// Aplikasi (biasanya messaging) menerima media masuk secara otomatis.
    /// Inilah pintu masuk klasik serangan zero-click.
    Media {
        ts: TimestampMs,
        app: String,
        #[serde(default)]
        bytes: u64,
    },
    /// Aplikasi baru terpasang.
    AppInstalled { ts: TimestampMs, app: String },
    /// Sebuah izin diberikan ke aplikasi (mis. "RECORD_AUDIO").
    Permission {
        ts: TimestampMs,
        app: String,
        permission: String,
    },
    /// Layanan Accessibility diaktifkan untuk aplikasi — sering disalahgunakan spyware.
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

/// Tingkat keparahan, terurut dari paling rendah ke paling tinggi.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Tidak ada indikasi berarti.
    Clean,
    /// Perlu diperhatikan, belum tentu jahat.
    Low,
    /// Mencurigakan.
    Medium,
    /// Kemungkinan besar spyware.
    High,
    /// Sangat kuat indikasinya — rekomendasi: putus & karantina.
    Critical,
}

impl Severity {
    /// Pemetaan skor kumulatif per-aplikasi ke tingkat keparahan.
    /// Deterministik & bisa diaudit — tidak ada tebakan.
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
            Severity::Clean => "AMAN",
            Severity::Low => "PANTAU",
            Severity::Medium => "MENCURIGAKAN",
            Severity::High => "KEMUNGKINAN SPYWARE",
            Severity::Critical => "BAHAYA",
        }
    }
}

/// Satu temuan yang dihasilkan oleh sebuah aturan deteksi.
///
/// Setiap temuan selalu membawa alasannya sendiri (`detail`) dan bobot
/// skornya (`score`). Tidak ada "kotak hitam": setiap keputusan bisa
/// ditelusuri balik ke aturan mana yang memicunya.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub ts: TimestampMs,
    pub app: String,
    /// ID aturan yang stabil (untuk pengujian & korelasi), mis. "ioc_match".
    pub rule: String,
    pub title: String,
    pub detail: String,
    pub score: u32,
}

/// Vonis gabungan untuk satu aplikasi: total skor, tingkat keparahan, dan
/// semua temuan yang menyusunnya.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Verdict {
    pub app: String,
    pub score: u32,
    pub severity: Severity,
    pub findings: Vec<Finding>,
}

impl Verdict {
    /// true jika aplikasi ini layak diblokir/dikarantina otomatis.
    pub fn should_block(&self) -> bool {
        self.severity >= Severity::High
    }
}
