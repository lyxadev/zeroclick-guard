//! Konfigurasi engine: ambang batas setiap aturan deteksi.
//!
//! Semua angka di sini sengaja dibuka & bisa diatur. Itu bagian dari janji
//! "bisa diaudit": tidak ada ambang rahasia. Nilai default dipilih
//! konservatif untuk menekan alarm palsu.

use serde::{Deserialize, Serialize};

/// Bobot skor tiap aturan. Dipisah dari ambang agar mudah ditala.
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

    /// Jumlah koneksi minimal ke tujuan yang sama sebelum pola beacon dinilai.
    pub beacon_min_hits: usize,
    /// Koefisien variasi maksimum (stddev/mean) interval agar dianggap "teratur
    /// seperti robot". Makin kecil makin ketat. 0.15 = jitter < 15%.
    pub beacon_max_cv: f64,
    /// Rentang interval beacon yang masuk akal (milidetik).
    pub beacon_min_interval_ms: u64,
    pub beacon_max_interval_ms: u64,

    /// Jendela waktu untuk menjumlahkan byte keluar (milidetik).
    pub exfil_window_ms: u64,
    /// Ambang byte keluar dari aplikasi latar belakang dalam satu jendela.
    pub exfil_threshold_bytes: u64,

    /// Berapa lama setelah media masuk sebuah koneksi baru masih dianggap
    /// "buntut zero-click" (milidetik).
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
            exfil_threshold_bytes: 2_000_000, // 2 MB dari app latar belakang = red flag
            zeroclick_window_ms: 120_000,     // 2 menit
        }
    }
}

/// Daftar izin yang dianggap sensitif. Kombinasi izin ini dengan layanan
/// Accessibility adalah sidik jari khas spyware Android.
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
