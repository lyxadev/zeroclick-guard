//! Engine deteksi: makan `Observation`, keluarkan `Finding`, simpulkan `Verdict`.
//!
//! Prinsip desain:
//! - **Deterministik**: input yang sama → output yang sama, selalu. Bisa diuji
//!   & diaudit. Tidak ada AI, tidak ada keacakan.
//! - **Streaming**: observasi diproses satu per satu sesuai urutan waktu,
//!   seperti di perangkat sungguhan.
//! - **Menjelaskan diri**: tiap temuan membawa alasan & bobotnya sendiri.

use std::collections::{HashMap, HashSet};

use crate::config::{Config, SENSITIVE_PERMISSIONS};
use crate::ioc::IocSet;
use crate::model::{Finding, Observation, Severity, TimestampMs, Verdict};
use crate::netutil::is_external;

/// Keadaan per-aplikasi yang diperlukan untuk aturan lintas-waktu
/// (beaconing, exfiltrasi, korelasi zero-click).
#[derive(Debug)]
struct AppState {
    /// Riwayat waktu koneksi per tujuan (kunci = "ip|port") untuk deteksi beacon.
    dst_history: HashMap<String, Vec<TimestampMs>>,
    /// Byte keluar terbaru: (waktu, jumlah) dalam jendela exfiltrasi.
    out_window: Vec<(TimestampMs, u64)>,
    /// Waktu media masuk terakhir (pintu zero-click).
    last_media: Option<TimestampMs>,
    /// Apakah Accessibility aktif untuk app ini.
    has_accessibility: bool,
    /// Izin sensitif yang sudah diberikan.
    sensitive_perms: HashSet<String>,
    /// Tujuan yang pernah dilihat (agar "tujuan baru" hanya dihitung sekali).
    seen_dsts: HashSet<String>,
    /// Kunci temuan yang sudah pernah diangkat, agar tidak dobel skor.
    raised: HashSet<String>,
    /// Apakah alarm exfiltrasi sedang "terpasang" (anti-spam).
    exfil_armed: bool,
    /// Semua temuan untuk app ini, menumpuk.
    findings: Vec<Finding>,
}

impl Default for AppState {
    fn default() -> Self {
        AppState {
            dst_history: HashMap::new(),
            out_window: Vec::new(),
            last_media: None,
            has_accessibility: false,
            sensitive_perms: HashSet::new(),
            seen_dsts: HashSet::new(),
            raised: HashSet::new(),
            // Alarm exfiltrasi "terpasang" sejak awal; lepas setelah berbunyi,
            // lalu terpasang lagi saat trafik mereda (anti-spam).
            exfil_armed: true,
            findings: Vec::new(),
        }
    }
}

pub struct Engine {
    config: Config,
    ioc: IocSet,
    apps: HashMap<String, AppState>,
}

impl Engine {
    pub fn new(config: Config, ioc: IocSet) -> Self {
        Engine {
            config,
            ioc,
            apps: HashMap::new(),
        }
    }

    /// Jalankan engine atas urutan observasi sekaligus. Mengembalikan semua
    /// temuan sesuai urutan kemunculannya (berguna untuk demo & log).
    pub fn run(&mut self, observations: &[Observation]) -> Vec<Finding> {
        let mut all = Vec::new();
        for obs in observations {
            all.extend(self.process(obs.clone()));
        }
        all
    }

    /// Proses satu observasi. Mengembalikan temuan BARU yang dipicu olehnya.
    pub fn process(&mut self, obs: Observation) -> Vec<Finding> {
        match obs {
            Observation::Flow {
                ts,
                app,
                app_background,
                dst_ip,
                dst_port,
                domain,
                bytes_out,
                bytes_in: _,
                proto: _,
            } => self.on_flow(ts, app, app_background, dst_ip, dst_port, domain, bytes_out),
            Observation::Media { ts, app, bytes: _ } => {
                self.app_mut(&app).last_media = Some(ts);
                Vec::new()
            }
            Observation::AppInstalled { ts, app } => {
                let w = self.config.weights.new_app;
                let detail = format!(
                    "Aplikasi baru '{}' terpasang. Perlu dipantau sebentar.",
                    app
                );
                vec![self.raise(&app, ts, "new_app", "Aplikasi baru terpasang", detail, w)]
            }
            Observation::Permission {
                ts,
                app,
                permission,
            } => self.on_permission(ts, app, permission),
            Observation::Accessibility { ts, app } => self.on_accessibility(ts, app),
        }
    }

    /// Kumpulkan vonis per-aplikasi, terurut dari paling berbahaya.
    pub fn verdicts(&self) -> Vec<Verdict> {
        let mut out: Vec<Verdict> = self
            .apps
            .iter()
            .map(|(app, st)| {
                let score: u32 = st.findings.iter().map(|f| f.score).sum();
                Verdict {
                    app: app.clone(),
                    score,
                    severity: Severity::from_score(score),
                    findings: st.findings.clone(),
                }
            })
            .collect();
        out.sort_by(|a, b| b.score.cmp(&a.score).then(a.app.cmp(&b.app)));
        out
    }

    // ---- penanganan tiap jenis observasi -------------------------------

    fn on_flow(
        &mut self,
        ts: TimestampMs,
        app: String,
        app_background: bool,
        dst_ip: String,
        dst_port: u16,
        domain: Option<String>,
        bytes_out: u64,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        let external = is_external(&dst_ip);
        let dst_key = format!("{}|{}", dst_ip, dst_port);

        // 1) Cocokkan IoC (paling tegas). Cek IP lalu domain.
        let ioc_hit = self
            .ioc
            .match_ip(&dst_ip)
            .map(|e| (e.label.clone(), e.source.clone(), dst_ip.clone()))
            .or_else(|| {
                domain.as_ref().and_then(|d| {
                    self.ioc
                        .match_domain(d)
                        .map(|e| (e.label.clone(), e.source.clone(), d.clone()))
                })
            });
        if let Some((label, source, value)) = ioc_hit {
            let key = format!("ioc|{}", value);
            if self.app_mut(&app).raised.insert(key) {
                let w = self.config.weights.ioc_match;
                let detail = format!(
                    "Koneksi ke indikator berbahaya yang dikenal: {} ({}{}).",
                    value,
                    if label.is_empty() {
                        "tanpa label"
                    } else {
                        &label
                    },
                    if source.is_empty() {
                        String::new()
                    } else {
                        format!(", sumber: {}", source)
                    }
                );
                findings.push(self.raise(&app, ts, "ioc_match", "Cocok daftar IoC", detail, w));
            }
        }

        // 2) Buntut zero-click: koneksi eksternal BARU sesaat setelah media masuk.
        if external {
            let is_new = !self.app_mut(&app).seen_dsts.contains(&dst_key);
            let recent_media = self
                .app_mut(&app)
                .last_media
                .map(|m| ts >= m && ts - m <= self.config.zeroclick_window_ms)
                .unwrap_or(false);
            if is_new && recent_media {
                let key = format!("zeroclick|{}", dst_key);
                if self.app_mut(&app).raised.insert(key) {
                    let w = self.config.weights.zeroclick_followup;
                    let gap = ts - self.app_mut(&app).last_media.unwrap();
                    let detail = format!(
                        "'{}' menerima media lalu {} dtk kemudian membuka koneksi baru ke {} \
                         (luar, belum pernah dihubungi). Ini pola khas serangan zero-click.",
                        app,
                        gap / 1000,
                        dst_ip
                    );
                    findings.push(self.raise(
                        &app,
                        ts,
                        "zeroclick_followup",
                        "Pola buntut zero-click",
                        detail,
                        w,
                    ));
                }
            }
        }

        // 3) Tujuan eksternal baru dari aplikasi latar belakang.
        if external && app_background {
            let key = format!("unknown_dst|{}", dst_key);
            if !self.app_mut(&app).seen_dsts.contains(&dst_key)
                && self.app_mut(&app).raised.insert(key)
            {
                let w = self.config.weights.unknown_destination;
                let detail = format!(
                    "Aplikasi latar belakang '{}' menghubungi tujuan luar yang belum \
                     dikenal: {}:{}.",
                    app, dst_ip, dst_port
                );
                findings.push(self.raise(
                    &app,
                    ts,
                    "unknown_destination",
                    "Tujuan asing (app latar belakang)",
                    detail,
                    w,
                ));
            }
        }

        // Catat tujuan sebagai sudah dilihat (setelah aturan "baru" dievaluasi).
        self.app_mut(&app).seen_dsts.insert(dst_key.clone());

        // 4) Deteksi beaconing: koneksi berkala & teratur ke tujuan yang sama.
        if let Some(f) = self.check_beacon(ts, &app, &dst_key, &dst_ip) {
            findings.push(f);
        }

        // 5) Exfiltrasi: lonjakan byte keluar dari aplikasi latar belakang.
        if let Some(f) = self.check_exfil(ts, &app, app_background, bytes_out, &dst_ip) {
            findings.push(f);
        }

        findings
    }

    fn check_beacon(
        &mut self,
        ts: TimestampMs,
        app: &str,
        dst_key: &str,
        dst_ip: &str,
    ) -> Option<Finding> {
        let cfg = self.config.clone();
        let st = self.app_mut(app);
        let hist = st.dst_history.entry(dst_key.to_string()).or_default();
        hist.push(ts);
        if hist.len() < cfg.beacon_min_hits {
            return None;
        }
        let (mean, cv) = interval_stats(hist)?;
        let regular = cv <= cfg.beacon_max_cv
            && mean >= cfg.beacon_min_interval_ms as f64
            && mean <= cfg.beacon_max_interval_ms as f64;
        if !regular {
            return None;
        }
        let key = format!("beacon|{}", dst_key);
        if !st.raised.insert(key) {
            return None; // sudah diangkat untuk tujuan ini
        }
        let w = cfg.weights.beaconing;
        let detail = format!(
            "Koneksi berulang sangat teratur ke {} setiap ~{} dtk (variasi {:.0}%). \
             Pola 'menelepon pulang' (beacon) khas C2 spyware.",
            dst_ip,
            (mean / 1000.0).round() as u64,
            cv * 100.0
        );
        let f = finding(app, ts, "beaconing", "Pola beacon terdeteksi", detail, w);
        st.findings.push(f.clone());
        Some(f)
    }

    fn check_exfil(
        &mut self,
        ts: TimestampMs,
        app: &str,
        app_background: bool,
        bytes_out: u64,
        dst_ip: &str,
    ) -> Option<Finding> {
        let cfg = self.config.clone();
        let st = self.app_mut(app);
        st.out_window.push((ts, bytes_out));
        // Buang entri di luar jendela.
        let lo = ts.saturating_sub(cfg.exfil_window_ms);
        st.out_window.retain(|(t, _)| *t >= lo);
        let total: u64 = st.out_window.iter().map(|(_, b)| *b).sum();

        if total >= cfg.exfil_threshold_bytes && app_background {
            if st.exfil_armed {
                st.exfil_armed = false; // satu alarm per lonjakan
                let w = cfg.weights.exfil_volume;
                let detail = format!(
                    "Aplikasi latar belakang '{}' mengirim ~{} KB keluar ke {} dalam {} dtk. \
                     Indikasi exfiltrasi data.",
                    app,
                    total / 1024,
                    dst_ip,
                    cfg.exfil_window_ms / 1000
                );
                let f = finding(app, ts, "exfil_volume", "Lonjakan data keluar", detail, w);
                st.findings.push(f.clone());
                return Some(f);
            }
        } else if total < cfg.exfil_threshold_bytes {
            st.exfil_armed = true; // pasang kembali saat trafik mereda
        }
        None
    }

    fn on_permission(&mut self, ts: TimestampMs, app: String, permission: String) -> Vec<Finding> {
        let perm = permission.to_ascii_uppercase();
        let sensitive = SENSITIVE_PERMISSIONS.contains(&perm.as_str());
        if sensitive {
            self.app_mut(&app).sensitive_perms.insert(perm.clone());
        }
        self.maybe_accessibility_abuse(ts, &app)
    }

    fn on_accessibility(&mut self, ts: TimestampMs, app: String) -> Vec<Finding> {
        self.app_mut(&app).has_accessibility = true;
        self.maybe_accessibility_abuse(ts, &app)
    }

    /// Accessibility + izin sensitif = kombinasi khas spyware Android.
    fn maybe_accessibility_abuse(&mut self, ts: TimestampMs, app: &str) -> Vec<Finding> {
        let (has_acc, perms, already) = {
            let st = self.app_mut(app);
            (
                st.has_accessibility,
                st.sensitive_perms.clone(),
                st.raised.contains("accessibility_abuse"),
            )
        };
        if has_acc && !perms.is_empty() && !already {
            self.app_mut(app)
                .raised
                .insert("accessibility_abuse".to_string());
            let w = self.config.weights.accessibility_abuse;
            let mut list: Vec<String> = perms.into_iter().collect();
            list.sort();
            let detail = format!(
                "'{}' memakai layanan Accessibility SEKALIGUS memegang izin sensitif [{}]. \
                 Kombinasi ini sangat umum pada spyware (baca layar + sadap).",
                app,
                list.join(", ")
            );
            return vec![self.raise(
                app,
                ts,
                "accessibility_abuse",
                "Penyalahgunaan Accessibility",
                detail,
                w,
            )];
        }
        Vec::new()
    }

    // ---- util internal -------------------------------------------------

    fn app_mut(&mut self, app: &str) -> &mut AppState {
        self.apps.entry(app.to_string()).or_default()
    }

    /// Bikin finding, simpan ke state app, lalu kembalikan salinannya.
    fn raise(
        &mut self,
        app: &str,
        ts: TimestampMs,
        rule: &str,
        title: &str,
        detail: String,
        score: u32,
    ) -> Finding {
        let f = finding(app, ts, rule, title, detail, score);
        self.app_mut(app).findings.push(f.clone());
        f
    }
}

/// Bikin satu Finding (tanpa menyentuh state).
fn finding(
    app: &str,
    ts: TimestampMs,
    rule: &str,
    title: &str,
    detail: String,
    score: u32,
) -> Finding {
    Finding {
        ts,
        app: app.to_string(),
        rule: rule.to_string(),
        title: title.to_string(),
        detail,
        score,
    }
}

/// Hitung rata-rata interval & koefisien variasi dari deret waktu terurut.
/// Mengembalikan None jika datanya kurang dari 2 titik atau rata-rata nol.
fn interval_stats(times: &[TimestampMs]) -> Option<(f64, f64)> {
    if times.len() < 2 {
        return None;
    }
    let mut diffs: Vec<f64> = times
        .windows(2)
        .map(|w| (w[1].saturating_sub(w[0])) as f64)
        .collect();
    // Abaikan interval nol (kejadian kembar) agar tidak merusak statistik.
    diffs.retain(|d| *d > 0.0);
    if diffs.len() < 2 {
        return None;
    }
    let n = diffs.len() as f64;
    let mean = diffs.iter().sum::<f64>() / n;
    if mean <= 0.0 {
        return None;
    }
    let var = diffs.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / n;
    let cv = var.sqrt() / mean;
    Some((mean, cv))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ioc::IocEntry;

    fn ioc_with(ip: &str) -> IocSet {
        let mut s = IocSet::new();
        s.add(IocEntry {
            value: ip.to_string(),
            kind: "ip".to_string(),
            label: "C2 uji".to_string(),
            source: "test".to_string(),
        });
        s
    }

    #[test]
    fn ioc_match_scores() {
        let mut eng = Engine::new(Config::default(), ioc_with("203.0.113.9"));
        let f = eng.process(Observation::Flow {
            ts: 1000,
            app: "com.evil".into(),
            app_background: true,
            dst_ip: "203.0.113.9".into(),
            dst_port: 443,
            domain: None,
            bytes_out: 10,
            bytes_in: 0,
            proto: "tcp".into(),
        });
        assert!(f.iter().any(|x| x.rule == "ioc_match"));
        let v = eng.verdicts();
        assert!(v[0].severity >= Severity::Medium);
    }

    #[test]
    fn beacon_regular_flagged() {
        let mut eng = Engine::new(Config::default(), IocSet::new());
        // 5 koneksi tiap 60 dtk persis ke tujuan yang sama → beacon.
        for i in 0..5u64 {
            eng.process(Observation::Flow {
                ts: 1_000 + i * 60_000,
                app: "com.spy".into(),
                app_background: true,
                dst_ip: "198.51.100.7".into(),
                dst_port: 8443,
                domain: None,
                bytes_out: 100,
                bytes_in: 50,
                proto: "tcp".into(),
            });
        }
        assert!(eng
            .verdicts()
            .iter()
            .any(|v| v.findings.iter().any(|f| f.rule == "beaconing")));
    }

    #[test]
    fn irregular_not_beacon() {
        let mut eng = Engine::new(Config::default(), IocSet::new());
        let offsets = [0u64, 3_000, 47_000, 51_000, 230_000];
        for off in offsets {
            eng.process(Observation::Flow {
                ts: 1_000 + off,
                app: "com.chat".into(),
                app_background: false,
                dst_ip: "198.51.100.7".into(),
                dst_port: 443,
                domain: None,
                bytes_out: 100,
                bytes_in: 50,
                proto: "tcp".into(),
            });
        }
        assert!(!eng
            .verdicts()
            .iter()
            .any(|v| v.findings.iter().any(|f| f.rule == "beaconing")));
    }

    #[test]
    fn zeroclick_correlation() {
        let mut eng = Engine::new(Config::default(), IocSet::new());
        eng.process(Observation::Media {
            ts: 10_000,
            app: "com.whatsapp".into(),
            bytes: 900_000,
        });
        let f = eng.process(Observation::Flow {
            ts: 40_000, // 30 dtk setelah media
            app: "com.whatsapp".into(),
            app_background: true,
            dst_ip: "203.0.113.50".into(),
            dst_port: 443,
            domain: None,
            bytes_out: 2000,
            bytes_in: 0,
            proto: "tcp".into(),
        });
        assert!(f.iter().any(|x| x.rule == "zeroclick_followup"));
    }

    #[test]
    fn accessibility_plus_perm_is_abuse() {
        let mut eng = Engine::new(Config::default(), IocSet::new());
        eng.process(Observation::Permission {
            ts: 1,
            app: "com.flash".into(),
            permission: "RECORD_AUDIO".into(),
        });
        let f = eng.process(Observation::Accessibility {
            ts: 2,
            app: "com.flash".into(),
        });
        assert!(f.iter().any(|x| x.rule == "accessibility_abuse"));
    }

    #[test]
    fn benign_app_stays_clean() {
        let mut eng = Engine::new(Config::default(), IocSet::new());
        // Aplikasi normal di foreground, koneksi wajar, tak berulang-teratur.
        eng.process(Observation::Flow {
            ts: 1_000,
            app: "com.good".into(),
            app_background: false,
            dst_ip: "203.0.113.1".into(),
            dst_port: 443,
            domain: Some("cdn.example".into()),
            bytes_out: 1500,
            bytes_in: 40_000,
            proto: "tcp".into(),
        });
        let v = eng.verdicts();
        assert!(v.is_empty() || v[0].severity <= Severity::Low);
    }
}
