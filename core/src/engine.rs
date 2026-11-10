//! Detection engine: eats `Observation`s, emits `Finding`s, concludes `Verdict`s.
//!
//! Design principles:
//! - **Deterministic**: same input → same output, always. Testable and
//!   auditable. No AI, no randomness.
//! - **Streaming**: observations are processed one by one in time order, like
//!   on a real device.
//! - **Self-explaining**: every finding carries its own reason and weight.

use std::collections::{HashMap, HashSet};

use crate::config::{Config, SENSITIVE_PERMISSIONS};
use crate::ioc::IocSet;
use crate::model::{Finding, Observation, Severity, TimestampMs, Verdict};
use crate::netutil::is_external;

/// Per-app state needed for cross-time rules (beaconing, exfiltration,
/// zero-click correlation).
#[derive(Debug)]
struct AppState {
    /// Connection timestamps per destination (key = "ip|port") for beacon detection.
    dst_history: HashMap<String, Vec<TimestampMs>>,
    /// Recent outbound bytes: (time, amount) within the exfil window.
    out_window: Vec<(TimestampMs, u64)>,
    /// Time of the last inbound media (the zero-click door).
    last_media: Option<TimestampMs>,
    /// Whether Accessibility is active for this app.
    has_accessibility: bool,
    /// Sensitive permissions already granted.
    sensitive_perms: HashSet<String>,
    /// Destinations seen before (so "new destination" is only counted once).
    seen_dsts: HashSet<String>,
    /// Keys of findings already raised, to avoid double-scoring.
    raised: HashSet<String>,
    /// Whether the exfil alarm is currently "armed" (anti-spam).
    exfil_armed: bool,
    /// All findings for this app, accumulating.
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
            // The exfil alarm is "armed" from the start; it disarms after firing,
            // then re-arms once traffic subsides (anti-spam).
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

    /// Run the engine over a batch of observations. Returns all findings in the
    /// order they were raised (useful for demos & logs).
    pub fn run(&mut self, observations: &[Observation]) -> Vec<Finding> {
        let mut all = Vec::new();
        for obs in observations {
            all.extend(self.process(obs.clone()));
        }
        all
    }

    /// Process a single observation. Returns the NEW findings it triggers.
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
                let detail = format!("New app '{}' installed. Worth watching briefly.", app);
                vec![self.raise(&app, ts, "new_app", "New app installed", detail, w)]
            }
            Observation::Permission {
                ts,
                app,
                permission,
            } => self.on_permission(ts, app, permission),
            Observation::Accessibility { ts, app } => self.on_accessibility(ts, app),
        }
    }

    /// Collect per-app verdicts, sorted most dangerous first.
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

    // ---- handling each observation kind --------------------------------

    #[allow(clippy::too_many_arguments)]
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

        // 1) Match IoC (most decisive). Check IP then domain.
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
                    "Connection to a known malicious indicator: {} ({}{}).",
                    value,
                    if label.is_empty() { "no label" } else { &label },
                    if source.is_empty() {
                        String::new()
                    } else {
                        format!(", source: {}", source)
                    }
                );
                findings.push(self.raise(&app, ts, "ioc_match", "IoC list match", detail, w));
            }
        }

        // 2) Zero-click follow-up: a NEW external connection shortly after media.
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
                        "'{}' received media, then {}s later opened a new connection to {} \
                         (external, never contacted before). This is a classic zero-click pattern.",
                        app,
                        gap / 1000,
                        dst_ip
                    );
                    findings.push(self.raise(
                        &app,
                        ts,
                        "zeroclick_followup",
                        "Zero-click follow-up pattern",
                        detail,
                        w,
                    ));
                }
            }
        }

        // 3) New external destination from a background app.
        if external && app_background {
            let key = format!("unknown_dst|{}", dst_key);
            if !self.app_mut(&app).seen_dsts.contains(&dst_key)
                && self.app_mut(&app).raised.insert(key)
            {
                let w = self.config.weights.unknown_destination;
                let detail = format!(
                    "Background app '{}' contacted an unknown external destination: {}:{}.",
                    app, dst_ip, dst_port
                );
                findings.push(self.raise(
                    &app,
                    ts,
                    "unknown_destination",
                    "Unknown destination (background app)",
                    detail,
                    w,
                ));
            }
        }

        // Record the destination as seen (after the "new" rules were evaluated).
        self.app_mut(&app).seen_dsts.insert(dst_key.clone());

        // 4) Beacon detection: periodic, regular connections to the same destination.
        if let Some(f) = self.check_beacon(ts, &app, &dst_key, &dst_ip) {
            findings.push(f);
        }

        // 5) Exfiltration: spike of outbound bytes from a background app.
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
            return None; // already raised for this destination
        }
        let w = cfg.weights.beaconing;
        let detail = format!(
            "Repeated, highly regular connections to {} every ~{}s (variation {:.0}%). \
             A 'phone home' (beacon) pattern typical of spyware C2.",
            dst_ip,
            (mean / 1000.0).round() as u64,
            cv * 100.0
        );
        let f = finding(app, ts, "beaconing", "Beacon pattern detected", detail, w);
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
        // Drop entries outside the window.
        let lo = ts.saturating_sub(cfg.exfil_window_ms);
        st.out_window.retain(|(t, _)| *t >= lo);
        let total: u64 = st.out_window.iter().map(|(_, b)| *b).sum();

        if total >= cfg.exfil_threshold_bytes && app_background {
            if st.exfil_armed {
                st.exfil_armed = false; // one alarm per spike
                let w = cfg.weights.exfil_volume;
                let detail = format!(
                    "Background app '{}' sent ~{} KB out to {} within {}s. \
                     Indication of data exfiltration.",
                    app,
                    total / 1024,
                    dst_ip,
                    cfg.exfil_window_ms / 1000
                );
                let f = finding(app, ts, "exfil_volume", "Outbound data spike", detail, w);
                st.findings.push(f.clone());
                return Some(f);
            }
        } else if total < cfg.exfil_threshold_bytes {
            st.exfil_armed = true; // re-arm once traffic subsides
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

    /// Accessibility + sensitive permissions = classic Android spyware combo.
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
                "'{}' uses an Accessibility service AND holds sensitive permissions [{}]. \
                 This combination is very common in spyware (screen reading + eavesdropping).",
                app,
                list.join(", ")
            );
            return vec![self.raise(
                app,
                ts,
                "accessibility_abuse",
                "Accessibility abuse",
                detail,
                w,
            )];
        }
        Vec::new()
    }

    // ---- internal helpers ----------------------------------------------

    fn app_mut(&mut self, app: &str) -> &mut AppState {
        self.apps.entry(app.to_string()).or_default()
    }

    /// Build a finding, store it in the app state, and return a copy.
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

/// Build a single Finding (without touching any state).
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

/// Compute the mean interval and coefficient of variation of a sorted time
/// series. Returns None if there are fewer than 2 points or the mean is zero.
fn interval_stats(times: &[TimestampMs]) -> Option<(f64, f64)> {
    if times.len() < 2 {
        return None;
    }
    let mut diffs: Vec<f64> = times
        .windows(2)
        .map(|w| (w[1].saturating_sub(w[0])) as f64)
        .collect();
    // Ignore zero intervals (duplicate events) so they don't skew the stats.
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
            label: "test C2".to_string(),
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
        // 5 connections exactly 60s apart to the same destination → beacon.
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
            ts: 40_000, // 30s after media
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
        // Normal app in the foreground, reasonable connection, not regularly repeated.
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
