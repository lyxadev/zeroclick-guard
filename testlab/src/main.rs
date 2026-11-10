//! `zcg-testlab` — a BENIGN behavior simulator.
//!
//! ⚠️  IMPORTANT: this program contains NO real exploit, payload, or spyware.
//! It only PRINTS observation records (JSONL) that MIMIC the *behavior
//! patterns* of an attack — periodic connections, data spikes, etc. — so the
//! detection engine can be tested and demoed honestly and repeatably.
//!
//! Think of it as a fire drill: the smoke is simulated, but the alarm being
//! tested (the zeroclick-guard engine) is 100% real.
//!
//! Usage:
//!   zcg-testlab <scenario>
//! Scenarios:
//!   zeroclick   Zero-click attack pattern (media in → C2 → beacon → exfil).
//!   spyware     Spyware "installed" (Accessibility + sensitive perms + C2).
//!   brutal      Coordinated APT-style attack across multiple apps at once.
//!   benign      Normal app behavior (must NOT trigger any alarm).
//!
//! Demo example (pipe straight into the engine):
//!   zcg-testlab brutal | zcg --ioc examples/ioc-testlab.json --replay

#![allow(clippy::vec_init_then_push)]

use zcg_core::Observation;

fn main() {
    let scenario = std::env::args().nth(1).unwrap_or_default();
    let obs = match scenario.as_str() {
        "zeroclick" => scenario_zeroclick(),
        "spyware" => scenario_spyware(),
        "benign" => scenario_benign(),
        "brutal" => scenario_brutal(),
        // Behavioral profiles inspired by publicly reported characteristics of
        // known spyware families. These are BENIGN simulations (RFC 5737 test
        // endpoints), NOT the real malware. The proof is that the engine flags
        // the documented *behavior*, reproducibly.
        "pegasus" => family_zeroclick("com.whatsapp", "203.0.113.10"),
        "triangulation" => family_zeroclick("com.apple.mobilesms", "203.0.113.70"),
        "predator" => family_installed(
            "com.android.system.service",
            "203.0.113.20",
            &["RECORD_AUDIO", "CAMERA", "ACCESS_FINE_LOCATION", "READ_SMS"],
        ),
        "finfisher" => family_installed(
            "com.adobe.flashplayer",
            "203.0.113.30",
            &["RECORD_AUDIO", "CAMERA", "READ_CONTACTS", "READ_CALL_LOG"],
        ),
        "hermit" => family_installed(
            "com.kaspersky.update",
            "203.0.113.40",
            &["RECORD_AUDIO", "READ_SMS", "ACCESS_FINE_LOCATION"],
        ),
        "chrysaor" => family_installed(
            "com.network.android",
            "203.0.113.60",
            &["RECORD_AUDIO", "READ_SMS", "READ_CONTACTS"],
        ),
        "stalkerware" => family_installed(
            "com.family.locator.pro",
            "198.51.100.50",
            &[
                "ACCESS_FINE_LOCATION",
                "READ_SMS",
                "READ_CALL_LOG",
                "RECORD_AUDIO",
            ],
        ),
        _ => {
            eprintln!(
                "zeroclick-guard benign behavior simulator\n\n\
                 scenarios:\n  \
                 zeroclick | spyware | brutal | benign\n  \
                 family profiles: pegasus | predator | finfisher | hermit |\n  \
                 chrysaor | triangulation | stalkerware\n\n\
                 example: zcg-testlab brutal | zcg --ioc examples/ioc-testlab.json --replay\n\n\
                 Note: this only prints mock observations (JSONL). There is no real\n\
                 exploit or spyware inside it. Family names denote BEHAVIORAL\n\
                 profiles inspired by public reporting, not the actual malware."
            );
            std::process::exit(if scenario.is_empty() { 0 } else { 1 });
        }
    };
    for o in obs {
        // One JSON object per line (JSONL).
        println!(
            "{}",
            serde_json::to_string(&o).expect("serialize observation")
        );
    }
}

/// Zero-click scenario: WhatsApp receives media, then the "compromised
/// process" calls a C2, sends data, then beacons periodically.
fn scenario_zeroclick() -> Vec<Observation> {
    let app = "com.whatsapp";
    let c2 = "203.0.113.50"; // TEST-NET-3 (RFC 5737) — a test address, not a real host
    let mut v = Vec::new();

    // Normal traffic first: WhatsApp talking to its own servers.
    v.push(flow(
        2_000,
        app,
        false,
        "198.51.100.10",
        443,
        Some("whatsapp.example"),
        1_200,
        8_000,
    ));

    // t=10s: media auto-received (the zero-click door). Not yet suspicious.
    v.push(Observation::Media {
        ts: 10_000,
        app: app.to_string(),
        bytes: 920_000,
    });

    // t=40s: 30s after media, a NEW connection to an external C2 (zero-click follow-up).
    v.push(flow(40_000, app, true, c2, 443, None, 2_400, 200));

    // t=50s: outbound data spike (exfiltrating contacts/messages).
    v.push(flow(50_000, app, true, c2, 443, None, 3_200_000, 400));

    // Beacon: "phones home" every 60s exactly to the same C2.
    for i in 1..=5u64 {
        v.push(flow(
            40_000 + i * 60_000,
            app,
            true,
            c2,
            443,
            None,
            800,
            120,
        ));
    }

    v
}

/// Installed-spyware scenario: an app in disguise requests Accessibility +
/// sensitive permissions, then beacons to a C2.
fn scenario_spyware() -> Vec<Observation> {
    let app = "com.senter.flashlight"; // a suspicious "flashlight app"
    let c2 = "203.0.113.77";
    let mut v = Vec::new();

    v.push(Observation::AppInstalled {
        ts: 1_000,
        app: app.to_string(),
    });
    v.push(Observation::Permission {
        ts: 2_000,
        app: app.to_string(),
        permission: "RECORD_AUDIO".to_string(),
    });
    v.push(Observation::Permission {
        ts: 2_500,
        app: app.to_string(),
        permission: "READ_SMS".to_string(),
    });
    v.push(Observation::Permission {
        ts: 3_000,
        app: app.to_string(),
        permission: "ACCESS_FINE_LOCATION".to_string(),
    });
    v.push(Observation::Accessibility {
        ts: 3_500,
        app: app.to_string(),
    });

    // Beacon to C2 every 90s.
    for i in 0..5u64 {
        v.push(flow(
            10_000 + i * 90_000,
            app,
            true,
            c2,
            8443,
            None,
            1_500,
            300,
        ));
    }
    v
}

/// BRUTAL scenario: a coordinated, APT-style attack on ONE victim at once.
/// Three vectors run in parallel — zero-click in 2 messengers + spyware
/// disguised as a "system update". Built for a dramatic demo; the defender is
/// still the real engine. All addresses use RFC 5737 test space (not real hosts).
fn scenario_brutal() -> Vec<Observation> {
    let mut v = Vec::new();

    // ── Normal traffic first, so the contrast lands ──
    v.push(flow(
        1_000,
        "com.android.chrome",
        false,
        "203.0.113.1",
        443,
        Some("news.example"),
        800,
        60_000,
    ));
    v.push(flow(
        3_000,
        "com.whatsapp",
        false,
        "198.51.100.10",
        443,
        Some("whatsapp.example"),
        1_000,
        7_000,
    ));
    v.push(flow(
        4_500,
        "org.telegram.messenger",
        false,
        "198.51.100.20",
        443,
        Some("telegram.example"),
        900,
        5_000,
    ));

    // ── VECTOR 1: zero-click via WhatsApp ──
    let wa_c2 = "203.0.113.50";
    v.push(Observation::Media {
        ts: 12_000,
        app: "com.whatsapp".into(),
        bytes: 980_000,
    });
    v.push(flow(
        34_000,
        "com.whatsapp",
        true,
        wa_c2,
        443,
        Some("evil.example"),
        2_600,
        180,
    )); // zero-click follow-up + IoC
    v.push(flow(
        44_000,
        "com.whatsapp",
        true,
        wa_c2,
        443,
        None,
        5_400_000,
        300,
    )); // large exfil
    for i in 1..=5u64 {
        v.push(flow(
            34_000 + i * 60_000,
            "com.whatsapp",
            true,
            wa_c2,
            443,
            None,
            900,
            120,
        )); // beacon
    }

    // ── VECTOR 2: zero-click via Telegram to a different C2 ──
    let tg_c2 = "203.0.113.99";
    v.push(Observation::Media {
        ts: 20_000,
        app: "org.telegram.messenger".into(),
        bytes: 1_240_000,
    });
    v.push(flow(
        41_000,
        "org.telegram.messenger",
        true,
        tg_c2,
        8443,
        None,
        3_100,
        240,
    )); // zero-click follow-up + IoC
    v.push(flow(
        55_000,
        "org.telegram.messenger",
        true,
        tg_c2,
        8443,
        None,
        2_800_000,
        260,
    )); // exfil
    for i in 1..=4u64 {
        v.push(flow(
            41_000 + i * 75_000,
            "org.telegram.messenger",
            true,
            tg_c2,
            8443,
            None,
            700,
            90,
        )); // beacon
    }

    // ── VECTOR 3: spyware disguised as a "system update" ──
    let spy = "com.system.update.helper";
    let spy_c2 = "198.51.100.200";
    v.push(Observation::AppInstalled {
        ts: 8_000,
        app: spy.into(),
    });
    v.push(Observation::Permission {
        ts: 9_000,
        app: spy.into(),
        permission: "RECORD_AUDIO".into(),
    });
    v.push(Observation::Permission {
        ts: 9_500,
        app: spy.into(),
        permission: "READ_SMS".into(),
    });
    v.push(Observation::Permission {
        ts: 10_000,
        app: spy.into(),
        permission: "CAMERA".into(),
    });
    v.push(Observation::Permission {
        ts: 10_500,
        app: spy.into(),
        permission: "ACCESS_FINE_LOCATION".into(),
    });
    v.push(Observation::Accessibility {
        ts: 11_000,
        app: spy.into(),
    });
    v.push(flow(
        15_000,
        spy,
        true,
        spy_c2,
        443,
        Some("evil.example"),
        4_200,
        300,
    )); // IoC domain
    v.push(flow(60_000, spy, true, spy_c2, 443, None, 6_800_000, 400)); // massive exfil
    for i in 1..=6u64 {
        v.push(flow(
            15_000 + i * 60_000,
            spy,
            true,
            spy_c2,
            443,
            None,
            1_100,
            150,
        )); // beacon
    }

    v
}

/// Benign scenario: must NOT trigger any alarm (false-positive test).
fn scenario_benign() -> Vec<Observation> {
    let mut v = Vec::new();

    // Browser in the foreground, reasonable and irregular connections to various CDNs.
    let chrome = "com.android.chrome";
    v.push(flow(
        1_000,
        chrome,
        false,
        "203.0.113.1",
        443,
        Some("cdn.example"),
        900,
        45_000,
    ));
    v.push(flow(
        4_300,
        chrome,
        false,
        "203.0.113.2",
        443,
        Some("img.example"),
        500,
        120_000,
    ));
    v.push(flow(
        9_800,
        chrome,
        false,
        "203.0.113.3",
        443,
        Some("api.example"),
        700,
        15_000,
    ));
    v.push(flow(
        21_000,
        chrome,
        false,
        "203.0.113.1",
        443,
        Some("cdn.example"),
        400,
        30_000,
    ));

    // WhatsApp receives media, then talks to the SAME server it always does
    // (already known) — so NOT a zero-click follow-up. This shows our
    // correlation is about NEW destinations, not merely "a connection after media".
    let wa = "com.whatsapp";
    v.push(flow(
        5_000,
        wa,
        false,
        "198.51.100.10",
        443,
        Some("whatsapp.example"),
        1_000,
        6_000,
    ));
    v.push(Observation::Media {
        ts: 30_000,
        app: wa.to_string(),
        bytes: 400_000,
    });
    v.push(flow(
        33_000,
        wa,
        false,
        "198.51.100.10",
        443,
        Some("whatsapp.example"),
        1_200,
        5_000,
    ));

    // Music streaming app in the background, large data IN (normal), small data out.
    // Intervals are deliberately IRREGULAR (real streaming is bursty) → not a beacon.
    let music = "com.music.player";
    let music_times = [2_000u64, 18_000, 51_000, 133_000];
    for t in music_times {
        v.push(flow(
            t,
            music,
            true,
            "203.0.113.9",
            443,
            Some("stream.example"),
            300,
            250_000,
        ));
    }

    v
}

/// Generic zero-click behavioral profile: normal traffic → inbound media →
/// NEW external C2 within the window → exfil → regular beacon. Models families
/// like Pegasus / Triangulation (delivery differs; the *behavior* is detected).
fn family_zeroclick(app: &str, c2: &str) -> Vec<Observation> {
    let mut v = Vec::new();
    // Known-good baseline traffic to the app's real servers.
    v.push(flow(
        2_000,
        app,
        false,
        "198.51.100.10",
        443,
        Some("cdn.example"),
        1_000,
        9_000,
    ));
    // Inbound media (the zero-click door) — not yet suspicious on its own.
    v.push(Observation::Media {
        ts: 10_000,
        app: app.to_string(),
        bytes: 1_050_000,
    });
    // Phone-home beacon to a brand-new external C2, perfectly regular every 60s.
    // The first tick (38s after media) is also the zero-click follow-up.
    for i in 0..6u64 {
        let ts = 38_000 + i * 60_000;
        // The 2nd tick carries the big exfiltration payload.
        let out = if i == 1 { 3_600_000 } else { 850 };
        v.push(flow(ts, app, true, c2, 443, None, out, 110));
    }
    v
}

/// Generic installed-spyware behavioral profile: app installed → requests
/// sensitive permissions → enables Accessibility → contacts C2 → exfil →
/// regular beacon. Models families like Predator / FinFisher / Hermit /
/// Chrysaor and commercial stalkerware.
fn family_installed(app: &str, c2: &str, perms: &[&str]) -> Vec<Observation> {
    let mut v = Vec::new();
    v.push(Observation::AppInstalled {
        ts: 1_000,
        app: app.to_string(),
    });
    let mut t = 2_000;
    for p in perms {
        v.push(Observation::Permission {
            ts: t,
            app: app.to_string(),
            permission: p.to_string(),
        });
        t += 500;
    }
    v.push(Observation::Accessibility {
        ts: t,
        app: app.to_string(),
    });
    // Regular beacon to a new external C2 every 70s; first tick = first contact.
    // The 2nd tick carries the big exfiltration payload.
    for i in 0..7u64 {
        let ts = 14_000 + i * 70_000;
        let out = if i == 1 { 4_500_000 } else { 1_000 };
        v.push(flow(ts, app, true, c2, 8443, None, out, 140));
    }
    v
}

/// Compact helper to build a Flow observation.
#[allow(clippy::too_many_arguments)]
fn flow(
    ts: u64,
    app: &str,
    background: bool,
    dst_ip: &str,
    dst_port: u16,
    domain: Option<&str>,
    bytes_out: u64,
    bytes_in: u64,
) -> Observation {
    Observation::Flow {
        ts,
        app: app.to_string(),
        app_background: background,
        dst_ip: dst_ip.to_string(),
        dst_port,
        domain: domain.map(|d| d.to_string()),
        bytes_out,
        bytes_in,
        proto: "tcp".to_string(),
    }
}
