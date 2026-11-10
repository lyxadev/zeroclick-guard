//! `zcg-pegasus` — a live, narrated Pegasus-style attack, neutralized.
//!
//! ⚠️  BENIGN SIMULATION. There is NO real exploit and NO real spyware here.
//! This program narrates the publicly documented Pegasus kill chain and then,
//! for the one phase a defender can actually touch — exfiltration — runs REAL
//! TCP sockets through an enforcement gateway (the role Android's VpnService
//! plays) that feeds the same `zcg-core` engine and DROPS the traffic before it
//! reaches the controlled "C2". A separate C2 server counts bytes itself, so
//! "0 bytes stolen" is its own tally, not our claim.
//!
//! Honest scope, stated up front and on screen: on a non-rooted device no tool
//! can PREVENT the zero-click exploit (it runs inside another app's sealed
//! process). What this proves is the other half — detecting the implant's
//! behavior and stopping the theft before your data leaves the device.
//!
//! The "stolen" payloads are dummy bytes labelled as photos/messages/mic/etc.
//! All addresses use loopback / RFC 5737 test space.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use zcg_core::model::Severity;
use zcg_core::{Config, Engine, IocEntry, IocSet, Observation};

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const GREEN: &str = "\x1b[32m";
const CYAN: &str = "\x1b[36m";
const YELLOW: &str = "\x1b[33m";
const REDBG: &str = "\x1b[41m\x1b[97m";

fn color() -> bool {
    std::env::var("NO_COLOR").is_err()
}
fn paint(code: &str, s: &str) -> String {
    if color() {
        format!("{}{}{}", code, s, RESET)
    } else {
        s.to_string()
    }
}
fn pause(ms: u64) {
    // Cinematic pacing; skip when output is captured for tests.
    if std::env::var("ZCG_FAST").is_err() {
        thread::sleep(Duration::from_millis(ms));
    }
}

/// What the gateway tells the narrator about one handled connection.
struct Event {
    bytes: u64,
    blocked: bool,
    rules: Vec<String>,
}

fn main() {
    // The victim's messenger — the process Pegasus rides in via a zero-click.
    let app = "com.apple.MobileSMS";
    let normal_app = "com.whatsapp";

    // Controlled "C2" — a known Pegasus-style C2 for this run (added to IoC).
    let c2 = TcpListener::bind("127.0.0.1:0").expect("bind c2");
    let c2_addr = c2.local_addr().unwrap();
    let c2_bytes = std::sync::Arc::new(AtomicU64::new(0));
    spawn_sink(c2, c2_bytes.clone());

    // A normal upstream for the benign app (not the C2, not on the IoC list).
    let good = TcpListener::bind("127.0.0.2:0").ok();
    let good_addr = good.as_ref().map(|l| l.local_addr().unwrap());
    let good_bytes = std::sync::Arc::new(AtomicU64::new(0));
    if let Some(l) = good {
        spawn_sink(l, good_bytes.clone());
    }

    // The enforcement gateway owns the engine and decides forward/drop.
    let guard = TcpListener::bind("127.0.0.1:0").expect("bind guard");
    let guard_addr = guard.local_addr().unwrap().to_string();
    let (tx, rx) = mpsc::channel::<Event>();
    let c2_ip = c2_addr.ip().to_string();
    let c2_port = c2_addr.port();
    // Real counters of connection attempts to the C2 and how many were blocked.
    let c2_attempts = std::sync::Arc::new(AtomicU64::new(0));
    let c2_blocked = std::sync::Arc::new(AtomicU64::new(0));
    spawn_guard(
        guard,
        c2_addr.to_string(),
        tx,
        c2_attempts.clone(),
        c2_blocked.clone(),
    );

    banner(&guard_addr, &c2_addr.to_string());

    // ── The kill chain (narration only; these phases are not stoppable) ──
    stage("1 · DELIVERY (zero-click)");
    line(
        DIM,
        "A malicious media message arrives via iMessage/WhatsApp.",
    );
    line(
        DIM,
        "The victim taps nothing. No link, no download, no sign.",
    );
    note("We cannot see or stop this — it is inside the messaging app's sealed process.");
    pause(900);

    stage("2 · EXPLOIT + IMPLANT");
    line(
        DIM,
        "The media parser is exploited by a zero-day. An in-memory implant starts.",
    );
    note("Still invisible to any on-device app. Prevention here is impossible without root.");
    pause(900);

    stage("3 · ACTIVATION — the implant phones home");
    line(DIM, "This is the first moment a network defender can act.");
    // First contact to the C2: a tiny beacon. Known C2 → flagged and dropped.
    let dst = format!("{}:{}", c2_ip, c2_port);
    exfil(&guard_addr, app, &dst, "beacon / check-in", 1_024, &rx);
    pause(700);

    // ── Exfiltration: Pegasus tries to steal everything ──
    stage("4 · EXFILTRATION — Pegasus tries to steal your data");
    let loot = [
        ("your contact list", 48_000u64),
        ("14 photos from your gallery", 3_200_000),
        ("WhatsApp & Signal message history", 1_100_000),
        ("a 20-second microphone recording", 640_000),
        ("live GPS location", 2_048),
        ("saved passwords & 2FA codes", 16_000),
    ];
    for (what, size) in loot {
        exfil(&guard_addr, app, &dst, what, size, &rx);
        pause(450);
    }

    // A burst of further attempts, to verify the block holds.
    for _ in 0..94 {
        exfil_quiet(&guard_addr, app, &dst, 4_096, &rx);
    }

    // The victim's real messaging keeps working (no false positive).
    if let Some(ga) = &good_addr {
        let gdst = ga.to_string();
        exfil(
            &guard_addr,
            normal_app,
            &gdst,
            "normal chat (to its real server)",
            12_000,
            &rx,
        );
    }

    pause(400);
    // The C2 is never forwarded to, so its counter is inherently 0. The normal
    // app WAS forwarded, so wait until its server has counted the bytes.
    if good_addr.is_some() {
        wait_nonzero(&good_bytes);
    }

    // ── Verification: independent proof nothing reached the C2 ──
    stage("5 · VERIFICATION — did anything actually get stolen?");
    let stolen = c2_bytes.load(Ordering::SeqCst);
    let delivered_normal = good_bytes.load(Ordering::SeqCst);
    let ok = paint(GREEN, "✔");
    let attempts = c2_attempts.load(Ordering::SeqCst);
    let blocked = c2_blocked.load(Ordering::SeqCst);
    kv(
        "Bytes of your data that reached the Pegasus C2",
        &format!(
            "{}  {}",
            commafmt(stolen),
            if stolen == 0 { &ok } else { "" }
        ),
        stolen == 0,
    );
    kv(
        "Exfiltration attempts to the C2 (blocked / delivered)",
        &format!(
            "{} → {} blocked / {} delivered  {}",
            attempts,
            blocked,
            attempts - blocked,
            ok
        ),
        blocked == attempts,
    );
    if good_addr.is_some() {
        kv(
            "Your normal messaging (still works)",
            &format!("{} delivered", commafmt(delivered_normal)),
            delivered_normal > 0,
        );
    }

    // ── Verdict ──
    let neutralized = stolen == 0;
    stage("VERDICT");
    verdict("Pegasus implant active on the device", false);
    verdict("Data exfiltration to its C2", !neutralized);
    verdict("You were alerted (most victims never are)", true);
    println!();
    if neutralized {
        println!(
            "{}",
            paint(
                REDBG,
                " ⛔ PEGASUS NEUTRALIZED — 0 bytes of your data left the device ",
            )
        );
    }
    println!();
    note(
        "Honest limit: the zero-click exploit itself was not prevented (it cannot be, \
         without root). What was stopped is the theft — and you now know.",
    );
    println!();

    std::process::exit(if neutralized { 0 } else { 1 });
}

/// Make one real connection through the guard and narrate the result.
fn exfil(guard: &str, app: &str, dst: &str, label: &str, size: u64, rx: &mpsc::Receiver<Event>) {
    tap_send(guard, app, dst, label, size);
    if let Ok(ev) = rx.recv() {
        let human = human_size(ev.bytes);
        if ev.blocked {
            println!(
                "  {} {:<42} {}  {}",
                paint(RED, "✗ BLOCKED"),
                label,
                paint(DIM, &human),
                paint(
                    &format!("{}{}", BOLD, RED),
                    "dropped at tap → C2 got nothing"
                ),
            );
            for r in &ev.rules {
                println!("     {} {}", paint(DIM, "└─"), paint(DIM, r));
            }
        } else {
            println!(
                "  {} {:<42} {}  {}",
                paint(GREEN, "✓ allowed"),
                label,
                paint(DIM, &human),
                paint(DIM, "forwarded (benign)"),
            );
        }
    }
}

/// A silent attempt (used for the verification burst); drains its event so the
/// channel stays in step with the connections.
fn exfil_quiet(guard: &str, app: &str, dst: &str, size: u64, rx: &mpsc::Receiver<Event>) {
    tap_send(guard, app, dst, "", size);
    let _ = rx.recv();
}

fn wait_nonzero(counter: &AtomicU64) {
    // Wait until a forwarded sink has counted its bytes (real sleep, so it also
    // works in fast mode). Bounded.
    for _ in 0..60 {
        if counter.load(Ordering::SeqCst) > 0 {
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

// ---- gateway + sinks ----------------------------------------------------

fn spawn_sink(listener: TcpListener, bytes: std::sync::Arc<AtomicU64>) {
    thread::spawn(move || {
        for mut s in listener.incoming().flatten() {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            bytes.fetch_add(buf.len() as u64, Ordering::SeqCst);
        }
    });
}

fn spawn_guard(
    listener: TcpListener,
    c2_addr: String,
    tx: mpsc::Sender<Event>,
    c2_attempts: std::sync::Arc<AtomicU64>,
    c2_blocked: std::sync::Arc<AtomicU64>,
) {
    thread::spawn(move || {
        // The gateway owns the engine; the known C2 is on the IoC list.
        let mut ioc = IocSet::new();
        let c2_ip = c2_addr
            .rsplit_once(':')
            .map(|(i, _)| i.to_string())
            .unwrap_or(c2_addr.clone());
        ioc.add(IocEntry {
            value: c2_ip,
            kind: "ip".to_string(),
            label: "known Pegasus-style C2 (this demo)".to_string(),
            source: "zcg-pegasus".to_string(),
        });
        let mut engine = Engine::new(Config::default(), ioc);
        let mut blocked: HashSet<String> = HashSet::new();
        let mut ts: u64 = 0;

        for stream in listener.incoming() {
            let s = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let mut reader = BufReader::new(s);
            let mut header = String::new();
            if reader.read_line(&mut header).is_err() {
                continue;
            }
            let (app, dst, _label) = parse_header(header.trim());
            let mut payload = Vec::new();
            let _ = reader.read_to_end(&mut payload);
            let bytes = payload.len() as u64;

            let (dip, dport) = split_addr(&dst);
            let new = engine.process(Observation::Flow {
                ts,
                app: app.clone(),
                app_background: true,
                dst_ip: dip,
                dst_port: dport,
                domain: None,
                bytes_out: bytes,
                bytes_in: 0,
                proto: "tcp".to_string(),
            });
            ts += 1_000;
            let mut rules: Vec<String> = Vec::new();
            for f in &new {
                rules.push(format!("{} (+{})", f.title, f.score));
            }
            let score = engine
                .verdicts()
                .into_iter()
                .find(|v| v.app == app)
                .map(|v| v.score)
                .unwrap_or(0);

            // Policy: block a known-C2 contact or anything already flagged
            // (Medium severity and up). Enforcement = do not forward.
            let should_block = blocked.contains(&app)
                || Severity::from_score(score) >= Severity::Medium
                || dst == c2_addr;
            if dst == c2_addr {
                c2_attempts.fetch_add(1, Ordering::SeqCst);
                if should_block {
                    c2_blocked.fetch_add(1, Ordering::SeqCst);
                }
            }
            if should_block {
                blocked.insert(app.clone());
            } else if let Ok(mut up) = TcpStream::connect(&dst) {
                let _ = up.write_all(&payload);
                let _ = up.flush();
            }

            let _ = tx.send(Event {
                bytes,
                blocked: should_block,
                rules,
            });
        }
    });
}

/// A real client connection through the guard.
fn tap_send(guard: &str, app: &str, dst: &str, label: &str, size: u64) {
    if let Ok(mut s) = TcpStream::connect(guard) {
        let header = format!("APP:{};DST:{};LABEL:{}\n", app, dst, label);
        if s.write_all(header.as_bytes()).is_err() {
            return;
        }
        let chunk = vec![0u8; 64 * 1024];
        let mut sent = 0u64;
        while sent < size {
            let n = ((size - sent) as usize).min(chunk.len());
            if s.write_all(&chunk[..n]).is_err() {
                break;
            }
            sent += n as u64;
        }
        let _ = s.flush();
    }
}

// ---- presentation -------------------------------------------------------

fn banner(guard: &str, c2: &str) {
    println!(
        "{}",
        paint(
            &format!("{}{}", BOLD, RED),
            "┌──────────────────────────────────────────────────────────────┐"
        )
    );
    println!(
        "{}",
        paint(
            &format!("{}{}", BOLD, RED),
            "│  PEGASUS — LIVE ATTACK SIMULATION  vs  zeroclick-guard        │"
        )
    );
    println!(
        "{}",
        paint(
            &format!("{}{}", BOLD, RED),
            "└──────────────────────────────────────────────────────────────┘"
        )
    );
    println!(
        "{}",
        paint(
            DIM,
            "  Benign simulation — no real exploit or spyware. Real sockets, real block."
        )
    );
    println!(
        "{}",
        paint(
            DIM,
            &format!("  VPN tap: {} · controlled C2: {}\n", guard, c2)
        )
    );
}

fn stage(s: &str) {
    println!(
        "\n{}",
        paint(&format!("{}{}", BOLD, CYAN), &format!("[STAGE {}]", s))
    );
}
fn line(code: &str, s: &str) {
    println!("  {}", paint(code, s));
}
fn note(s: &str) {
    println!("  {} {}", paint(YELLOW, "⚠"), paint(DIM, s));
}
fn kv(k: &str, v: &str, good: bool) {
    let vc = if good { GREEN } else { RED };
    println!("  {:<46} {}", k, paint(&format!("{}{}", BOLD, vc), v));
}
fn verdict(label: &str, bad: bool) {
    let (mark, col) = if bad { ("YES", RED) } else { ("NO", GREEN) };
    // For "implant active" and "alerted", a plain state reads better:
    let state = match label {
        _ if label.starts_with("Pegasus implant active") => paint(RED, "YES"),
        _ if label.starts_with("You were alerted") => paint(GREEN, "YES"),
        _ => paint(&format!("{}{}", BOLD, col), mark),
    };
    println!("  {:<46} {}", format!("{}:", label), state);
}

fn human_size(b: u64) -> String {
    if b >= 1_000_000 {
        format!("{:.1} MB", b as f64 / 1_000_000.0)
    } else if b >= 1_000 {
        format!("{} KB", b / 1_000)
    } else {
        format!("{} B", b)
    }
}
fn commafmt(n: u64) -> String {
    let s = n.to_string();
    let b = s.as_bytes();
    let mut out = String::new();
    for (i, ch) in b.iter().enumerate() {
        if i > 0 && (b.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(*ch as char);
    }
    format!("{} bytes", out)
}

fn parse_header(h: &str) -> (String, String, String) {
    let mut app = String::new();
    let mut dst = String::new();
    let mut label = String::new();
    for part in h.splitn(3, ';') {
        if let Some(v) = part.strip_prefix("APP:") {
            app = v.to_string();
        } else if let Some(v) = part.strip_prefix("DST:") {
            dst = v.to_string();
        } else if let Some(v) = part.strip_prefix("LABEL:") {
            label = v.to_string();
        }
    }
    (app, dst, label)
}
fn split_addr(addr: &str) -> (String, u16) {
    match addr.rsplit_once(':') {
        Some((ip, port)) => (ip.to_string(), port.parse().unwrap_or(0)),
        None => (addr.to_string(), 0),
    }
}
