//! `zcg-redteam` — an adversarial benchmark, scored in percentages.
//!
//! A "red team" launches a battery of Pegasus-style attacks at the real
//! `zcg-core` engine through an enforcement tap. Every attack runs on REAL TCP
//! sockets: when the engine decides to block, the bytes are NOT sent; otherwise
//! they are sent to a sink that counts them — that counter is the measured
//! "bytes stolen". We then score the defense in honest percentages.
//!
//! Two suites, kept separate on purpose:
//!   • CORE — the behaviors zeroclick-guard is built to catch (C2 beaconing,
//!     exfil spikes, zero-click follow-up, known IoCs). These must be caught.
//!   • EVASION — deliberate bypass attempts (low-and-slow, foreground exfil,
//!     jittered beacons). Some slip; we report the real gap rather than hide it.
//!
//! Plus a FALSE-POSITIVE suite of normal apps that must NOT be blocked.
//!
//! Benign simulation: no real exploit or spyware. The "stolen" bytes are dummy.
//! Reported destinations use RFC 5737 test ranges; the engine judges those
//! (as a VpnService would see the real external IP), while bytes are counted on
//! a loopback sink.
//!
//! Exit 0 only if: CORE detection = 100%, CORE exfiltration blocked ≥ 99%, and
//! false positives = 0%. The evasion suite is reported but does not gate.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
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

#[derive(Clone)]
enum Op {
    Flow {
        at_ms: u64,
        ip: &'static str,
        domain: Option<&'static str>,
        background: bool,
        bytes: u64,
    },
    Media {
        at_ms: u64,
    },
}

#[derive(Clone, Copy, PartialEq)]
enum Suite {
    Core,
    Evasion,
    Benign,
}

struct Attack {
    name: &'static str,
    suite: Suite,
    ops: Vec<Op>,
}

struct Outcome {
    detected: bool,
    attempted: u64,
    stolen: u64,
    blocked: bool, // true if blocking engaged at all (app flagged)
}

fn ioc_set() -> IocSet {
    let mut s = IocSet::new();
    s.add(IocEntry {
        value: "203.0.113.10".to_string(),
        kind: "ip".to_string(),
        label: "known C2".to_string(),
        source: "redteam".to_string(),
    });
    s.add(IocEntry {
        value: "evil.example".to_string(),
        kind: "domain".to_string(),
        label: "known C2 domain".to_string(),
        source: "redteam".to_string(),
    });
    s
}

/// Run one attack against a fresh engine, on real sockets. Returns the measured
/// outcome (bytes stolen are counted by an independent sink).
fn run_attack(attack: &Attack) -> Outcome {
    // Independent sink that counts everything that is actually forwarded.
    let sink = TcpListener::bind("127.0.0.1:0").expect("bind sink");
    let sink_addr = sink.local_addr().unwrap();
    let counter = Arc::new(AtomicU64::new(0));
    let c2 = counter.clone();
    thread::spawn(move || {
        for mut s in sink.incoming().flatten() {
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            c2.fetch_add(buf.len() as u64, Ordering::SeqCst);
        }
    });

    let mut engine = Engine::new(Config::default(), ioc_set());
    let app = "com.attacker.app";
    let mut blocked = false;
    let mut detected = false;
    let mut attempted = 0u64;

    let mut ops = attack.ops.clone();
    ops.sort_by_key(|o| match o {
        Op::Flow { at_ms, .. } | Op::Media { at_ms } => *at_ms,
    });

    for op in ops {
        match op {
            Op::Media { at_ms } => {
                engine.process(Observation::Media {
                    ts: at_ms,
                    app: app.to_string(),
                    bytes: 900_000,
                });
            }
            Op::Flow {
                at_ms,
                ip,
                domain,
                background,
                bytes,
            } => {
                attempted += bytes;
                engine.process(Observation::Flow {
                    ts: at_ms,
                    app: app.to_string(),
                    app_background: background,
                    dst_ip: ip.to_string(),
                    dst_port: 443,
                    domain: domain.map(|d| d.to_string()),
                    bytes_out: bytes,
                    bytes_in: 0,
                    proto: "tcp".to_string(),
                });
                let score = engine
                    .verdicts()
                    .into_iter()
                    .find(|v| v.app == app)
                    .map(|v| v.score)
                    .unwrap_or(0);
                if Severity::from_score(score) >= Severity::Medium {
                    detected = true;
                    blocked = true;
                }
                // Enforcement: forward only if not blocked.
                if !blocked {
                    send_real(&sink_addr.to_string(), bytes);
                }
            }
        }
    }

    // Let the sink finish counting.
    settle(&counter, attempted);
    Outcome {
        detected,
        attempted,
        stolen: counter.load(Ordering::SeqCst),
        blocked,
    }
}

fn send_real(addr: &str, bytes: u64) {
    if let Ok(mut s) = TcpStream::connect(addr) {
        let chunk = vec![0u8; 64 * 1024];
        let mut sent = 0u64;
        while sent < bytes {
            let n = ((bytes - sent) as usize).min(chunk.len());
            if s.write_all(&chunk[..n]).is_err() {
                break;
            }
            sent += n as u64;
        }
        let _ = s.flush();
    }
}

fn settle(counter: &AtomicU64, target_max: u64) {
    // Wait until the counter stops moving (bounded). target_max lets us return
    // early once everything attempted has been counted.
    let mut last = counter.load(Ordering::SeqCst);
    for _ in 0..60 {
        if last >= target_max {
            return;
        }
        thread::sleep(Duration::from_millis(15));
        let now = counter.load(Ordering::SeqCst);
        if now == last {
            return;
        }
        last = now;
    }
}

fn attacks() -> Vec<Attack> {
    let big = 3_000_000u64;
    let mut v = Vec::new();

    // ---- CORE: behaviors zeroclick-guard targets --------------------------
    v.push(Attack {
        name: "Known-C2 exfiltration",
        suite: Suite::Core,
        ops: vec![
            Op::Flow {
                at_ms: 0,
                ip: "203.0.113.10",
                domain: None,
                background: true,
                bytes: 800,
            },
            Op::Flow {
                at_ms: 2_000,
                ip: "203.0.113.10",
                domain: None,
                background: true,
                bytes: big,
            },
        ],
    });
    v.push(Attack {
        name: "Zero-click follow-up + exfil",
        suite: Suite::Core,
        ops: vec![
            Op::Media { at_ms: 0 },
            Op::Flow {
                at_ms: 30_000,
                ip: "203.0.113.21",
                domain: None,
                background: true,
                bytes: 800,
            },
            Op::Flow {
                at_ms: 40_000,
                ip: "203.0.113.21",
                domain: None,
                background: true,
                bytes: big,
            },
        ],
    });
    v.push(Attack {
        name: "Recon then exfil (unknown C2)",
        suite: Suite::Core,
        ops: vec![
            Op::Flow {
                at_ms: 0,
                ip: "203.0.113.30",
                domain: None,
                background: true,
                bytes: 800,
            },
            Op::Flow {
                at_ms: 5_000,
                ip: "203.0.113.30",
                domain: None,
                background: true,
                bytes: big,
            },
        ],
    });
    v.push(Attack {
        name: "Regular beacon + exfil",
        suite: Suite::Core,
        ops: {
            let mut ops = vec![];
            for i in 0..4u64 {
                ops.push(Op::Flow {
                    at_ms: i * 60_000,
                    ip: "203.0.113.40",
                    domain: None,
                    background: true,
                    bytes: 800,
                });
            }
            ops.push(Op::Flow {
                at_ms: 5 * 60_000,
                ip: "203.0.113.40",
                domain: None,
                background: true,
                bytes: big,
            });
            ops
        },
    });
    v.push(Attack {
        name: "Single large exfil spike",
        suite: Suite::Core,
        ops: vec![Op::Flow {
            at_ms: 0,
            ip: "203.0.113.50",
            domain: None,
            background: true,
            bytes: big,
        }],
    });
    v.push(Attack {
        name: "Beacon to known-bad domain",
        suite: Suite::Core,
        ops: vec![
            Op::Flow {
                at_ms: 0,
                ip: "198.51.100.9",
                domain: Some("evil.example"),
                background: true,
                bytes: 800,
            },
            Op::Flow {
                at_ms: 2_000,
                ip: "198.51.100.9",
                domain: Some("evil.example"),
                background: true,
                bytes: big,
            },
        ],
    });

    // ---- EVASION: deliberate bypass attempts (honest gaps) ----------------
    v.push(Attack {
        name: "Low-and-slow drip",
        suite: Suite::Evasion,
        ops: {
            // Chunks spread far apart so the 60s exfil window never fills.
            let mut ops = vec![];
            for i in 0..12u64 {
                ops.push(Op::Flow {
                    at_ms: i * 120_000,
                    ip: "203.0.113.61",
                    domain: None,
                    background: true,
                    bytes: 150_000,
                });
            }
            ops
        },
    });
    v.push(Attack {
        name: "Foreground exfil",
        suite: Suite::Evasion,
        ops: vec![Op::Flow {
            at_ms: 0,
            ip: "203.0.113.62",
            domain: None,
            background: false,
            bytes: big,
        }],
    });
    v.push(Attack {
        name: "Jittered beacon (no payload)",
        suite: Suite::Evasion,
        ops: {
            let offs = [0u64, 7_000, 51_000, 130_000, 400_000];
            offs.iter()
                .map(|&o| Op::Flow {
                    at_ms: o,
                    ip: "203.0.113.63",
                    domain: None,
                    background: true,
                    bytes: 1_200,
                })
                .collect()
        },
    });
    v.push(Attack {
        name: "Mimic-normal foreground",
        suite: Suite::Evasion,
        ops: {
            let offs = [0u64, 40_000, 95_000];
            offs.iter()
                .map(|&o| Op::Flow {
                    at_ms: o,
                    ip: "203.0.113.64",
                    domain: Some("cdn.example"),
                    background: false,
                    bytes: 2_000,
                })
                .collect()
        },
    });

    // ---- BENIGN: must NOT be blocked (false-positive check) ---------------
    v.push(Attack {
        name: "Browser (foreground)",
        suite: Suite::Benign,
        ops: {
            let offs = [0u64, 4_300, 9_800, 21_000];
            offs.iter()
                .map(|&o| Op::Flow {
                    at_ms: o,
                    ip: "203.0.113.70",
                    domain: Some("cdn.example"),
                    background: false,
                    bytes: 1_000,
                })
                .collect()
        },
    });
    v.push(Attack {
        name: "Music streaming (background)",
        suite: Suite::Benign,
        ops: {
            let offs = [0u64, 18_000, 51_000, 133_000];
            offs.iter()
                .map(|&o| Op::Flow {
                    at_ms: o,
                    ip: "203.0.113.71",
                    domain: Some("stream.example"),
                    background: true,
                    bytes: 300,
                })
                .collect()
        },
    });
    v.push(Attack {
        name: "Messenger to its own server",
        suite: Suite::Benign,
        ops: vec![
            Op::Flow {
                at_ms: 0,
                ip: "198.51.100.10",
                domain: Some("whatsapp.example"),
                background: false,
                bytes: 1_000,
            },
            Op::Flow {
                at_ms: 33_000,
                ip: "198.51.100.10",
                domain: Some("whatsapp.example"),
                background: false,
                bytes: 1_200,
            },
        ],
    });

    v
}

fn pct(n: f64, d: f64) -> f64 {
    if d == 0.0 {
        100.0
    } else {
        n / d * 100.0
    }
}

fn main() {
    let all = attacks();
    banner();

    let mut core_detected = 0usize;
    let mut core_total = 0usize;
    let mut core_attempted = 0u64;
    let mut core_stolen = 0u64;

    let mut ev_detected = 0usize;
    let mut ev_total = 0usize;
    let mut ev_attempted = 0u64;
    let mut ev_stolen = 0u64;

    let mut fp_blocked = 0usize;
    let mut fp_total = 0usize;

    section(
        "CORE ATTACKS",
        "the behaviors zeroclick-guard is built to catch",
    );
    for a in all.iter().filter(|a| a.suite == Suite::Core) {
        let o = run_attack(a);
        core_total += 1;
        core_attempted += o.attempted;
        core_stolen += o.stolen;
        if o.detected {
            core_detected += 1;
        }
        row_attack(a.name, &o);
    }

    section(
        "EVASION SUITE",
        "deliberate bypass attempts — real gaps, reported honestly",
    );
    for a in all.iter().filter(|a| a.suite == Suite::Evasion) {
        let o = run_attack(a);
        ev_total += 1;
        ev_attempted += o.attempted;
        ev_stolen += o.stolen;
        if o.detected {
            ev_detected += 1;
        }
        row_attack(a.name, &o);
    }

    section("FALSE POSITIVES", "normal apps that must keep working");
    for a in all.iter().filter(|a| a.suite == Suite::Benign) {
        let o = run_attack(a);
        fp_total += 1;
        if o.blocked {
            fp_blocked += 1;
        }
        let ok = !o.blocked;
        println!(
            "  {} {:<34} {}",
            if ok {
                paint(GREEN, "✓")
            } else {
                paint(RED, "✗")
            },
            a.name,
            if ok {
                paint(DIM, "untouched")
            } else {
                paint(RED, "WRONGLY BLOCKED")
            }
        );
    }

    // ---- scorecard --------------------------------------------------------
    let core_det = pct(core_detected as f64, core_total as f64);
    let core_block = pct((core_attempted - core_stolen) as f64, core_attempted as f64);
    let ev_det = pct(ev_detected as f64, ev_total as f64);
    let ev_block = pct(
        (ev_attempted - ev_stolen) as f64,
        ev_attempted.max(1) as f64,
    );
    let fp_rate = pct(fp_blocked as f64, fp_total as f64);

    println!(
        "\n{}",
        paint(
            &format!("{}{}", BOLD, CYAN),
            "══════════════════ SCORECARD ══════════════════"
        )
    );
    metric("Core attacks detected", core_det, core_det >= 100.0);
    metric("Core exfiltration blocked", core_block, core_block >= 99.0);
    metric(
        "False-positive rate (lower is better)",
        fp_rate,
        fp_rate == 0.0,
    );
    println!(
        "{}",
        paint(
            DIM,
            &format!(
        "  Evasion suite: detected {:.0}% · exfiltration blocked {:.0}%  (known gaps → roadmap)",
        ev_det, ev_block
    )
        )
    );

    let won = core_det >= 100.0 && core_block >= 99.0 && fp_rate == 0.0;
    println!();
    if won {
        println!(
            "{}",
            paint(
                &format!("{}{}", BOLD, GREEN),
                &format!(
                    "  ✓ DEFENSE HOLDS — {:.1}% of targeted exfiltration blocked, {:.0}% detected, {:.0}% false positives.",
                    core_block, core_det, fp_rate
                )
            )
        );
    } else {
        println!(
            "{}",
            paint(
                &format!("{}{}", BOLD, RED),
                "  ✗ DEFENSE REGRESSED — a targeted attack was not contained."
            )
        );
    }
    println!(
        "{}",
        paint(DIM, "  Honest: evasion gaps are tracked, not hidden. We do not claim to stop the exploit — we stop the theft.")
    );
    println!();

    std::process::exit(if won { 0 } else { 1 });
}

fn row_attack(name: &str, o: &Outcome) {
    let blocked_pct = pct((o.attempted - o.stolen) as f64, o.attempted.max(1) as f64);
    let caught = o.detected && blocked_pct >= 99.0;
    let mark = if caught {
        paint(GREEN, "✓ caught")
    } else if o.detected {
        paint(YELLOW, "~ partial")
    } else {
        paint(RED, "✗ missed")
    };
    let status = if o.stolen == 0 {
        paint(GREEN, "0 B stolen")
    } else {
        paint(
            if blocked_pct >= 99.0 { YELLOW } else { RED },
            &format!("{} stolen", human(o.stolen)),
        )
    };
    println!(
        "  {:<9} {:<34} {}  {}",
        mark,
        name,
        paint(DIM, &format!("blocked {:.1}%", blocked_pct)),
        status,
    );
}

fn metric(label: &str, value: f64, good: bool) {
    let col = if good { GREEN } else { RED };
    println!(
        "  {:<40} {}",
        label,
        paint(&format!("{}{}", BOLD, col), &format!("{:.1}%", value))
    );
}

fn banner() {
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
            "│  RED TEAM  vs  zeroclick-guard  —  adversarial benchmark      │"
        )
    );
    println!(
        "{}",
        paint(
            &format!("{}{}", BOLD, RED),
            "└──────────────────────────────────────────────────────────────┘"
        )
    );
    println!("{}", paint(DIM, "  Many attacks, one defender, real sockets. Scored in percentages — proof, not a claim.\n"));
}

fn section(title: &str, sub: &str) {
    println!(
        "\n{}  {}",
        paint(&format!("{}{}", BOLD, CYAN), title),
        paint(DIM, sub)
    );
}

fn human(b: u64) -> String {
    if b >= 1_000_000 {
        format!("{:.1} MB", b as f64 / 1_000_000.0)
    } else if b >= 1_000 {
        format!("{} KB", b / 1_000)
    } else {
        format!("{} B", b)
    }
}
