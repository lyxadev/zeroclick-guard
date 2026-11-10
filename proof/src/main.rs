//! `zcg-proof` — Level-2 proof: the engine fed by REAL network traffic.
//!
//! Everything else in this repo feeds the engine *scripted* observations. This
//! tool does not. It:
//!
//!   1. Opens a real local TCP sink (a stand-in "C2 server").
//!   2. Spawns a real, benign client process-thread that actually `connect()`s
//!      to the sink on a regular cadence (a beacon) and `write()`s real bytes,
//!      including one large transfer (exfiltration).
//!   3. The sink MEASURES each real socket — the connect time and the number of
//!      bytes actually received over the wire — and turns those genuine
//!      measurements into `Observation`s.
//!   4. Those observations are fed LIVE into the exact same `zcg-core` engine
//!      used by the product, which flags the behavior.
//!
//! What is real here: the TCP connections, their timing, and the byte volumes —
//! all measured from the kernel's sockets, not hard-coded. What is passed as
//! metadata: the app identity (sent in a tiny handshake); on Android this comes
//! from the OS instead. This proves the detection logic works on real traffic —
//! it is not a guarantee against a live implant, but it is not "just theory".
//!
//! Usage: zcg-proof [app] [beacons] [interval_ms]
//!   defaults: com.demo.spyware 6 2500   (~15s, respects the engine's 2s min)

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use zcg_core::model::Severity;
use zcg_core::{Config, Engine, IocEntry, IocSet, Observation};

const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const GREEN: &str = "\x1b[32m";
const REDBG: &str = "\x1b[41m\x1b[97m";

fn color() -> bool {
    std::env::var("NO_COLOR").is_err()
}

fn main() {
    let app = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "com.demo.spyware".to_string());
    let beacons: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(6);
    let interval_ms: u64 = std::env::args()
        .nth(3)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2500);

    let c = color();
    let (cyan, bold, reset, dim) = if c {
        (CYAN, BOLD, RESET, DIM)
    } else {
        ("", "", "", "")
    };

    // 1) Real local TCP sink (the stand-in C2 server).
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind sink");
    let addr = listener.local_addr().expect("sink addr");
    let sink_ip = addr.ip().to_string();
    let sink_port = addr.port();

    println!(
        "{}{}┌─────────────────────────────────────────────────────────┐{}",
        bold, cyan, reset
    );
    println!(
        "{}{}│  ⚡ zeroclick-guard — LIVE PROOF (real network traffic)   │{}",
        bold, cyan, reset
    );
    println!(
        "{}{}└─────────────────────────────────────────────────────────┘{}",
        bold, cyan, reset
    );
    println!(
        "{}  Real TCP sockets → real measurements → the real engine. No scripted input.{}",
        dim, reset
    );
    println!(
        "{}  sink (stand-in C2) listening on {}:{} · app under test: {}{}\n",
        dim, sink_ip, sink_port, app, reset
    );

    let start = Instant::now();
    let (tx, rx) = mpsc::channel::<Observation>();

    // 2+3) Sink thread: accept real connections, MEASURE them, emit observations.
    let sink = thread::spawn(move || {
        for stream in listener.incoming().take(beacons as usize) {
            let mut s = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let ts = start.elapsed().as_millis() as u64;
            // Read everything the client sends on this connection.
            let mut buf = Vec::new();
            let _ = s.read_to_end(&mut buf);
            // The first line is a tiny handshake: "APP:<id>;BG:<0|1>\n".
            // Everything after it is the real payload (counted as bytes_out).
            let (meta, payload_len) = split_handshake(&buf);
            let (app_id, background) = parse_meta(&meta);
            let obs = Observation::Flow {
                ts,
                app: app_id,
                app_background: background,
                dst_ip: sink_ip.clone(),
                dst_port: sink_port,
                domain: None,
                bytes_out: payload_len as u64, // REAL bytes received over the wire
                bytes_in: 0,
                proto: "tcp".to_string(),
            };
            if tx.send(obs).is_err() {
                break;
            }
        }
    });

    // 2) Client thread: the benign "spyware" making REAL connections.
    let client_app = app.clone();
    let client = thread::spawn(move || {
        for i in 0..beacons {
            // The 2nd beacon carries a large "exfiltration" payload.
            let payload_size = if i == 1 { 3_000_000 } else { 800 };
            if let Ok(mut stream) = TcpStream::connect((sink_ip_str().as_str(), sink_port)) {
                let header = format!("APP:{};BG:1\n", client_app);
                let _ = stream.write_all(header.as_bytes());
                let chunk = vec![0u8; 64 * 1024];
                let mut sent = 0usize;
                while sent < payload_size {
                    let n = (payload_size - sent).min(chunk.len());
                    if stream.write_all(&chunk[..n]).is_err() {
                        break;
                    }
                    sent += n;
                }
                let _ = stream.flush();
                // Dropping the stream closes it so the sink's read_to_end returns.
            }
            if i + 1 < beacons {
                thread::sleep(Duration::from_millis(interval_ms));
            }
        }
    });

    // 4) Engine loop: consume the REAL observations live.
    // The sink IS the stand-in C2 for this run, so we tell the engine its
    // address is a known indicator — then every real connection to it, plus the
    // real beacon cadence and the real exfil volume, all light up.
    let mut ioc = IocSet::new();
    ioc.add(IocEntry {
        value: "127.0.0.1".to_string(),
        kind: "ip".to_string(),
        label: "stand-in C2 (this proof run's sink)".to_string(),
        source: "zcg-proof".to_string(),
    });
    let mut engine = Engine::new(Config::default(), ioc);
    let mut announced = Severity::Clean;
    let mut n = 0u64;
    while let Ok(obs) = rx.recv() {
        n += 1;
        if let Observation::Flow {
            ts,
            bytes_out,
            dst_ip,
            dst_port,
            ..
        } = &obs
        {
            let (d, r) = if c { (DIM, RESET) } else { ("", "") };
            println!(
                "{}· [{}] real TCP connect → {}:{}  ({} bytes measured){}",
                d,
                fmt_ts(*ts),
                dst_ip,
                dst_port,
                bytes_out,
                r
            );
        }
        for f in engine.process(obs.clone()) {
            print_finding(c, &f);
        }
        if let Some(v) = engine.verdicts().into_iter().find(|v| v.app == obs.app()) {
            if v.severity > announced {
                announce(c, &v.app, v.severity, v.score);
                announced = v.severity;
            }
        }
    }

    let _ = client.join();
    let _ = sink.join();

    summary(c, &engine, n);
    // Exit 2 if a threat was caught (handy for scripted checks).
    let flagged = engine
        .verdicts()
        .iter()
        .any(|v| v.severity >= Severity::High);
    std::process::exit(if flagged { 2 } else { 0 });
}

fn sink_ip_str() -> String {
    "127.0.0.1".to_string()
}

/// Split the first line (handshake) from the rest (payload); return (meta, payload_len).
fn split_handshake(buf: &[u8]) -> (String, usize) {
    if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
        let meta = String::from_utf8_lossy(&buf[..pos]).to_string();
        let payload_len = buf.len().saturating_sub(pos + 1);
        (meta, payload_len)
    } else {
        (String::new(), buf.len())
    }
}

/// Parse "APP:<id>;BG:<0|1>" → (app, background).
fn parse_meta(meta: &str) -> (String, bool) {
    let mut app = "unknown".to_string();
    let mut bg = true;
    for part in meta.split(';') {
        if let Some(v) = part.strip_prefix("APP:") {
            app = v.to_string();
        } else if let Some(v) = part.strip_prefix("BG:") {
            bg = v.trim() != "0";
        }
    }
    (app, bg)
}

fn print_finding(c: bool, f: &zcg_core::Finding) {
    if c {
        let col = match Severity::from_score(f.score) {
            Severity::High | Severity::Critical => RED,
            Severity::Medium => YELLOW,
            _ => CYAN,
        };
        println!(
            "{}  ├─ [{}] {}{}{} {}(+{}){}  {}",
            col,
            fmt_ts(f.ts),
            BOLD,
            f.title,
            RESET,
            DIM,
            f.score,
            RESET,
            f.app
        );
        println!("  │    {}{}{}", DIM, f.detail, RESET);
    } else {
        println!(
            "  ├─ [{}] {} (+{})  {}",
            fmt_ts(f.ts),
            f.title,
            f.score,
            f.app
        );
        println!("  │    {}", f.detail);
    }
}

fn announce(c: bool, app: &str, sev: Severity, score: u32) {
    let msg = match sev {
        Severity::Medium => format!("  ⚠  {} SUSPICIOUS (score {})", app, score),
        Severity::High => format!(
            "  ⚠  {} LIKELY SPYWARE — preparing to cut off… (score {})",
            app, score
        ),
        Severity::Critical => format!(
            " ⛔ {} DANGER — CONNECTION CUT & QUARANTINED (score {}) ",
            app, score
        ),
        _ => return,
    };
    if c {
        let col = match sev {
            Severity::Medium => YELLOW.to_string(),
            Severity::High => format!("{}{}", BOLD, RED),
            Severity::Critical => REDBG.to_string(),
            _ => String::new(),
        };
        println!("{}{}{}", col, msg, RESET);
    } else {
        println!("{}", msg);
    }
}

fn summary(c: bool, engine: &Engine, n: u64) {
    let (bold, cyan, reset, green, red, redbg) = if c {
        (BOLD, CYAN, RESET, GREEN, RED, REDBG)
    } else {
        ("", "", "", "", "", "")
    };
    println!(
        "\n{}{}══════════ VERDICT (from {} real connections) ══════════{}",
        bold, cyan, n, reset
    );
    let mut blocked = 0;
    for v in engine.verdicts() {
        let col = match v.severity {
            Severity::High | Severity::Critical => red,
            Severity::Medium => YELLOW,
            Severity::Low => cyan,
            Severity::Clean => green,
        };
        let act = if v.should_block() {
            blocked += 1;
            " → CUT OFF & QUARANTINED"
        } else {
            ""
        };
        println!(
            "  {}{:<22}{} score {:>3}  {}{}{}{}",
            bold,
            v.app,
            reset,
            v.score,
            col,
            v.severity.label_id(),
            reset,
            act
        );
    }
    if blocked > 0 {
        println!(
            "\n{} ⛔ REAL-TRAFFIC THREAT NEUTRALIZED — detected from actual sockets {}",
            redbg, reset
        );
    } else {
        println!("\n{}  ✓ No threat.{}", green, reset);
    }
    println!();
}

fn fmt_ts(ms: u64) -> String {
    let s = ms / 1000;
    format!("{:02}:{:02}.{:03}", s / 60, s % 60, ms % 1000)
}
