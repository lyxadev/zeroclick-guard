//! `zcg` — the zeroclick-guard command-line interface.
//!
//! Reads observations (JSONL) from a file or stdin, runs the SAME detection
//! engine used in the product, and prints streaming alerts followed by a
//! verdict summary.
//!
//! Usage:
//!   zcg [--ioc <file.json>] [--json] [--replay] [--speed N] [<observations.jsonl>]
//!   cat observations.jsonl | zcg --ioc ioc.json --replay
//!
//! `--replay` mode plays observations back with delays based on their
//! timestamps (sped up) so an attack looks like it is "unfolding live" —
//! useful for demos/recordings. Detection is still 100% from the real engine;
//! only the display tempo is adjusted.
//!
//! Exit code 2 if any app reaches High/Critical severity (handy in CI pipelines
//! for demos/tests).

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::process::ExitCode;
use std::thread::sleep;
use std::time::Duration;

use zcg_core::model::Severity;
use zcg_core::{Config, Engine, IocSet, Observation};

// ANSI color codes (no dependency). Disabled when stdout is not a TTY.
struct Palette {
    reset: &'static str,
    dim: &'static str,
    bold: &'static str,
    red: &'static str,
    yellow: &'static str,
    cyan: &'static str,
    green: &'static str,
    red_bg: &'static str,
}

impl Palette {
    fn colored() -> Self {
        Palette {
            reset: "\x1b[0m",
            dim: "\x1b[2m",
            bold: "\x1b[1m",
            red: "\x1b[31m",
            yellow: "\x1b[33m",
            cyan: "\x1b[36m",
            green: "\x1b[32m",
            red_bg: "\x1b[41m\x1b[97m",
        }
    }
    fn plain() -> Self {
        Palette {
            reset: "",
            dim: "",
            bold: "",
            red: "",
            yellow: "",
            cyan: "",
            green: "",
            red_bg: "",
        }
    }
    fn for_severity(&self, s: Severity) -> &'static str {
        match s {
            Severity::Clean => self.green,
            Severity::Low => self.cyan,
            Severity::Medium => self.yellow,
            Severity::High | Severity::Critical => self.red,
        }
    }
}

struct Args {
    ioc_path: Option<String>,
    input_path: Option<String>,
    json: bool,
    replay: bool,
    speed: u64,
}

fn parse_args() -> Result<Args, String> {
    let mut ioc_path = None;
    let mut input_path = None;
    let mut json = false;
    let mut replay = false;
    let mut speed = 50;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--ioc" => {
                ioc_path = Some(it.next().ok_or("--ioc needs a file argument")?);
            }
            "--json" => json = true,
            "--replay" => replay = true,
            "--speed" => {
                speed = it
                    .next()
                    .ok_or("--speed needs a number")?
                    .parse()
                    .map_err(|_| "--speed must be a number > 0")?;
                if speed == 0 {
                    return Err("--speed must be > 0".to_string());
                }
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other if other.starts_with('-') => {
                return Err(format!("unknown option: {}", other));
            }
            other => input_path = Some(other.to_string()),
        }
    }
    Ok(Args {
        ioc_path,
        input_path,
        json,
        replay,
        speed,
    })
}

fn print_help() {
    println!(
        "zcg — the zeroclick-guard detection engine\n\n\
         USAGE:\n  \
         zcg [--ioc <file.json>] [--json] [--replay] [--speed N] [<observations.jsonl>]\n  \
         cat observations.jsonl | zcg --ioc ioc.json --replay\n\n\
         OPTIONS:\n  \
         --ioc <file>   Load an IoC list (JSON array) for matching.\n  \
         --json         Emit verdicts as JSON (instead of colored text).\n  \
         --replay       Play back live according to timestamps (sped up).\n  \
         --speed N       Replay speed factor (default 50; higher = faster).\n  \
         -h, --help     Show this help.\n"
    );
}

fn load_input(path: &Option<String>) -> io::Result<String> {
    match path {
        Some(p) => std::fs::read_to_string(p),
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            Ok(buf)
        }
    }
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {}", e);
            return ExitCode::from(1);
        }
    };

    // Load IoC if provided.
    let ioc = match &args.ioc_path {
        Some(p) => match std::fs::read_to_string(p).map(|s| IocSet::from_json(&s)) {
            Ok(Ok(set)) => set,
            Ok(Err(e)) => {
                eprintln!("error: failed to parse IoC '{}': {}", p, e);
                return ExitCode::from(1);
            }
            Err(e) => {
                eprintln!("error: failed to read IoC '{}': {}", p, e);
                return ExitCode::from(1);
            }
        },
        None => IocSet::new(),
    };

    // Read & parse observations (JSONL).
    let raw = match load_input(&args.input_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to read input: {}", e);
            return ExitCode::from(1);
        }
    };
    let mut observations: Vec<Observation> = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match serde_json::from_str::<Observation>(line) {
            Ok(o) => observations.push(o),
            Err(e) => {
                eprintln!("error: line {} is not a valid observation: {}", i + 1, e);
                return ExitCode::from(1);
            }
        }
    }
    // Sort by time so cross-time rules are correct.
    observations.sort_by_key(|o| o.ts());

    let use_color = std::env::var("NO_COLOR").is_err() && (args.replay || atty_stdout());
    let pal = if use_color {
        Palette::colored()
    } else {
        Palette::plain()
    };

    let mut engine = Engine::new(Config::default(), ioc);

    if args.json {
        // JSON mode: process quietly, emit verdicts as JSON.
        let _ = engine.run(&observations);
        let verdicts = engine.verdicts();
        match serde_json::to_string_pretty(&verdicts) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("error: failed to serialize JSON: {}", e);
                return ExitCode::from(1);
            }
        }
        return exit_code(&engine);
    }

    banner(&pal, observations.len(), args.replay);

    // Track the highest severity already "announced" per app, so an action
    // (alert/cutoff) is only shouted once as the score crosses a threshold.
    let mut announced: HashMap<String, Severity> = HashMap::new();
    let mut prev_ts: Option<u64> = None;

    for obs in &observations {
        // Cinematic pacing for replay mode (does not affect detection).
        if args.replay {
            if let Some(pt) = prev_ts {
                let gap = obs.ts().saturating_sub(pt);
                let ms = (gap / args.speed).min(1_500);
                if ms > 0 {
                    sleep(Duration::from_millis(ms));
                }
            }
            println!(
                "{}· [{}] {}{}",
                pal.dim,
                fmt_ts(obs.ts()),
                describe_obs(obs),
                pal.reset
            );
            let _ = io::stdout().flush();
        }
        prev_ts = Some(obs.ts());

        let findings = engine.process(obs.clone());
        for f in findings {
            let sev = Severity::from_score(f.score); // per-finding severity (indicative)
            let col = pal.for_severity(sev);
            println!(
                "{}  ├─ [{}] {}{}{} {}(+{})  {}{}",
                col,
                fmt_ts(f.ts),
                pal.bold,
                f.title,
                pal.reset,
                pal.dim,
                f.score,
                pal.reset,
                f.app,
            );
            println!("  │    {}{}{}", pal.dim, f.detail, pal.reset);
            if args.replay {
                let _ = io::stdout().flush();
                sleep(Duration::from_millis(220));
            }
        }

        // Did this app just cross a new threshold? Shout the action.
        if let Some(v) = engine.verdicts().into_iter().find(|v| v.app == obs.app()) {
            let last = announced.get(&v.app).copied().unwrap_or(Severity::Clean);
            if v.severity > last {
                announce_action(&pal, &v.app, v.severity, v.score);
                announced.insert(v.app.clone(), v.severity);
                if args.replay {
                    let _ = io::stdout().flush();
                    sleep(Duration::from_millis(350));
                }
            }
        }
    }

    summary(&pal, &engine);
    exit_code(&engine)
}

fn announce_action(pal: &Palette, app: &str, sev: Severity, score: u32) {
    match sev {
        Severity::Medium => println!(
            "{}  ⚠  {} SUSPICIOUS (score {}){}",
            pal.yellow, app, score, pal.reset
        ),
        Severity::High => println!(
            "{}{}  ⚠  {} LIKELY SPYWARE — preparing to cut off… (score {}){}",
            pal.bold, pal.red, app, score, pal.reset
        ),
        Severity::Critical => println!(
            "{} ⛔ {} DANGER — CONNECTION CUT & QUARANTINED (score {}) {}",
            pal.red_bg, app, score, pal.reset
        ),
        _ => {}
    }
}

fn banner(pal: &Palette, n: usize, replay: bool) {
    println!(
        "{}{}┌───────────────────────────────────────────────┐{}",
        pal.bold, pal.cyan, pal.reset
    );
    println!(
        "{}{}│  ⚡ zeroclick-guard — SHIELD ACTIVE             │{}",
        pal.bold, pal.cyan, pal.reset
    );
    println!(
        "{}{}└───────────────────────────────────────────────┘{}",
        pal.bold, pal.cyan, pal.reset
    );
    println!(
        "{}monitoring {} observations{}{}\n",
        pal.dim,
        n,
        if replay { " · live replay mode" } else { "" },
        pal.reset
    );
}

fn summary(pal: &Palette, engine: &Engine) {
    let verdicts = engine.verdicts();
    println!(
        "\n{}{}══════════ VERDICT SUMMARY ══════════{}",
        pal.bold, pal.cyan, pal.reset
    );
    if verdicts.is_empty() {
        println!("  {}No meaningful observations.{}", pal.dim, pal.reset);
    }
    let mut blocked = 0;
    for v in &verdicts {
        let col = pal.for_severity(v.severity);
        let action = if v.should_block() {
            blocked += 1;
            " → CUT OFF & QUARANTINED"
        } else {
            ""
        };
        println!(
            "  {}{:<24}{} score {:>3}  {}{}{}{}",
            pal.bold,
            v.app,
            pal.reset,
            v.score,
            col,
            v.severity.label_id(),
            pal.reset,
            action,
        );
    }
    if blocked > 0 {
        println!(
            "\n{} ⛔ THREAT NEUTRALIZED — {} app(s) cut off & quarantined {}",
            pal.red_bg, blocked, pal.reset
        );
    } else {
        println!("\n{}  ✓ No active threats.{}", pal.green, pal.reset);
    }
    println!();
}

fn exit_code(engine: &Engine) -> ExitCode {
    let flagged = engine
        .verdicts()
        .iter()
        .any(|v| v.severity >= Severity::High);
    if flagged {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    }
}

/// Short description of one observation for the "live" view.
fn describe_obs(obs: &Observation) -> String {
    match obs {
        Observation::Flow {
            app,
            dst_ip,
            dst_port,
            bytes_out,
            app_background,
            ..
        } => format!(
            "{} {} → {}:{}  (out {} B)",
            if *app_background { "◴" } else { "●" },
            app,
            dst_ip,
            dst_port,
            bytes_out
        ),
        Observation::Media { app, bytes, .. } => {
            format!("✉ {} received inbound media ({} KB)", app, bytes / 1024)
        }
        Observation::AppInstalled { app, .. } => format!("⬇ new app installed: {}", app),
        Observation::Permission {
            app, permission, ..
        } => format!("🔑 {} granted permission {}", app, permission),
        Observation::Accessibility { app, .. } => {
            format!("♿ {} enabled an Accessibility service", app)
        }
    }
}

/// Format timestamp ms → relative MM:SS.mmm (enough for demos & logs).
fn fmt_ts(ms: u64) -> String {
    let s = ms / 1000;
    let mm = s / 60;
    let ss = s % 60;
    format!("{:02}:{:02}.{:03}", mm, ss, ms % 1000)
}

/// Simple check of whether stdout is a terminal (no dependency).
fn atty_stdout() -> bool {
    match std::env::var("TERM") {
        Ok(t) => !t.is_empty() && t != "dumb",
        Err(_) => false,
    }
}
