//! `zcg` — antarmuka baris perintah zeroclick-guard.
//!
//! Membaca observasi (JSONL) dari berkas atau stdin, menjalankan engine
//! deteksi yang SAMA dengan yang dipakai produk, lalu menampilkan alert
//! secara streaming diikuti ringkasan vonis.
//!
//! Penggunaan:
//!   zcg [--ioc <berkas.json>] [--json] [<berkas-observasi.jsonl>]
//!   cat observasi.jsonl | zcg --ioc ioc.json
//!
//! Kode keluar 2 jika ada aplikasi dengan tingkat keparahan High/Critical
//! (berguna untuk dipakai di pipeline CI pada demo/pengujian).

use std::io::{self, Read};
use std::process::ExitCode;

use zcg_core::model::Severity;
use zcg_core::{Config, Engine, IocSet, Observation};

// Kode warna ANSI (tanpa dependensi). Dinonaktifkan jika output bukan TTY.
struct Palette {
    reset: &'static str,
    dim: &'static str,
    bold: &'static str,
    red: &'static str,
    yellow: &'static str,
    cyan: &'static str,
    green: &'static str,
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
}

fn parse_args() -> Result<Args, String> {
    let mut ioc_path = None;
    let mut input_path = None;
    let mut json = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--ioc" => {
                ioc_path = Some(it.next().ok_or("--ioc butuh argumen berkas")?);
            }
            "--json" => json = true,
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other if other.starts_with('-') => {
                return Err(format!("opsi tak dikenal: {}", other));
            }
            other => input_path = Some(other.to_string()),
        }
    }
    Ok(Args {
        ioc_path,
        input_path,
        json,
    })
}

fn print_help() {
    println!(
        "zcg — engine deteksi zeroclick-guard\n\n\
         PENGGUNAAN:\n  \
         zcg [--ioc <berkas.json>] [--json] [<observasi.jsonl>]\n  \
         cat observasi.jsonl | zcg --ioc ioc.json\n\n\
         OPSI:\n  \
         --ioc <berkas>   Muat daftar IoC (JSON array) untuk pencocokan.\n  \
         --json           Keluarkan vonis sebagai JSON (bukan teks berwarna).\n  \
         -h, --help       Tampilkan bantuan ini.\n"
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

    // Muat IoC jika diberikan.
    let ioc = match &args.ioc_path {
        Some(p) => match std::fs::read_to_string(p).map(|s| IocSet::from_json(&s)) {
            Ok(Ok(set)) => set,
            Ok(Err(e)) => {
                eprintln!("error: gagal parse IoC '{}': {}", p, e);
                return ExitCode::from(1);
            }
            Err(e) => {
                eprintln!("error: gagal baca IoC '{}': {}", p, e);
                return ExitCode::from(1);
            }
        },
        None => IocSet::new(),
    };

    // Baca & parse observasi (JSONL).
    let raw = match load_input(&args.input_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: gagal baca input: {}", e);
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
                eprintln!("error: baris {} bukan observasi valid: {}", i + 1, e);
                return ExitCode::from(1);
            }
        }
    }
    // Urutkan berdasarkan waktu agar aturan lintas-waktu benar.
    observations.sort_by_key(|o| o.ts());

    let use_color = std::env::var("NO_COLOR").is_err() && atty_stdout();
    let pal = if use_color {
        Palette::colored()
    } else {
        Palette::plain()
    };

    let mut engine = Engine::new(Config::default(), ioc);

    if args.json {
        // Mode JSON: proses senyap, keluarkan vonis sebagai JSON.
        let _ = engine.run(&observations);
        let verdicts = engine.verdicts();
        match serde_json::to_string_pretty(&verdicts) {
            Ok(s) => println!("{}", s),
            Err(e) => {
                eprintln!("error: gagal serialisasi JSON: {}", e);
                return ExitCode::from(1);
            }
        }
        return exit_code(&engine);
    }

    // Mode teks: streaming alert lalu ringkasan.
    println!(
        "{}{}zeroclick-guard{} — memantau {} observasi\n",
        pal.bold,
        pal.cyan,
        pal.reset,
        observations.len()
    );

    for obs in &observations {
        let findings = engine.process(obs.clone());
        for f in findings {
            let sev = Severity::from_score(f.score); // keparahan per-temuan (indikatif)
            let col = pal.for_severity(sev);
            println!(
                "{}[{}]{} {}{}{} {}(+{})  {}{}",
                col,
                fmt_ts(f.ts),
                pal.reset,
                pal.bold,
                f.title,
                pal.reset,
                pal.dim,
                f.score,
                pal.reset,
                f.app,
            );
            println!("    {}{}{}", pal.dim, f.detail, pal.reset);
        }
    }

    // Ringkasan vonis.
    let verdicts = engine.verdicts();
    println!(
        "\n{}{}── RINGKASAN VONIS ──{}",
        pal.bold, pal.cyan, pal.reset
    );
    if verdicts.is_empty() {
        println!("  {}Tidak ada observasi berarti.{}", pal.dim, pal.reset);
    }
    for v in &verdicts {
        let col = pal.for_severity(v.severity);
        let action = if v.should_block() {
            " → REKOMENDASI: putus koneksi & karantina"
        } else {
            ""
        };
        println!(
            "  {}{:<22}{} skor {:>3}  {}{}{}{}",
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
    println!();

    exit_code(&engine)
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

/// Format timestamp ms → MM:SS.mmm relatif (cukup untuk demo & log).
fn fmt_ts(ms: u64) -> String {
    let s = ms / 1000;
    let mm = s / 60;
    let ss = s % 60;
    format!("{:02}:{:02}.{:03}", mm, ss, ms % 1000)
}

/// Deteksi sederhana apakah stdout adalah terminal (tanpa dependensi).
fn atty_stdout() -> bool {
    // Jika TERM diset dan bukan "dumb", anggap TTY. Konservatif tapi cukup
    // untuk demo; pengguna bisa paksa nonaktif dengan NO_COLOR.
    match std::env::var("TERM") {
        Ok(t) => !t.is_empty() && t != "dumb",
        Err(_) => false,
    }
}
