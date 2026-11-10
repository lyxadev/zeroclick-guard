//! `zcg-testlab` — simulator perilaku JINAK.
//!
//! ⚠️  PENTING: program ini TIDAK berisi exploit, payload, atau spyware
//! sungguhan. Ia hanya MENCETAK catatan observasi (JSONL) yang MENIRU *pola
//! perilaku* serangan — koneksi berkala, lonjakan data, dsb. — supaya engine
//! deteksi bisa diuji & didemokan secara jujur dan berulang.
//!
//! Analoginya seperti latihan kebakaran: asapnya simulasi, tapi alarm yang
//! diuji (engine zeroclick-guard) 100% asli.
//!
//! Penggunaan:
//!   zcg-testlab <skenario>
//! Skenario:
//!   zeroclick   Pola serangan zero-click (media masuk → C2 → beacon → exfil).
//!   spyware     Spyware "dipasang" (Accessibility + izin sensitif + C2).
//!   benign      Perilaku aplikasi normal (harus TIDAK memicu alarm).
//!
//! Contoh demo (pipa langsung ke engine):
//!   zcg-testlab zeroclick | zcg --ioc examples/ioc-testlab.json

use zcg_core::Observation;

fn main() {
    let scenario = std::env::args().nth(1).unwrap_or_default();
    let obs = match scenario.as_str() {
        "zeroclick" => scenario_zeroclick(),
        "spyware" => scenario_spyware(),
        "benign" => scenario_benign(),
        _ => {
            eprintln!(
                "simulator perilaku jinak zeroclick-guard\n\n\
                 skenario: zeroclick | spyware | benign\n\n\
                 contoh: zcg-testlab zeroclick | zcg --ioc examples/ioc-testlab.json\n\n\
                 Catatan: ini hanya mencetak observasi tiruan (JSONL). Tidak ada\n\
                 exploit atau spyware sungguhan di dalamnya."
            );
            std::process::exit(if scenario.is_empty() { 0 } else { 1 });
        }
    };
    for o in obs {
        // Tiap observasi satu baris JSON (JSONL).
        println!(
            "{}",
            serde_json::to_string(&o).expect("serialisasi observasi")
        );
    }
}

/// Skenario zero-click: WhatsApp menerima media, lalu "proses yang
/// dikompromikan" menelepon C2, mengirim data, lalu beacon berkala.
fn scenario_zeroclick() -> Vec<Observation> {
    let app = "com.whatsapp";
    let c2 = "203.0.113.50"; // TEST-NET-3 (RFC 5737) — alamat uji, bukan host nyata
    let mut v = Vec::new();

    // Lalu lintas normal lebih dulu: WhatsApp bicara ke servernya sendiri.
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

    // t=10s: media masuk otomatis (pintu zero-click). Belum mencurigakan.
    v.push(Observation::Media {
        ts: 10_000,
        app: app.to_string(),
        bytes: 920_000,
    });

    // t=40s: 30 dtk setelah media, koneksi BARU ke C2 luar (buntut zero-click).
    v.push(flow(40_000, app, true, c2, 443, None, 2_400, 200));

    // t=50s: lonjakan data keluar (exfiltrasi kontak/pesan).
    v.push(flow(50_000, app, true, c2, 443, None, 3_200_000, 400));

    // Beacon: "menelepon pulang" tiap 60 dtk persis ke C2 yang sama.
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

/// Skenario spyware terpasang: app menyamar, minta Accessibility + izin
/// sensitif, lalu beacon ke C2.
fn scenario_spyware() -> Vec<Observation> {
    let app = "com.senter.flashlight"; // "aplikasi senter" yang mencurigakan
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

    // Beacon ke C2 tiap 90 dtk.
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

/// Skenario normal: harus TIDAK memicu alarm (uji false-positive).
fn scenario_benign() -> Vec<Observation> {
    let mut v = Vec::new();

    // Browser di foreground, koneksi wajar & tak teratur ke macam-macam CDN.
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

    // WhatsApp menerima media, lalu bicara ke server yang SAMA seperti biasa
    // (sudah dikenal) — jadi BUKAN buntut zero-click. Ini menunjukkan korelasi
    // kita soal tujuan BARU, bukan sekadar "ada koneksi setelah media".
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

    // App musik streaming di background, data MASUK besar (wajar), keluar kecil.
    // Interval sengaja TAK TERATUR (streaming asli bursty) → bukan beacon.
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

/// Pembuat observasi Flow yang ringkas.
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
