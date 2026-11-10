<div align="center">

# ⚡ zeroclick-guard

**Perisai anti-spyware & zero-click untuk Android — dan desktop.**

Mendeteksi & memutus perilaku spyware (koneksi C2, exfiltrasi data, penyalahgunaan izin)
langsung di perangkat. Berbasis aturan, deterministik, bisa diaudit.
Tanpa AI. Tanpa cloud. Privasi penuh.

[![lisensi](https://img.shields.io/badge/lisensi-GPLv3-blue.svg)](LICENSE)
[![status](https://img.shields.io/badge/status-pengembangan%20awal-orange.svg)](#status)
[![bahasa](https://img.shields.io/badge/core-Rust-orange.svg)](core/)

</div>

---

> ### 🚧 Status
> **Tahap pengembangan awal.** Engine deteksi inti **sudah berfungsi penuh & bisa
> didemokan** (lihat di bawah). Integrasi Android (VpnService) sedang dikerjakan —
> lihat [Roadmap](docs/ROADMAP.md). Kami hanya mengklaim apa yang benar-benar jalan.

## Apa ini — dan apa yang TIDAK kami janjikan

Spyware canggih (kelas Pegasus) sering masuk lewat serangan **zero-click**: korban tidak
perlu mengklik apa pun — aplikasi seperti WhatsApp otomatis memproses media jahat, dan
exploit berjalan di dalam proses itu.

**Jujur sejak awal:** di Android tanpa root, **tidak ada** perangkat lunak yang bisa
*mencegah* exploit zero-click itu sendiri — exploit terjadi di dalam proses aplikasi lain
yang disegel oleh Android. Siapa pun yang mengklaim bisa mencegah 100%, berbohong.

Yang **bisa** — dan ini yang zeroclick-guard lakukan — adalah **menangkap serangan dari
jejak perilakunya** dalam hitungan detik: spyware *harus* menelepon pulang (C2), *harus*
mengirim data keluar. Di sanalah kami mendeteksi dan **memutus** koneksinya.

> Analogi: kami bukan rompi anti-peluru. Kami alarm & detektor asap yang berbunyi keras
> saat ada yang terbakar, lalu menutup pintunya — sehingga korban **tahu** dan kerugian
> **dihentikan**. Kelemahan terbesar korban spyware adalah mereka tidak pernah sadar.

## Cara kerja (ringkas)

```
   Sumber observasi            Engine deteksi (zcg-core)          Aksi
 ┌──────────────────┐        ┌───────────────────────────┐    ┌──────────────┐
 │ Android VpnService│  ───▶  │  aturan + skor + IoC       │──▶ │ alert + putus │
 │ (lalu lintas HP)  │        │  korelasi zero-click       │    │ koneksi + saran│
 │ pcap / simulator  │        │  deteksi beacon & exfil    │    └──────────────┘
 └──────────────────┘        └───────────────────────────┘
```

Engine inti **platform-agnostik**: ia hanya memakan aliran *observasi* (koneksi jaringan,
media masuk, izin). Hari ini bisa dijalankan di desktop; integrasi Android mengisi engine
yang sama. **Engine yang dipakai di demo = engine yang dipakai di produk.** Tidak ada yang
dipalsukan.

### Apa yang dideteksi

| Aturan | Sinyal | Skor |
|---|---|---|
| `ioc_match` | Koneksi ke IP/domain jahat yang dikenal | +50 |
| `zeroclick_followup` | Koneksi luar **baru** sesaat setelah media masuk | +40 |
| `accessibility_abuse` | Accessibility + izin sensitif (sadap) | +35 |
| `beaconing` | Koneksi berkala sangat teratur (menelepon pulang) | +30 |
| `exfil_volume` | Lonjakan data keluar dari app latar belakang | +25 |
| `unknown_destination` | App latar belakang → tujuan luar asing | +15 |

Skor menumpuk per-aplikasi → vonis: `AMAN` · `PANTAU` · `MENCURIGAKAN` · `KEMUNGKINAN
SPYWARE` · `BAHAYA`. Detail: [docs/DETECTION.md](docs/DETECTION.md).

## Coba sendiri (± 1 menit)

Butuh [Rust](https://rustup.rs). Clone lalu:

```bash
cargo build --workspace
```

Jalankan simulator serangan **jinak** dan pipa ke engine:

```bash
./target/debug/zcg-testlab zeroclick | ./target/debug/zcg --ioc examples/ioc-testlab.json
```

Hasilnya (serangan zero-click ditangkap, lalu diberi vonis):

```
[00:40.000] Cocok daftar IoC (+50)  com.whatsapp
    Koneksi ke indikator berbahaya yang dikenal: 203.0.113.50 ...
[00:40.000] Pola buntut zero-click (+40)  com.whatsapp
    'com.whatsapp' menerima media lalu 30 dtk kemudian membuka koneksi baru ke
    203.0.113.50 (luar, belum pernah dihubungi). Ini pola khas serangan zero-click.
[00:50.000] Lonjakan data keluar (+25)  com.whatsapp
    'com.whatsapp' mengirim ~3128 KB keluar ke 203.0.113.50 ...

── RINGKASAN VONIS ──
  com.whatsapp           skor 130  BAHAYA → REKOMENDASI: putus koneksi & karantina
```

Bandingkan dengan perilaku **normal** (seharusnya tidak ada alarm):

```bash
./target/debug/zcg-testlab benign | ./target/debug/zcg --ioc examples/ioc-testlab.json
```

> **Simulator itu jinak.** `zcg-testlab` hanya *mencetak catatan observasi* yang meniru
> **pola perilaku** serangan. Tidak ada exploit atau spyware sungguhan di dalamnya —
> seperti latihan kebakaran: asapnya simulasi, alarmnya (engine) asli. Lihat
> [testlab/](testlab/).

## Struktur proyek

```
zeroclick-guard/
├── core/      zcg-core  — engine deteksi (library, Rust). Jantung produk.
├── cli/       zcg       — jalankan engine atas berkas observasi (demo & uji).
├── testlab/   zcg-testlab — simulator perilaku JINAK untuk demo & pengujian.
├── examples/  contoh daftar IoC untuk demo.
└── docs/      DESIGN (acuan), DETECTION (aturan & skor), ROADMAP.
```

## Dokumentasi

- 📐 [docs/DESIGN.md](docs/DESIGN.md) — visi, arsitektur, apa yang realistis, prinsip kejujuran.
- 🔍 [docs/DETECTION.md](docs/DETECTION.md) — aturan deteksi & sistem skor, lengkap.
- 🗺️ [docs/ROADMAP.md](docs/ROADMAP.md) — rencana bertahap.

## Lisensi

[GPLv3](LICENSE). Bebas dipakai, dipelajari, dan diaudit — dan tetap terbuka: siapa pun
yang mendistribusikan versi modifikasi wajib ikut membukanya.

---

<div align="center"><sub>Dibuat untuk membantu orang-orang yang jadi target di Indonesia & dunia.</sub></div>
