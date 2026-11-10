# Aturan Deteksi & Sistem Skor

Engine `zcg-core` bersifat **deterministik**: input yang sama selalu menghasilkan output
yang sama. Setiap temuan (`Finding`) membawa alasan dan bobot skornya sendiri — tidak ada
"kotak hitam". Dokumen ini menjelaskan setiap aturan, ambangnya, dan cara skor diubah
menjadi vonis.

Semua ambang didefinisikan di [`core/src/config.rs`](../core/src/config.rs) dan bisa ditala.

## Input: `Observation`

Engine memakan aliran observasi (format JSONL, satu objek per baris, dibedakan field
`type`). Lihat [`core/src/model.rs`](../core/src/model.rs).

| `type` | Arti | Field penting |
|---|---|---|
| `flow` | Satu koneksi jaringan keluar | `app`, `app_background`, `dst_ip`, `dst_port`, `domain`, `bytes_out`, `bytes_in` |
| `media` | App menerima media masuk otomatis | `app`, `bytes` |
| `app_installed` | Aplikasi baru terpasang | `app` |
| `permission` | Izin diberikan ke app | `app`, `permission` |
| `accessibility` | Accessibility diaktifkan untuk app | `app` |

Semua observasi punya `ts` (milidetik Unix) dan diproses **terurut waktu**.

## Aturan

### 1. `ioc_match` — cocok daftar IoC (+50)
Koneksi ke IP atau domain yang ada di daftar Indicator of Compromise. Bobot tertinggi
karena paling tegas. Dicatat sekali per tujuan unik per aplikasi.

### 2. `zeroclick_followup` — pola buntut zero-click (+40)
Koneksi ke tujuan **eksternal yang BARU** dalam `zeroclick_window_ms` (default **120 dtk**)
setelah aplikasi menerima **media** masuk. Ini sidik jari khas zero-click: media diproses →
exploit → proses menelepon pulang.

> Penting: hanya tujuan **baru**. Jika setelah media app menghubungi server yang **sudah
> biasa** ia hubungi, itu **tidak** diflag — inilah yang menekan alarm palsu (lihat
> skenario `benign`).

**Keterbatasan jujur:** korelasi ini per-aplikasi. Jika spyware berjalan sebagai proses
terpisah dari aplikasi yang menerima media, korelasi langsung ini bisa terlewat — aturan
lain (IoC, beacon, exfil) tetap menjadi jaring pengaman.

### 3. `accessibility_abuse` — penyalahgunaan Accessibility (+35)
Aplikasi mengaktifkan layanan **Accessibility** *sekaligus* memegang **izin sensitif**
(mis. `RECORD_AUDIO`, `READ_SMS`, `ACCESS_FINE_LOCATION`). Kombinasi ini sangat umum pada
spyware Android (baca layar + menyadap). Daftar izin sensitif ada di `config.rs`.

### 4. `beaconing` — pola beacon (+30)
Koneksi berulang ke tujuan yang sama dengan interval **sangat teratur** ("menelepon
pulang"). Algoritmanya sederhana & dapat diaudit:

- Kumpulkan ≥ `beacon_min_hits` (default **4**) waktu koneksi ke tujuan yang sama.
- Hitung interval antar-koneksi, lalu **koefisien variasi** `CV = stddev / mean`.
- Flag jika `CV ≤ beacon_max_cv` (default **0.15**, yakni jitter < 15%) **dan** rata-rata
  interval berada dalam rentang masuk akal (2 dtk – 1 jam).

CV kecil = interval nyaris identik = "robotik". Trafik manusia/aplikasi normal jitter-nya
besar sehingga tidak terflag (lihat skenario `benign`).

### 5. `exfil_volume` — lonjakan data keluar (+25)
Total `bytes_out` dari aplikasi **latar belakang** melampaui `exfil_threshold_bytes`
(default **2 MB**) dalam jendela `exfil_window_ms` (default **60 dtk**). Satu alarm per
lonjakan (anti-spam): alarm "terpasang lagi" setelah trafik mereda di bawah ambang.

### 6. `unknown_destination` — tujuan asing (+15)
Aplikasi **latar belakang** menghubungi tujuan **eksternal** yang belum pernah ia hubungi.
Bobot rendah (informatif) karena wajar terjadi; menjadi berarti saat menumpuk dengan sinyal
lain.

### 7. `new_app` — aplikasi baru terpasang (+5)
Sekadar penanda untuk dipantau sebentar. Bobot sangat rendah.

## Dari skor ke vonis

Skor semua temuan sebuah aplikasi **dijumlahkan**, lalu dipetakan (lihat
[`model.rs`](../core/src/model.rs)):

| Total skor | Severity | Label | Aksi |
|---:|---|---|---|
| 0–9 | `Clean` | AMAN | — |
| 10–29 | `Low` | PANTAU | catat |
| 30–59 | `Medium` | MENCURIGAKAN | beri tahu pengguna |
| 60–79 | `High` | KEMUNGKINAN SPYWARE | alert + sarankan putus |
| ≥ 80 | `Critical` | BAHAYA | putus koneksi & karantina |

`Verdict::should_block()` bernilai benar untuk `High` ke atas.

## Contoh hasil

| Skenario | Temuan yang menyala | Total | Vonis |
|---|---|---:|---|
| `zeroclick` | ioc + zeroclick + exfil + unknown + beacon | 130 | **BAHAYA** |
| `spyware` | accessibility_abuse + ioc + beacon + ... | 135 | **BAHAYA** |
| `benign` | unknown_destination saja (musik di background) | 15 | PANTAU |

Jalankan sendiri: lihat [README](../README.md#coba-sendiri--1-menit).

## Menala ambang

Semua angka ada di `config.rs`. Menurunkan `beacon_max_cv` membuat deteksi beacon lebih
ketat (lebih sedikit alarm palsu, tapi bisa melewatkan beacon ber-jitter). Menaikkan
`exfil_threshold_bytes` mengurangi alarm pada app yang wajar mengirim banyak data. Semua
trade-off ini **terbuka dan bisa diaudit** — itulah inti pendekatan berbasis aturan.
