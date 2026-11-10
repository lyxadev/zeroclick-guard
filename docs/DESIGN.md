# Dokumen Acuan — zeroclick-guard

Dokumen ini adalah "peta" proyek: visi, apa yang realistis (dan tidak), arsitektur,
prinsip kejujuran, pembagian terbuka vs berbayar, dan arah bisnis. Semua keputusan desain
dirujuk ke sini.

---

## 1. Visi

> Menjadi perisai anti-spyware paling **mudah dipakai** dan paling **jujur** —
> khususnya untuk Indonesia & Asia Tenggara, pasar yang belum digarap serius —
> sehingga jurnalis, aktivis, pengacara, dan orang biasa bisa **tahu** saat mereka
> diintai, dan **menghentikan** kerugiannya.

Kami **tidak** berusaha "mengalahkan Pegasus" dalam arti mencegah exploit kelas negara.
Itu tidak realistis di perangkat non-root. Target kami adalah sisi **pertahanan**: deteksi
cepat + pemutusan + penjelasan yang bisa dimengerti orang awam.

## 2. Apa yang realistis — dan apa yang TIDAK

### Kenyataan keras Android
Android menyandbox aplikasi dengan ketat. Tanpa **root**, satu aplikasi **tidak bisa**
melihat memori, syscall, atau berkas aplikasi lain. Ini batas sistem operasi, bukan batas
bahasa pemrograman. Maka:

| Fase serangan zero-click | Bisa kita tangani (non-root)? |
|---|---|
| Media jahat dikirim | Tidak terlihat |
| Media diproses otomatis, exploit berjalan | ❌ **Tidak** — di dalam proses app lain |
| Spyware aktif di memori | Sebagian (lewat efek sampingnya) |
| **Spyware konek C2 / exfiltrasi data** | ✅ **Ya — di sinilah kekuatan kami** |
| Spyware minta izin / Accessibility | ✅ Ya |

**Janji inti yang jujur:** _"Kami tidak mencegah exploit zero-click. Kami mendeteksi
perilaku pasca-eksploitasi — C2, exfiltrasi, penyalahgunaan izin — dan memutusnya, dalam
hitungan detik."_

### Yang bisa dilakukan tanpa root (dan sudah terbukti di industri)
- **VpnService lokal** — rutekan semua trafik perangkat melalui VPN *di dalam perangkat
  sendiri* (tidak ke server mana pun) untuk inspeksi tujuan koneksi. (Pendekatan NetGuard,
  TrackerControl.)
- **IoC matching** — cocokkan tujuan dengan indikator spyware yang dikenal. (Pendekatan
  MVT milik Amnesty International.)
- **Deteksi perilaku** — beaconing, exfiltrasi, tujuan asing, penyalahgunaan izin.

## 3. Kenapa TANPA AI (untuk sekarang)

Engine inti **deterministik dan berbasis aturan**, bukan AI. Ini pilihan sadar, bukan
kekurangan:

- **Bisa diaudit** — tiap keputusan punya alasan pasti; tidak ada "halusinasi".
- **Cepat & ringan** — real-time di perangkat, hemat baterai, tanpa panggilan server.
- **Gratis & privat** — tidak ada data dikirim ke cloud, tidak ada tagihan.
- **Jalan offline.**

Mayoritas tool keamanan kelas dunia (firewall, IDS seperti Suricata/Snort) berbasis aturan,
bukan AI. AI **tidak menambah kemampuan menangkap** — ia hanya (nanti) memperbaiki
*penjelasan* dan mengurangi alarm palsu di kasus abu-abu. Lihat Roadmap Fase 2.

> **Aturan penamaan jujur:** selama belum ada model AI sungguhan, fitur penjelasan disebut
> **"berbasis aturan"**, bukan "AI". Tidak ada klaim "AI" sampai benar-benar ada AI.

## 4. Arsitektur

```
┌─────────────────────────────────────────────────────────────┐
│  SUMBER OBSERVASI (pluggable)                                │
│   • Android VpnService  • pcap desktop  • simulator uji      │
└───────────────────────────┬─────────────────────────────────┘
                            │  aliran Observation (JSONL / in-proc)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  zcg-core  (Rust, deterministik)                             │
│   IoC ─ korelasi zero-click ─ beacon ─ exfil ─ izin ─ skor   │
└───────────────────────────┬─────────────────────────────────┘
                            │  Finding + Verdict
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  AKSI:  alert  ·  putus koneksi  ·  saran  ·  (nanti) AI      │
└─────────────────────────────────────────────────────────────┘
```

**Kunci:** `zcg-core` tidak tahu dari mana observasi datang. Maka engine yang sama dipakai
di produk Android **dan** di demo/uji — tidak ada dua versi, tidak ada yang dipalsukan.

### Peran Rust vs Kotlin (untuk Android nanti)
Aplikasi Android **tidak bisa** full-Rust. Pembagiannya:
- **Kotlin** → shell: VpnService, UI, izin, event sistem (PackageManager, Accessibility).
- **Rust (`zcg-core` via JNI/`uniffi`)** → engine: parsing paket, aturan, skor, IoC.

Core Rust yang sama juga bisa dipakai ulang di desktop (Linux/Windows) nanti.

## 5. Prinsip kejujuran demo (garis merah)

Demo menampilkan "penyerang" (simulator jinak) vs "defender" (engine asli).

- ✅ **Defender 100% asli.** Alert, skor, pemutusan — semua dari engine sungguhan.
- ✅ **Penyerang = simulator perilaku jinak.** Menghasilkan trafik/observasi nyata, tapi
  tanpa exploit & tanpa data sungguhan (pakai alamat uji RFC 5737 & domain RFC 2606).
- ❌ **DILARANG** memalsukan respons defender (alert yang di-hardcode, animasi tanpa
  engine). Demo **wajib** memanggil engine yang sama dengan produk.

Alasan: jika kami curang sedikit saja, begitu ada ahli menguji dengan serangan nyata dan
engine diam → reputasi hancur selamanya. Untuk tool keamanan, kepercayaan adalah segalanya.

**Kami tidak membangun spyware sungguhan.** Sisi "penyerang" selalu berupa simulator
perilaku. Membangun spyware fungsional berbahaya, bisa bocor/disalahgunakan, dan ilegal —
dan tidak diperlukan: yang perlu diuji adalah *perilaku* yang dideteksi, bukan exploit-nya.

## 6. Model terbuka vs berbayar (open-core)

Tool keamanan tertutup sulit dipercaya. Maka inti kami **open source** (membangun
kepercayaan + komunitas + audit publik), sementara monetisasi di lapisan layanan.

| Terbuka (gratis, open source) | Berbayar / privat |
|---|---|
| Engine deteksi inti (`zcg-core`) | Feed IoC premium (ter-update, terkurasi) |
| VpnService + aturan dasar | Lapisan penjelas AI (Fase 2) |
| Simulator/test lab | Dashboard B2B / manajemen tim |
| Daftar IoC dasar | Dukungan & SLA |

**Prinsip:** yang membangun **kepercayaan** → dibuka. Yang membangun **pendapatan** →
ditahan. Uang ada di *layanan + data + dukungan*, bukan di kode inti.

Lisensi **GPLv3** menjaga agar kode inti tidak diam-diam dijadikan produk tertutup.

## 7. Posisi vs pembanding

| | Fokus | Celah yang kami isi |
|---|---|---|
| **MVT** (Amnesty) | Forensik IoC, open source | Terlalu teknis untuk orang awam |
| **iVerify** | Deteksi spyware mobile (komersial) | Mahal, berbahasa Inggris |
| **Lookout / Zimperium** | Enterprise | Mahal, bukan untuk individu |
| **zeroclick-guard** | Deteksi perilaku real-time | **Mudah, bahasa Indonesia, terjangkau, terbuka** |

## 8. Arah bisnis (ringkas & realistis)

- **B2B dulu** (media, NGO, kantor hukum): sedikit pembeli, bayar serius & stabil. Satu
  kontrak organisasi = ratusan user individu. Jalur tercepat menghasilkan.
- **Individu high-risk** (jurnalis, aktivis): langganan / freemium.
- Pendapatan datang dari **langganan layanan + feed IoC + dukungan B2B**, bukan dari kode
  yang gratis.

> Catatan jujur: open source adalah mesin **kepercayaan & marketing**, bukan mesin uang
> langsung. "Viral" itu pengecualian yang butuh kualitas nyata + kerja konsisten, bukan
> otomatis.

## 9. Peta jalan singkat

1. **Fase 1 (sekarang, gratis):** engine deteksi real + simulator + CLI demo. ✅ berjalan.
2. **Fase 1b:** integrasi Android (VpnService + shell Kotlin).
3. **Fase 2 (saat ada budget):** lapisan penjelas AI (mis. Cloudflare Workers AI),
   pluggable — tanpa membongkar engine.
4. **Fase 3:** dashboard B2B, feed IoC, monetisasi.

Detail: [ROADMAP.md](ROADMAP.md).
