# Roadmap

Kami hanya mencantumkan sesuatu sebagai "selesai" bila benar-benar berjalan & teruji.
Sisanya jelas ditandai sebagai **rencana**.

## ✅ Fase 1 — Engine inti (berjalan sekarang)

- [x] Model observasi platform-agnostik (`Observation`).
- [x] Engine deteksi deterministik (`zcg-core`): IoC, korelasi zero-click, beacon, exfil,
      penyalahgunaan izin, tujuan asing.
- [x] Sistem skor → vonis, dapat diaudit & ditala.
- [x] CLI (`zcg`) untuk menjalankan engine atas berkas/stream observasi.
- [x] Simulator perilaku jinak (`zcg-testlab`): skenario `zeroclick`, `spyware`, `benign`.
- [x] Uji otomatis (unit test) untuk setiap aturan + uji anti-false-positive.

## 🔜 Fase 1b — Integrasi Android (rencana)

- [ ] Shell aplikasi Android (Kotlin): izin, UI dasar.
- [ ] `VpnService` lokal untuk menangkap metadata koneksi keluar.
- [ ] Jembatan Rust↔Kotlin (`uniffi`/JNI) agar `zcg-core` jalan di perangkat.
- [ ] Pembacaan event sistem: `PackageManager` (app baru), status Accessibility, izin.
- [ ] Aksi pemutusan koneksi nyata + notifikasi + layar penjelasan.
- [ ] Uji di perangkat/emulator terhadap skenario simulator.

## 🔭 Fase 2 — Lapisan penjelas AI (rencana, saat ada budget)

- [ ] Antarmuka penjelas *pluggable* (engine → penjelas), default = template lokal.
- [ ] Penyambung AI opsional (mis. Cloudflare Workers AI) untuk penjelasan bahasa manusia
      yang lebih luwes & pengurangan alarm palsu di kasus abu-abu.
- [ ] Jaga privasi: hanya kirim metadata minimal, dengan izin eksplisit pengguna.
- [ ] Tetap jujur: fitur disebut "AI" hanya setelah benar-benar memakai model.

## 🏢 Fase 3 — Monetisasi (rencana)

- [ ] Feed IoC premium (ter-update & terkurasi), dengan fokus ancaman di Indonesia/Asia Tenggara.
- [ ] Dashboard B2B / manajemen tim untuk media, NGO, kantor hukum.
- [ ] Dukungan & SLA.

## Ide yang sedang dipertimbangkan

- Desktop (Linux/Windows) memakai `zcg-core` yang sama + sumber pcap.
- Impor IoC dari feed publik (format STIX/MISP) ke bentuk IoC internal.
- Deteksi anomali DNS (banyak domain acak/NXDOMAIN).
- Mode forensik: pindai log/backup (pendekatan ala MVT) selain pemantauan real-time.

> Punya masukan atau ingin membantu? Buka issue atau diskusi di repo.
