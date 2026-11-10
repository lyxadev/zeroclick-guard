# Roadmap

We only list something as "done" when it genuinely works and is tested. Everything else is
clearly marked as **planned**.

## ✅ Phase 1 — Core engine (working now)

- [x] Platform-agnostic observation model (`Observation`).
- [x] Deterministic detection engine (`zcg-core`): IoC, zero-click correlation, beacon,
      exfil, Accessibility+permission abuse, unknown destination.
- [x] Score → verdict system, auditable & tunable.
- [x] CLI (`zcg`) to run the engine over observation files/streams, with a cinematic
      `--replay` mode.
- [x] Benign behavior simulator (`zcg-testlab`): `zeroclick`, `spyware`, `brutal`, `benign`.
- [x] Automated tests for every rule + an anti-false-positive test.
- [x] CI (GitHub Actions): fmt, clippy (deny warnings), tests, and an attack simulation that
      asserts the real engine catches every threat and stays silent on benign traffic.
- [x] World Spyware Gauntlet: behavioral profiles of 7 known families, all detected (CI-gated).
- [x] Level-2 proof (`zcg-proof`): real traffic through an enforcement gateway — detect →
      **block** → **independently verify** (controlled C2 receives 0 bytes after block,
      100/100 attempts blocked, normal app unaffected). Evidence recorder writes JSON.
      CI-gated. See [PROOF.md](PROOF.md).
- [x] Vision & honesty tracker ([VISION.md](VISION.md)): every "Beyond Pegasus" capability
      tied to a proof status (✅ / ◑ / 🔭), moved to ✅ only with a re-runnable test.

## 🔜 Phase 1b — Android integration (in progress)

See [android/README.md](../android/README.md) for phase-by-phase status. Built CI-first:
Android CI assembles the APK on every push to `android/**`.

- [x] Android app shell (Kotlin): permissions, basic UI, VpnService scaffold. *(Phase A)*
- [ ] Local `VpnService` forwarding + feeding `zcg-core` (JNI via cargo-ndk). *(Phase B)*
- [ ] Emulator instrumented test proving per-app blocking on-device. *(Phase C)*
- [ ] Rust↔Kotlin bridge (`uniffi`/JNI) so `zcg-core` runs on the device.
- [ ] System event reading: `PackageManager` (new apps), Accessibility status, permissions.
- [ ] Real connection cutoff + notification + an explanation screen.
- [ ] On-device/emulator testing against the simulator scenarios.

## 🔭 Phase 2 — AI explanation layer (planned, when there is budget)

- [ ] Pluggable explainer interface (engine → explainer), default = local templates.
- [ ] Optional AI connector (e.g. Cloudflare Workers AI) for more fluent human-language
      explanations and false-positive reduction in gray-area cases.
- [ ] Privacy-preserving: send only minimal metadata, with explicit user consent.
- [ ] Stay honest: the feature is called "AI" only once it actually uses a model.

## 🏢 Phase 3 — Monetization (planned)

- [ ] Premium IoC feed (fresh & curated), focused on threats in Indonesia/Southeast Asia.
- [ ] B2B dashboard / team management for newsrooms, NGOs, law firms.
- [ ] Support & SLA.

## Ideas under consideration

- Desktop (Linux/Windows) using the same `zcg-core` + a pcap source.
- Import IoCs from public feeds (STIX/MISP) into the internal IoC format.
- DNS anomaly detection (many random domains / NXDOMAIN).
- Forensic mode: scan logs/backups (MVT-style) in addition to real-time monitoring.

> Have feedback or want to help? Open an issue or discussion on the repo.
