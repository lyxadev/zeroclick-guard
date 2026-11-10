# Vision — Beyond Pegasus (defense, proven not claimed)

The ambition is big: grow zeroclick-guard from an anti-spyware tool into a
next-generation **defensive** security platform — for researchers, teams,
organizations, and ordinary high-risk users.

One principle is non-negotiable, and it is the whole reason this repo exists:

> **Defensive capability is demonstrated through reproducible and independent
> testing — never through marketing claims.**

"Beyond Pegasus" here means **better protection against** that class of threat,
**not** a more invasive tool. We do not build spyware. Every ambition below is
tracked against its real proof status, so the roadmap can never quietly become a
list of promises.

## The honest ceiling

We say it on every page and we will keep saying it: on a non-rooted device, **no
software can prevent a zero-click exploit itself** — that happens inside another
app's sealed process. Detecting an *exploit* and detecting *spyware behavior* are
two different capabilities. We do the second, and we do the *containment* that
follows. That is the achievable, life-saving half, and it is what we prove.

## Capability matrix — with proof status

Legend: ✅ proven & reproducible · ◑ partially proven · 🔭 planned.

| Capability | What it really means here | Status | Evidence |
|---|---|---|---|
| Zero-click **behavior** defense | Detect post-exploitation behavior (not prevent the exploit) | ✅ | engine + unit tests + [gauntlet](../README.md#-proof-the-world-spyware-gauntlet) |
| Advanced spyware detection | Flag behavioral profiles of known families | ✅ (simulated) · 🔭 (live feed) | [gauntlet GIF](media/gauntlet.gif), 7/7 |
| **Verified** network prevention | Block the connection **and prove it** (C2 gets 0 bytes) | ✅ (desktop gateway) · 🔭 (on-device) | [zcg-proof](../proof), [PROOF.md](PROOF.md) |
| Network interception defense | Per-app block at the enforcement point | ✅ (gateway) | zcg-proof: 100/100 blocked |
| Anti-evasion / anti-bypass | No traffic slips the enforcement point | ◑ (through the gateway) · 🔭 (full OS, VpnService) | zcg-proof: bypass=NO |
| Low false positives | Don't quarantine legitimate apps | ✅ | benign scenario + zcg-proof (normal app still forwarded) |
| Automated containment | Isolate a compromised app, keep others working | ◑ (per-app block proven) · 🔭 (recovery flow) | zcg-proof RECOVERY section |
| Forensic evidence | Machine-readable record of every action | ◑ (evidence recorder) · 🔭 (full timeline) | `target/zcg-evidence.json` |
| Threat intelligence | IoC database, kept fresh | ◑ (basic IoC) · 🔭 (premium feed) | `examples/ioc-*.json` |
| Real-time forensic engine | Live compromise analysis | 🔭 | — |
| AI behavioral intelligence | Learn threat behavior | 🔭 (rules today; "AI" only when real) | — |
| Android system protection | On-device VpnService, per-app, IPv4/6, TCP/UDP/DNS/QUIC | 🔭 (Level 3) | [ROADMAP](ROADMAP.md) |
| Persistence detection | Detect spyware persistence mechanisms | 🔭 | — |

We will only ever move a row to ✅ when there is a test anyone can re-run.

## The five hard tests we hold ourselves to

Adopted from external review. These define "done" for the defense claims:

1. **Real network attack simulation** — measure actual connections, not simulated
   numbers. → `zcg-proof` (real sockets). ✅ begun.
2. **Verified connection blocking** — prove subsequent attempts fail and the
   controlled C2 receives zero further bytes. → `zcg-proof` VERIFICATION. ✅ on
   desktop; 🔭 on-device.
3. **Android real-device testing** — VpnService, per-app, TCP/UDP/IPv4/IPv6/DNS/
   QUIC, no silent bypass. 🔭 Level 3.
4. **False-positive & evasion testing** — normal apps, flaky links, Wi-Fi↔cellular,
   IP changes, beacon-like-but-benign traffic. ◑ begun (benign controls); 🔭
   expand.
5. **Independent validation** — outside researchers test against scenarios they
   have not seen, and results are published reproducibly. 🔭 — see below.

## Independent red-team: an open invitation

Everything needed to test us is in this repo and runs in
[CI](../.github/workflows/ci.yml): the engine, the benign attack simulators, the
gauntlet, and the verified-blocking proof. If you are a security researcher:
clone it, write a scenario we have **not** seen, and show us a miss or a false
positive. Open an issue with a reproducible case. We would rather you break it in
public than a real adversary break it in silence.

## What we are deliberately NOT doing (yet)

- No "AI" labels until a real model is wired in (rules today are called rules).
- No claim to prevent zero-click exploits — only to detect & contain the behavior.
- No 50-feature dashboard before the core five tests above are solid. Priority #1
  stays **verified prevention**, proven on a real Android device.
