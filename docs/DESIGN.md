# Design Reference — zeroclick-guard

This document is the project's "map": vision, what is realistic (and what is not),
architecture, honesty principles, the open vs. paid split, and business direction. Design
decisions trace back here.

---

## 1. Vision

> Become the most **usable** and most **honest** anti-spyware shield — especially for
> Indonesia & Southeast Asia, a market no one has served seriously — so that journalists,
> activists, lawyers, and ordinary people can **know** when they are being watched, and
> **stop** the damage.

We do **not** try to "beat Pegasus" in the sense of preventing a nation-state exploit. That
is not realistic on a non-rooted device. Our target is the **defensive** side: fast
detection + cutoff + an explanation an ordinary person can understand.

## 2. What is realistic — and what is NOT

### The hard reality of Android
Android sandboxes apps strictly. Without **root**, one app **cannot** see another app's
memory, syscalls, or files. This is an OS limit, not a programming-language limit. So:

| Zero-click attack phase | Can we handle it (non-root)? |
|---|---|
| Malicious media sent | Not visible |
| Media auto-processed, exploit runs | ❌ **No** — inside another app's process |
| Spyware active in memory | Partly (via side effects) |
| **Spyware connects to C2 / exfiltrates data** | ✅ **Yes — this is our strength** |
| Spyware requests permissions / Accessibility | ✅ Yes |

**The honest core promise:** _"We do not prevent the zero-click exploit. We detect the
post-exploitation behavior — C2, exfiltration, permission abuse — and cut it off, within
seconds."_

### What is doable without root (and proven in the industry)
- **Local VpnService** — route all device traffic through a VPN *inside the device itself*
  (not to any server) to inspect connection destinations. (NetGuard, TrackerControl approach.)
- **IoC matching** — match destinations against known spyware indicators. (Amnesty
  International's MVT approach.)
- **Behavioral detection** — beaconing, exfiltration, unknown destinations, permission abuse.

## 3. Why NO AI (for now)

The core engine is **deterministic and rule-based**, not AI. This is a deliberate choice,
not a shortcoming:

- **Auditable** — every decision has a definite reason; no "hallucinations".
- **Fast & light** — real-time on device, battery-friendly, no server calls.
- **Free & private** — no data sent to the cloud, no bills.
- **Works offline.**

Most world-class security tools (firewalls, IDS like Suricata/Snort) are rule-based, not AI.
AI **does not add detection power** — it would (later) only improve the *explanations* and
reduce false positives in gray-area cases. See Roadmap Phase 2.

> **Honest naming rule:** until a real AI model exists, the explanation feature is called
> **"rule-based"**, not "AI". No "AI" claim until there is actually AI.

## 4. Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  OBSERVATION SOURCES (pluggable)                             │
│   • Android VpnService  • desktop pcap  • test simulator     │
└───────────────────────────┬─────────────────────────────────┘
                            │  Observation stream (JSONL / in-proc)
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  zcg-core  (Rust, deterministic)                             │
│   IoC ─ zero-click correlation ─ beacon ─ exfil ─ perms ─ score │
└───────────────────────────┬─────────────────────────────────┘
                            │  Finding + Verdict
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  ACTION:  alert  ·  cut off  ·  guidance  ·  (later) AI       │
└─────────────────────────────────────────────────────────────┘
```

**Key:** `zcg-core` does not know where observations come from. So the same engine runs in
the Android product **and** in the demo/tests — there are not two versions, and nothing is
faked.

### Rust vs. Kotlin (for Android, later)
An Android app **cannot** be pure Rust. The split:
- **Kotlin** → the shell: VpnService, UI, permissions, system events (PackageManager,
  Accessibility).
- **Rust (`zcg-core` via JNI/`uniffi`)** → the engine: packet parsing, rules, scoring, IoC.

The same Rust core can be reused on desktop (Linux/Windows) later.

## 5. Demo honesty principles (the red line)

The demo shows an "attacker" (benign simulator) vs. a "defender" (the real engine).

- ✅ **The defender is 100% real.** Alerts, scores, cutoff — all from the real engine.
- ✅ **The attacker is a benign behavior simulator.** It generates real traffic/observations
  but with no exploit and no real data (it uses RFC 5737 test addresses & RFC 2606 domains).
- ❌ **It is FORBIDDEN** to fake the defender's response (hard-coded alerts, animations
  without the engine). The demo **must** call the same engine as the product.

Reason: if we cheat even slightly, the moment an expert tests with a real attack and the
engine stays silent → the reputation is gone for good. For a security tool, trust is
everything.

**We do not build real spyware.** The "attacker" side is always a behavior simulator.
Building functional spyware is dangerous, can leak / be abused, and is illegal — and it is
unnecessary: what needs testing is the *behavior* being detected, not the exploit.

## 6. Open vs. paid model (open-core)

Closed-source security tools are hard to trust. So our core is **open source** (building
trust + community + public audit), while monetization lives in the service layer.

| Open (free, open source) | Paid / private |
|---|---|
| Core detection engine (`zcg-core`) | Premium IoC feed (fresh, curated) |
| VpnService + basic rules | AI explanation layer (Phase 2) |
| Simulator / test lab | B2B dashboard / team management |
| Basic IoC list | Support & SLA |

**Principle:** what builds **trust** → open. What builds **revenue** → held back. The money
is in *service + data + support*, not in the core code.

The **GPLv3** license keeps the core code from quietly becoming a closed product.

## 7. Position vs. alternatives

| | Focus | The gap we fill |
|---|---|---|
| **MVT** (Amnesty) | Forensic IoC, open source | Too technical for ordinary people |
| **iVerify** | Mobile spyware detection (commercial) | Expensive, English-only |
| **Lookout / Zimperium** | Enterprise | Expensive, not for individuals |
| **zeroclick-guard** | Real-time behavioral detection | **Easy, localized, affordable, open** |

## 8. Business direction (short & realistic)

- **B2B first** (newsrooms, NGOs, law firms): few buyers, but they pay seriously and
  steadily. One organization contract = hundreds of individual users. The fastest path to
  revenue.
- **High-risk individuals** (journalists, activists): subscription / freemium.
- Revenue comes from **service subscriptions + IoC feed + B2B support**, not from the code,
  which is free.

> Honest note: open source is a **trust & marketing** engine, not a direct revenue engine.
> "Going viral" is the exception — it takes real quality + consistent work, not automatic.

## 9. Short roadmap

1. **Phase 1 (now, free):** real detection engine + simulator + CLI demo. ✅ working.
2. **Phase 1b:** Android integration (VpnService + Kotlin shell).
3. **Phase 2 (when there is budget):** AI explanation layer (e.g. Cloudflare Workers AI),
   pluggable — without touching the engine.
4. **Phase 3:** B2B dashboard, IoC feed, monetization.

Details: [ROADMAP.md](ROADMAP.md).

## Contact

- Website: [lyxvo.ai](https://lyxvo.ai) · [siappergi.com](https://siappergi.com)
- Email: halo@siappergi.com
