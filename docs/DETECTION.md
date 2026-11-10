# Detection Rules & Scoring System

The `zcg-core` engine is **deterministic**: the same input always produces the same output.
Every `Finding` carries its own reason and score weight — there is no "black box". This
document explains each rule, its thresholds, and how scores become a verdict.

All thresholds are defined in [`core/src/config.rs`](../core/src/config.rs) and are tunable.

## Input: `Observation`

The engine eats a stream of observations (JSONL format, one object per line, distinguished
by the `type` field). See [`core/src/model.rs`](../core/src/model.rs).

| `type` | Meaning | Key fields |
|---|---|---|
| `flow` | One outbound network connection | `app`, `app_background`, `dst_ip`, `dst_port`, `domain`, `bytes_out`, `bytes_in` |
| `media` | App auto-received inbound media | `app`, `bytes` |
| `app_installed` | A new app was installed | `app` |
| `permission` | A permission was granted to an app | `app`, `permission` |
| `accessibility` | Accessibility was enabled for an app | `app` |

Every observation has a `ts` (Unix milliseconds) and is processed **in time order**.

## Rules

### 1. `ioc_match` — IoC list match (+50)
A connection to an IP or domain on the Indicator of Compromise list. Highest weight because
it is the most decisive. Recorded once per unique destination per app.

### 2. `zeroclick_followup` — zero-click follow-up pattern (+40)
A connection to a **NEW external** destination within `zeroclick_window_ms` (default
**120 s**) after the app received inbound **media**. This is the classic zero-click
fingerprint: media processed → exploit → the process phones home.

> Important: only **new** destinations. If, after media, the app contacts a server it
> **already** talks to, it is **not** flagged — this is what keeps false positives down
> (see the `benign` scenario).

**Honest limitation:** this correlation is per-app. If the spyware runs as a process
separate from the app that received the media, this direct correlation can be missed — the
other rules (IoC, beacon, exfil) remain the safety net.

### 3. `accessibility_abuse` — Accessibility abuse (+35)
An app enables an **Accessibility** service *and* holds **sensitive permissions** (e.g.
`RECORD_AUDIO`, `READ_SMS`, `ACCESS_FINE_LOCATION`). This combination is very common in
Android spyware (screen reading + eavesdropping). The sensitive-permission list is in
`config.rs`.

### 4. `beaconing` — beacon pattern (+30)
Repeated connections to the same destination at **highly regular** intervals ("phoning
home"). The algorithm is simple and auditable:

- Collect ≥ `beacon_min_hits` (default **4**) connection times to the same destination.
- Compute the inter-connection intervals, then the **coefficient of variation**
  `CV = stddev / mean`.
- Flag if `CV ≤ beacon_max_cv` (default **0.15**, i.e. jitter < 15%) **and** the mean
  interval is in a plausible range (2 s – 1 h).

A small CV = nearly identical intervals = "robotic". Normal human/app traffic has large
jitter and is not flagged (see the `benign` scenario).

### 5. `exfil_volume` — outbound data spike (+25)
Total `bytes_out` from a **background** app exceeds `exfil_threshold_bytes` (default
**2 MB**) within the `exfil_window_ms` (default **60 s**) window. One alarm per spike
(anti-spam): the alarm "re-arms" once traffic subsides below the threshold.

### 6. `unknown_destination` — unknown destination (+15)
A **background** app contacts an **external** destination it has never contacted before.
Low weight (informational) because it is common; it matters when it stacks with other
signals.

### 7. `new_app` — new app installed (+5)
Just a marker to watch briefly. Very low weight.

## From score to verdict

All of an app's finding scores are **summed**, then mapped (see
[`model.rs`](../core/src/model.rs)):

| Total score | Severity | Label | Action |
|---:|---|---|---|
| 0–9 | `Clean` | SAFE | — |
| 10–29 | `Low` | WATCH | log |
| 30–59 | `Medium` | SUSPICIOUS | notify the user |
| 60–79 | `High` | LIKELY SPYWARE | alert + suggest cutoff |
| ≥ 80 | `Critical` | DANGER | cut off & quarantine |

`Verdict::should_block()` is true for `High` and above.

## Example results

| Scenario | Rules that fire | Total | Verdict |
|---|---|---:|---|
| `zeroclick` | ioc + zeroclick + exfil + unknown + beacon | 130 | **DANGER** |
| `spyware` | accessibility_abuse + ioc + beacon + ... | 135 | **DANGER** |
| `brutal` | all of the above across 3 apps at once | 130 each | **DANGER ×3** |
| `benign` | unknown_destination only (background music) | 15 | WATCH |

Run it yourself: see the [README](../README.md#try-it-yourself-1-minute).

## Tuning thresholds

All numbers live in `config.rs`. Lowering `beacon_max_cv` makes beacon detection stricter
(fewer false positives, but it may miss jittered beacons). Raising `exfil_threshold_bytes`
reduces alarms on apps that legitimately send a lot of data. All of these trade-offs are
**open and auditable** — that is the point of the rule-based approach.
