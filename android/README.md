# zeroclick-guard — Android (Level 3)

The on-device rung of the [proof ladder](../docs/PROOF.md): a real `VpnService`
tap feeding the same `zcg-core` engine, enforcing per-app blocking, and proving
it on an emulator in CI.

## Honest status

This is built in phases, and only CI-green phases are claimed as working.

| Phase | Goal | Status |
|---|---|---|
| **A** | Android app builds; `VpnService` tap established; packets parsed | 🔨 in progress (this) |
| **B** | `zcg-core` (Rust) wired in via JNI (`cargo-ndk`), same engine on device | 🔭 next |
| **C** | Instrumented emulator test proving per-app blocking on-device | 🔭 next |

**Phase A does not provide protection.** The service establishes the TUN and
reads/parses packets, but does not yet feed the engine, forward allowed traffic,
or drop blocked traffic. It is the plumbing the later phases build on. Do not
ship it as-is.

## Build

CI builds it on every push to `android/**` (see
[`.github/workflows/android.yml`](../.github/workflows/android.yml)); the debug
APK is uploaded as an artifact.

Locally, with Android Studio (easiest) or the SDK + Gradle 8.9:

```bash
cd android
gradle assembleDebug        # or ./gradlew once a wrapper is generated
```

Requires JDK 17 and Android SDK platform 34.

## Why VpnService

On a non-rooted device, a local `VpnService` is the one place an app can see and
control another app's outbound traffic — the same role the desktop proof's
"guard gateway" played. It is how NetGuard and TrackerControl work. It lets us:

- observe outbound flows (destination, size, timing) → feed `zcg-core`;
- enforce a **per-app** block by dropping that app's packets;
- do it with **no root**.

What it cannot do: prevent the initial zero-click exploit (that is inside another
app's sealed process). This is detection + containment — see the top-level
[README](../README.md) and [docs/VISION.md](../docs/VISION.md).
