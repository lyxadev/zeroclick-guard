# zeroclick-guard — Android (Level 3)

The on-device rung of the [proof ladder](../docs/PROOF.md): a real `VpnService`
tap feeding the same `zcg-core` engine, enforcing per-app blocking, and proving
it on an emulator in CI.

## Honest status

This is built in phases, and only CI-green phases are claimed as working.

| Phase | Goal | Status |
|---|---|---|
| **A** | Android app builds; `VpnService` tap established; packets parsed | ✅ CI-green |
| **B** | `zcg-core` (Rust) wired in via JNI (`cargo-ndk`), same engine on device | ✅ CI-green |
| **C1** | Emulator test: the real engine runs on-device and flags spyware behavior | ✅ CI-green |
| **C2** | On-device `VpnService` forwarding + per-app block, verified on emulator | 🔭 next |

**What is proven (in CI, on an emulator):** the exact same `zcg-core` engine,
compiled for Android and called over JNI, runs on a real Android runtime and
flags spyware behavior (score ≥ 60, behavior-only) while keeping a normal app
low. See [`NativeEngineTest`](app/src/androidTest/kotlin/ai/lyxvo/zeroclickguard/NativeEngineTest.kt)
and the [Android workflow](../.github/workflows/android.yml).

**What is NOT done yet (C2):** the `VpnService` still only establishes the TUN
and parses packets — it does not yet forward allowed traffic or drop blocked
traffic. So the app does not provide on-device protection yet; the desktop proof
([PROOF.md](../docs/PROOF.md)) already demonstrates the enforce-and-verify
mechanism, and C2 brings it onto the device. Do not ship this as protection yet.

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
