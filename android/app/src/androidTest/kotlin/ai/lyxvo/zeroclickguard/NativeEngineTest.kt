package ai.lyxvo.zeroclickguard

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device proof (Level 3): the SAME `zcg-core` engine, compiled for Android
 * and called over JNI, flags spyware behavior while running on a real Android
 * runtime (the emulator in CI). Purely behavioral — no IoC list is loaded.
 */
@RunWith(AndroidJUnit4::class)
class NativeEngineTest {

    @Test
    fun detectsSpywareBehaviorOnDevice() {
        val h = NativeEngine.create()
        assertTrue("engine handle should be non-zero", h != 0L)
        try {
            val app = "com.demo.spyware"
            val c2 = "203.0.113.5" // external (RFC 5737 test address)
            var score = 0

            // A real exfil-sized flow, then a regular beacon to the same C2.
            score = NativeEngine.observeFlow(h, 0L, app, true, c2, 443, 3_000_000L)
            for (i in 1..5) {
                score = NativeEngine.observeFlow(h, i * 60_000L, app, true, c2, 443, 800L)
            }

            // unknown_destination(+15) + exfil(+25) + beacon(+30) = 70 → High+.
            assertTrue("expected a High/Critical score, got $score", score >= 60)
        } finally {
            NativeEngine.destroy(h)
        }
    }

    @Test
    fun normalAppStaysLow() {
        val h = NativeEngine.create()
        try {
            // Foreground app, irregular, modest traffic → should not alarm.
            val app = "com.good.app"
            val offsets = longArrayOf(0, 3_000, 47_000, 230_000)
            var score = 0
            for (t in offsets) {
                score = NativeEngine.observeFlow(h, t, app, false, "203.0.113.9", 443, 500L)
            }
            assertTrue("normal app should stay below alarm, got $score", score < 30)
        } finally {
            NativeEngine.destroy(h)
        }
    }
}
