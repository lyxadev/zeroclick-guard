package ai.lyxvo.zeroclickguard

/**
 * Kotlin handle to the native `zcg-core` engine (the SAME Rust engine the
 * desktop tools use), loaded as `libzcg_android.so`.
 *
 * Usage:
 *   val h = NativeEngine.create()
 *   val score = NativeEngine.observeFlow(h, ts, app, background, dstIp, dstPort, bytesOut)
 *   NativeEngine.destroy(h)
 */
object NativeEngine {
    init {
        System.loadLibrary("zcg_android")
    }

    /** Create an engine; returns an opaque handle. */
    external fun create(): Long

    /** Feed one flow; returns the app's current cumulative score. */
    external fun observeFlow(
        handle: Long,
        ts: Long,
        app: String,
        background: Boolean,
        dstIp: String,
        dstPort: Int,
        bytesOut: Long,
    ): Int

    /** Free an engine handle. */
    external fun destroy(handle: Long)
}
