package ai.lyxvo.zeroclickguard

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.FileInputStream
import kotlin.concurrent.thread

/**
 * The on-device tap. A VpnService creates a local TUN interface and every
 * outbound packet is handed to us — exactly the "sensor" the desktop proof
 * modeled. This is where, on a real device, the same `zcg-core` engine will
 * judge flows and where blocked apps' packets will be dropped.
 *
 * HONEST STATUS (Phase A scaffold):
 *   - It establishes the TUN and reads packets, parsing IPv4/TCP/UDP headers to
 *     extract the destination and size of each flow.
 *   - It does NOT yet forward allowed traffic, feed `zcg-core`, or enforce
 *     per-app blocking. So this scaffold does not provide protection yet; it is
 *     the plumbing the Phase B/C work builds on. Do not ship it as-is.
 */
class ZcgVpnService : VpnService() {

    private var tun: ParcelFileDescriptor? = null
    @Volatile
    private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (running) return START_STICKY

        val builder = Builder()
            .setSession("ZeroClickGuard")
            .addAddress("10.111.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .setMtu(MTU)

        tun = builder.establish()
        if (tun == null) {
            Log.e(TAG, "failed to establish TUN interface")
            stopSelf()
            return START_NOT_STICKY
        }

        running = true
        thread(name = "zcg-tun") { readLoop() }
        Log.i(TAG, "VPN tap established")
        return START_STICKY
    }

    private fun readLoop() {
        val fd = tun?.fileDescriptor ?: return
        val input = FileInputStream(fd)
        val packet = ByteArray(MTU * 4)
        while (running) {
            val n = try {
                input.read(packet)
            } catch (e: Exception) {
                break
            }
            if (n > 0) {
                onPacket(packet, n)
            }
        }
    }

    /**
     * Extract a minimal flow descriptor from a raw packet. Phase B feeds this
     * into `zcg-core` (via JNI) and uses the verdict to drop or forward.
     */
    private fun onPacket(data: ByteArray, len: Int) {
        if (len < 20) return
        val version = (data[0].toInt() ushr 4) and 0xF
        if (version != 4) return // IPv6 comes later (Phase C)

        val ihl = (data[0].toInt() and 0xF) * 4
        if (ihl < 20 || len < ihl) return
        val proto = data[9].toInt() and 0xFF
        val dst = buildString {
            append(data[16].toInt() and 0xFF); append('.')
            append(data[17].toInt() and 0xFF); append('.')
            append(data[18].toInt() and 0xFF); append('.')
            append(data[19].toInt() and 0xFF)
        }
        var dport = 0
        if ((proto == PROTO_TCP || proto == PROTO_UDP) && len >= ihl + 4) {
            dport = ((data[ihl].toInt() and 0xFF) shl 8) or (data[ihl + 1].toInt() and 0xFF)
        }

        // TODO(Phase B): val verdict = ZcgCore.observeFlow(appUidFor(dst), dst, dport, proto, len)
        //                if (verdict.block) return   // drop: do not forward
        //                else forwardToUpstream(data, len)
        Log.d(TAG, "flow dst=$dst:$dport proto=$proto len=$len")
    }

    override fun onDestroy() {
        running = false
        try {
            tun?.close()
        } catch (_: Exception) {
        }
        tun = null
        super.onDestroy()
    }

    companion object {
        private const val TAG = "zcg"
        private const val MTU = 1500
        private const val PROTO_TCP = 6
        private const val PROTO_UDP = 17
    }
}
