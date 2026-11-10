package ai.lyxvo.zeroclickguard

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.net.VpnService
import android.os.Bundle
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

/**
 * Minimal launcher UI. Phase A: it wires up the VpnService consent flow and can
 * start the (scaffold) service. The real-time detection + per-app blocking that
 * make this useful land in Phase B/C (Rust core via JNI, then the emulator-
 * verified blocking test). See android/README.md for honest status.
 */
class MainActivity : Activity() {

    private val vpnRequest = 1

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(64, 128, 64, 64)
            setBackgroundColor(Color.parseColor("#0d1117"))
        }

        root.addView(TextView(this).apply {
            text = "⚡ ZeroClick Guard"
            textSize = 26f
            setTextColor(Color.parseColor("#39c5cf"))
        })
        root.addView(TextView(this).apply {
            text = "Real-time spyware & zero-click shield\n(early development)"
            textSize = 14f
            setTextColor(Color.parseColor("#8b949e"))
            setPadding(0, 16, 0, 48)
        })

        root.addView(Button(this).apply {
            text = "Enable protection (local VPN)"
            setOnClickListener { requestVpn() }
        })

        setContentView(root)
    }

    private fun requestVpn() {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, vpnRequest)
        } else {
            onActivityResult(vpnRequest, RESULT_OK, null)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == vpnRequest && resultCode == RESULT_OK) {
            startService(Intent(this, ZcgVpnService::class.java))
        }
    }
}
