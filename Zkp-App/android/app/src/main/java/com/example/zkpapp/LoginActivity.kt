package com.example.zkpapp

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.*
import android.util.Log
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.zkpapp.auth.ZkAuthManager
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.coroutines.launch

/**
 * LoginActivity - Web QR Login with Benchmark
 *
 * Flow:
 * 1️⃣ Scan Web QR → Generate ZKP Proof
 * 2️⃣ Benchmark display → Redirect back to Dashboard
 * 3️⃣ Handles errors gracefully and allows rescan
 */
class LoginActivity : AppCompatActivity() {

    companion object {
        init {
            try {
                System.loadLibrary("zkp_mobile")
            } catch (e: UnsatisfiedLinkError) {
                Log.e("ZKP", "Native library failed to load", e)
            }
        }
    }

    private lateinit var statusText: TextView
    private var qrCardView: View? = null
    private val hideViewsIds = listOf(
        R.id.imgDynamicQr,
        R.id.btnTransmit,
        R.id.btnGotoScanner
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)

        statusText = findViewById(R.id.tvStatus)
        qrCardView = findViewById<View>(R.id.imgDynamicQr)?.let { findRootCard(it) }

        // 🛡 Identity must exist
        if (!IdentityStorage.hasIdentity()) {
            Toast.makeText(this, "⚠️ Identity Missing", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        hideViewsSmart()
        showStatus("🦁 Starting Web Scanner...", Color.WHITE)
        startWebQrScanner()
    }

    // ------------------------------
    // Smart view hiding
    // ------------------------------
    private fun findRootCard(view: View): View {
        var parent = view.parent
        var lastView: View? = view
        while (parent is ViewGroup) {
            lastView = parent
            parent = parent.parent
        }
        return lastView ?: view
    }

    private fun hideViewsSmart() {
        qrCardView?.visibility = View.GONE
        hideViewsIds.forEach { id ->
            findViewById<View>(id)?.visibility = View.GONE
        }
    }

    private fun showStatus(text: String, color: Int, size: Float = 20f) {
        statusText.apply {
            this.text = text
            setTextColor(color)
            textSize = size
        }
    }

    // ------------------------------
    // Web QR Scanner
    // ------------------------------
    private fun startWebQrScanner() {
        IntentIntegrator(this).apply {
            setCaptureActivity(PortraitCaptureActivity::class.java)
            setOrientationLocked(true)
            setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
            setPrompt("🦁 Scan Web Login QR")
            setCameraId(0)
            setBeepEnabled(true)
            setBarcodeImageEnabled(false)
            initiateScan()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        IntentIntegrator.parseActivityResult(requestCode, resultCode, data)?.let { result ->
            if (result.contents == null) finish()
            else performZkLogin(result.contents)
        } ?: super.onActivityResult(requestCode, resultCode, data)
    }

    // ------------------------------
    // ZKP Proof Generation + Benchmark
    // ------------------------------
    private fun performZkLogin(sessionId: String) {
        statusText.setOnClickListener(null)
        showStatus("🦁 Generating Proof...", Color.parseColor("#FF9800"))

        lifecycleScope.launch {
            ZkAuthManager.startUniversalLogin(
                context = this@LoginActivity,
                sessionId = sessionId,

                onStatus = { msg -> showStatus(msg, Color.parseColor("#FF9800")) },

                onSuccess = { meta ->
                    triggerVibration(150)

                    val benchmarkReport = """
                        ✅ LOGIN APPROVED!
                        
                        ⏱️ Time: ${meta.generation_time_ms} ms
                        📦 Size: ${meta.proof_size_bytes} bytes
                        ⚙️ Gates: ${meta.num_gates}
                        🔑 ID: #${meta.proof_id}
                        
                        (Redirecting to Dashboard in 4s...)
                    """.trimIndent()

                    showStatus(benchmarkReport, Color.parseColor("#4CAF50"), 18f)

                    // Redirect back to Dashboard instead of OfflineMenu
                    Handler(Looper.getMainLooper()).postDelayed({
                        Toast.makeText(this@LoginActivity, "Login Successful!", Toast.LENGTH_SHORT).show()
                        startActivity(Intent(this@LoginActivity, MainActivity::class.java).apply {
                            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                        })
                        finish()
                    }, 4000)
                },

                onError = { error ->
                    Toast.makeText(this@LoginActivity, error, Toast.LENGTH_SHORT).show()
                    triggerVibration(500)
                    showStatus("🦁 Scan Web Login QR", Color.WHITE)
                    Handler(Looper.getMainLooper()).postDelayed({ startWebQrScanner() }, 800)
                }
            )
        }
    }

    private fun triggerVibration(durationMs: Long) {
        (getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator)?.let { vibrator ->
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                vibrator.vibrate(VibrationEffect.createOneShot(durationMs, VibrationEffect.DEFAULT_AMPLITUDE))
            } else {
                @Suppress("DEPRECATION")
                vibrator.vibrate(durationMs)
            }
        }
    }
}
