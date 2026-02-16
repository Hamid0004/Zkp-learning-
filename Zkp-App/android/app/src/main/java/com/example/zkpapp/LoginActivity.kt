package com.example.zkpapp

import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.VibrationEffect
import android.os.Vibrator
import android.util.Log
import android.view.View
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.zkpapp.auth.ZkAuthManager
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.coroutines.launch

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

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_login)

        statusText = findViewById(R.id.tvStatus)

        val qrImage = findViewById<View>(R.id.imgDynamicQr)
        val parent1 = qrImage?.parent as? View
        val parent2 = parent1?.parent as? View
        val parent3 = parent2?.parent as? View
        qrCardView = parent3 ?: parent2

        // Identity Check
        if (!IdentityStorage.hasIdentity()) {
            Toast.makeText(this, "⚠️ Identity Missing", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        // Hide unnecessary UI
        qrCardView?.visibility = View.GONE
        findViewById<View>(R.id.imgDynamicQr)?.visibility = View.GONE
        findViewById<View>(R.id.btnTransmit)?.visibility = View.GONE
        findViewById<View>(R.id.btnGotoScanner)?.visibility = View.GONE

        statusText.text = "🦁 Starting Web Scanner..."
        statusText.setTextColor(Color.WHITE)

        startWebQrScanner()
    }

    // -----------------------------------------------------------
    // 🔵 WEB LOGIN LOGIC
    // -----------------------------------------------------------

    private fun startWebQrScanner() {
        val integrator = IntentIntegrator(this)
        integrator.setCaptureActivity(PortraitCaptureActivity::class.java)
        integrator.setOrientationLocked(true)
        integrator.setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
        integrator.setPrompt("🦁 Scan Web Login QR")
        integrator.setCameraId(0)
        integrator.setBeepEnabled(true)
        integrator.setBarcodeImageEnabled(false)
        integrator.initiateScan()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        val result = IntentIntegrator.parseActivityResult(requestCode, resultCode, data)
        if (result != null) {
            if (result.contents == null) {
                finish()
            } else {
                performZkLogin(result.contents)
            }
        } else {
            super.onActivityResult(requestCode, resultCode, data)
        }
    }

    private fun performZkLogin(sessionId: String) {

        statusText.setOnClickListener(null) // Clear old retry listener

        statusText.text = "🦁 Generating Proof..."
        statusText.setTextColor(Color.parseColor("#FF9800"))
        statusText.textSize = 20f

        lifecycleScope.launch {
            ZkAuthManager.startUniversalLogin(
                context = this@LoginActivity,
                sessionId = sessionId,

                onStatus = { msg ->
                    statusText.text = msg
                },

                // 🦁 CHANGE 1: Receive Metadata Here
                onSuccess = { meta ->
                    
                    // 1. Success Haptic Feedback
                    val vibrator = getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
                    if (android.os.Build.VERSION.SDK_INT >= 26) {
                        vibrator.vibrate(VibrationEffect.createOneShot(150, VibrationEffect.DEFAULT_AMPLITUDE))
                    } else {
                        vibrator.vibrate(150)
                    }

                    // 2. Display Benchmark Report
                    val benchmarkReport = """
                        ✅ LOGIN APPROVED!
                        
                        ⏱️ Time: ${meta.generation_time_ms} ms
                        📦 Size: ${meta.proof_size_bytes} bytes
                        ⚙️ Gates: ${meta.num_gates}
                        🔑 ID: #${meta.proof_id}
                        
                        (Auto-closing in 4s...)
                    """.trimIndent()

                    statusText.text = benchmarkReport
                    statusText.setTextColor(Color.parseColor("#4CAF50")) // Green
                    statusText.textSize = 18f 

                    Toast.makeText(this@LoginActivity, "Login Successful!", Toast.LENGTH_SHORT).show()

                    // 3. Hold screen for 4 seconds so you can read it
                    Handler(Looper.getMainLooper()).postDelayed({
                        finish()
                    }, 4000)
                },

                // 4. Error Handling
                onError = { error ->
                    statusText.text = "$error\n\nTap to retry"
                    statusText.setTextColor(Color.RED)

                    // Error ke liye bhi thodi vibration
                    val vibrator = getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
                    if (android.os.Build.VERSION.SDK_INT >= 26) {
                         vibrator.vibrate(VibrationEffect.createOneShot(500, VibrationEffect.DEFAULT_AMPLITUDE))
                    }

                    Toast.makeText(this@LoginActivity, error, Toast.LENGTH_LONG).show()

                    // Retry on tap
                    statusText.setOnClickListener {
                        statusText.setOnClickListener(null)
                        statusText.text = "🦁 Restarting Scanner..."
                        statusText.setTextColor(Color.WHITE)

                        Handler(Looper.getMainLooper()).postDelayed({
                            startWebQrScanner()
                        }, 800)
                    }
                }
            )
        }
    }
}