package com.example.zkpapp

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
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

    external fun stringFromRust(): String

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

                onSuccess = {
                    statusText.text = "✅ Login Approved!"
                    statusText.setTextColor(Color.parseColor("#2E7D32"))

                    Toast.makeText(
                        this@LoginActivity,
                        "Web Login Successful!",
                        Toast.LENGTH_LONG
                    ).show()

                    Handler(Looper.getMainLooper()).postDelayed({
                        finish()
                    }, 1500)
                },

                // ✅ UPDATED ERROR HANDLING (No Auto Close)
                onError = { error ->
                    statusText.text = "❌ $error\n\nTap to retry"
                    statusText.setTextColor(Color.RED)

                    Toast.makeText(
                        this@LoginActivity,
                        error,
                        Toast.LENGTH_LONG
                    ).show()

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
