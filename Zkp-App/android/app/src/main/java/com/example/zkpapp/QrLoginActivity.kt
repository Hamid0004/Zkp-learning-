package com.example.zkpapp

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.*
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * QrLoginActivity v3.0 — ZKAuth QR Scanner
 *
 * v2.0 → v3.0 Changes:
 * 🔴 Removed ECDSA signature check — QR now contains deep_link directly
 * 🔴 Removed ALLOWED_ORIGINS whitelist — Railway URL hardcoded check
 * 🟢 Two QR formats supported:
 * Format A: zkauth:// deep link (direct — website button)
 * Format B: base64 JSON with deep_link field (server QR)
 * 🟢 Both formats route to AuthActivity via same deep link
 */
class QrLoginActivity : AppCompatActivity() {

    private lateinit var viewFinder: PreviewView
    private val cameraExecutor = Executors.newSingleThreadExecutor()
    private val scanLocked     = AtomicBoolean(false)

    companion object {
        private const val TAG = "QrLoginActivity"
        private const val REQUEST_CAMERA = 200
        private const val MAX_AGE_SECONDS = 900L  // 15 min — matches server SESSION_TTL
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_qr_login)
        viewFinder = findViewById(R.id.viewFinder)

        if (hasCameraPermission()) startCamera()
        else ActivityCompat.requestPermissions(
            this,
            arrayOf(Manifest.permission.CAMERA),
            REQUEST_CAMERA
        )
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_CAMERA &&
            grantResults.firstOrNull() == PackageManager.PERMISSION_GRANTED
        ) startCamera()
        else { showError("Camera permission required."); finish() }
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
    }

    // ── Camera ────────────────────────────────────────────────────────────────

    private fun startCamera() {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)
        cameraProviderFuture.addListener({
            val cameraProvider = cameraProviderFuture.get()

            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(viewFinder.surfaceProvider)
            }

            val analyzer = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
                .also {
                    it.setAnalyzer(cameraExecutor) { proxy -> processImageProxy(proxy) }
                }

            cameraProvider.unbindAll()
            cameraProvider.bindToLifecycle(
                this,
                CameraSelector.DEFAULT_BACK_CAMERA,
                preview,
                analyzer
            )
        }, ContextCompat.getMainExecutor(this))
    }

    @androidx.camera.core.ExperimentalGetImage
    private fun processImageProxy(imageProxy: ImageProxy) {
        val mediaImage = imageProxy.image ?: run { imageProxy.close(); return }
        val image = InputImage.fromMediaImage(mediaImage, imageProxy.imageInfo.rotationDegrees)

        BarcodeScanning.getClient()
            .process(image)
            .addOnSuccessListener { barcodes ->
                for (barcode in barcodes) {
                    if (barcode.format == Barcode.FORMAT_QR_CODE) {
                        handleQrDetected(barcode.rawValue)
                    }
                }
            }
            .addOnFailureListener { Log.w(TAG, "Barcode error", it) }
            .addOnCompleteListener { imageProxy.close() }
    }

    // ── QR Handler ────────────────────────────────────────────────────────────

    private fun handleQrDetected(rawValue: String?) {
        if (rawValue == null)   return
        if (scanLocked.get())   return

        Log.d(TAG, "QR detected: ${rawValue.take(60)}...")

        // Try to extract deep link from QR
        val deepLink = extractDeepLink(rawValue)

        if (deepLink == null) {
            Log.w(TAG, "QR rejected — no valid deep link found")
            runOnUiThread { showError("Invalid QR code — please scan a ZKAuth QR") }
            return
        }

        // Validate deep link
        if (!isValidDeepLink(deepLink)) {
            runOnUiThread { showError("QR code is invalid or expired.") }
            return
        }

        // Claim scan lock
        if (!scanLocked.compareAndSet(false, true)) return

        Log.i(TAG, "✅ Valid QR → launching AuthActivity")

        runOnUiThread {
            // Launch via deep link → AuthActivity handles routing
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(deepLink)).apply {
                setPackage(packageName)  // stay in our app
            }
            startActivity(intent)
            finish()
        }
    }

    // ── Deep Link Extraction ──────────────────────────────────────────────────

    /**
     * Extracts zkauth:// deep link from QR content.
     *
     * Supports 2 formats:
     * Format A — Direct deep link:
     * zkauth://auth?domain=X&claim=Y&challenge=Z&callback=W&session=S&tier=T
     *
     * Format B — Server base64 JSON (QR on website desktop):
     * base64{ sessionId, domain, challenge, deep_link, timestamp }
     */
    private fun extractDeepLink(raw: String): String? {
        // Format A — direct zkauth:// link
        if (raw.startsWith("zkauth://")) {
            return raw
        }

        // Format B — base64 JSON with deep_link field
        return try {
            val decoded = String(Base64.decode(raw, Base64.DEFAULT), Charsets.UTF_8)
            val json    = JSONObject(decoded)

            // Check timestamp freshness
            val timestamp = json.optLong("timestamp", 0L)
            if (timestamp > 0) {
                val ageSeconds = (System.currentTimeMillis() - timestamp) / 1000L
                if (ageSeconds > MAX_AGE_SECONDS) {
                    Log.w(TAG, "QR too old: ${ageSeconds}s > ${MAX_AGE_SECONDS}s")
                    return null
                }
            }

            // Extract deep_link
            val link = json.optString("deep_link", "")
            if (link.isNotEmpty()) {
                link
            } else {
                // Fallback — reconstruct from fields if deep_link missing
                val sessionId = json.optString("sessionId", "")
                val challenge = json.optString("challenge", "")
                val domain    = json.optString("domain", "")
                if (sessionId.isEmpty() || challenge.isEmpty()) return null
                // Can't reconstruct full deep link without callback — return null
                Log.w(TAG, "deep_link field missing in QR JSON")
                null
            }
        } catch (e: Exception) {
            Log.w(TAG, "QR parse failed: ${e.message}")
            null
        }
    }

    // ── Deep Link Validation ──────────────────────────────────────────────────

    private fun isValidDeepLink(deepLink: String): Boolean {
        return try {
            val uri = Uri.parse(deepLink)

            // Must be zkauth://auth
            if (uri.scheme != "zkauth" || uri.host != "auth") {
                Log.w(TAG, "Invalid scheme/host: ${uri.scheme}://${uri.host}")
                return false
            }

            // Must have required params
            val challenge = uri.getQueryParameter("challenge") ?: return false
            val callback  = uri.getQueryParameter("callback")  ?: return false
            val domain    = uri.getQueryParameter("domain")    ?: return false

            // Challenge must be at least 32 chars
            if (challenge.length < 32) {
                Log.w(TAG, "Challenge too short: ${challenge.length}")
                return false
            }

            // Callback must be HTTPS or Railway
            val isSecure = callback.startsWith("https://") ||
                callback.contains("railway.app") ||
                callback.startsWith("http://localhost") ||
                callback.startsWith("http://127.0.0.1")

            if (!isSecure) {
                Log.w(TAG, "Insecure callback: $callback")
                return false
            }

            Log.d(TAG, "✅ Deep link valid | domain=$domain")
            true
        } catch (e: Exception) {
            Log.w(TAG, "Deep link validation failed: ${e.message}")
            false
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun hasCameraPermission() =
        ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED

    private fun showError(message: String) =
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
}