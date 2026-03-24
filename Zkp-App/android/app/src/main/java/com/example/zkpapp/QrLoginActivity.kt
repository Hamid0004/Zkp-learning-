package com.example.zkpapp

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.util.Log
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.appcompat.app.AppCompatActivity
import androidx.camera.core.*
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import org.json.JSONObject
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * QrLoginActivity v3.0 — ZKAuth QR Scanner (Jetpack Compose)
 *
 * v2.0 → v3.0:
 * 🔴 Removed XML layout — full Compose UI
 * 🔴 Removed ECDSA signature check
 * 🔴 Removed ALLOWED_ORIGINS whitelist
 * 🟢 Format A: zkauth:// deep link direct
 * 🟢 Format B: base64 JSON with deep_link field
 * 🟢 Both → AuthActivity via deep link
 */
class QrLoginActivity : AppCompatActivity() {

    private val cameraExecutor = Executors.newSingleThreadExecutor()
    private val scanLocked     = AtomicBoolean(false)

    companion object {
        private const val TAG             = "QrLoginActivity"
        private const val REQUEST_CAMERA  = 200
        private const val MAX_AGE_SECONDS = 900L  // 15 min
    }

    // ── Lifecycle ─────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        setContent {
            QrScanScreen()
        }

        if (!hasCameraPermission()) {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.CAMERA),
                REQUEST_CAMERA
            )
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == REQUEST_CAMERA &&
            grantResults.firstOrNull() != PackageManager.PERMISSION_GRANTED
        ) {
            Toast.makeText(this, "Camera permission required.", Toast.LENGTH_SHORT).show()
            finish()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
    }

    // ── Compose UI ────────────────────────────────────────────

    @Composable
    private fun QrScanScreen() {
        val context = LocalContext.current

        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color(0xFF020510)),
            contentAlignment = Alignment.Center,
        ) {
            // Camera preview
            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory  = { ctx ->
                    val previewView = PreviewView(ctx)
                    startCamera(previewView)
                    previewView
                }
            )

            // Overlay
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.Center,
            ) {
                Text(
                    text      = "🦁 SCAN WEB LOGIN QR",
                    color     = Color(0xFF00E5FF),
                    fontSize  = 14.sp,
                    fontFamily= FontFamily.Monospace,
                    letterSpacing = 2.sp,
                    modifier  = Modifier.padding(bottom = 24.dp),
                )

                // Scan frame
                Box(
                    modifier = Modifier
                        .size(220.dp)
                        .clip(RoundedCornerShape(12.dp))
                        .border(
                            width = 2.dp,
                            color = Color(0xFF00E5FF),
                            shape = RoundedCornerShape(12.dp),
                        )
                        .background(Color(0x1A00E5FF))
                )

                Text(
                    text      = "Point camera at ZKAuth QR code",
                    color     = Color(0x997A99C0),
                    fontSize  = 11.sp,
                    fontFamily= FontFamily.Monospace,
                    textAlign = TextAlign.Center,
                    modifier  = Modifier.padding(top = 20.dp, start = 32.dp, end = 32.dp),
                )
            }
        }
    }

    // ── Camera ────────────────────────────────────────────────

    private fun startCamera(previewView: PreviewView) {
        val cameraProviderFuture = ProcessCameraProvider.getInstance(this)
        cameraProviderFuture.addListener({
            val cameraProvider = cameraProviderFuture.get()

            val preview = Preview.Builder().build().also {
                it.setSurfaceProvider(previewView.surfaceProvider)
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

    // ── QR Handler ────────────────────────────────────────────

    private fun handleQrDetected(rawValue: String?) {
        if (rawValue == null) return
        if (scanLocked.get()) return

        Log.d(TAG, "QR: ${rawValue.take(60)}...")

        val deepLink = extractDeepLink(rawValue) ?: run {
            runOnUiThread { Toast.makeText(this, "Invalid ZKAuth QR code", Toast.LENGTH_SHORT).show() }
            return
        }

        if (!isValidDeepLink(deepLink)) {
            runOnUiThread { Toast.makeText(this, "QR expired or invalid.", Toast.LENGTH_SHORT).show() }
            return
        }

        if (!scanLocked.compareAndSet(false, true)) return

        Log.i(TAG, "✅ Valid QR → AuthActivity")

        runOnUiThread {
            startActivity(
                Intent(Intent.ACTION_VIEW, Uri.parse(deepLink)).apply {
                    setPackage(packageName)
                }
            )
            finish()
        }
    }

    // ── Deep Link Extraction ──────────────────────────────────

    private fun extractDeepLink(raw: String): String? {
        // Format A — direct zkauth://
        if (raw.startsWith("zkauth://")) return raw

        // Format B — base64 JSON
        return try {
            val decoded   = String(Base64.decode(raw, Base64.DEFAULT), Charsets.UTF_8)
            val json      = JSONObject(decoded)
            val timestamp = json.optLong("timestamp", 0L)
            
            if (timestamp > 0) {
                val age = (System.currentTimeMillis() - timestamp) / 1000L
                if (age > MAX_AGE_SECONDS) {
                    Log.w(TAG, "QR too old: ${age}s")
                    return null
                }
            }
            
            val link = json.optString("deep_link", "")
            if (link.isEmpty()) null else link
            
        } catch (e: Exception) {
            Log.w(TAG, "QR parse failed: ${e.message}")
            null
        }
    }

    // ── Validation ────────────────────────────────────────────

    private fun isValidDeepLink(deepLink: String): Boolean {
        return try {
            val uri       = Uri.parse(deepLink)
            val challenge = uri.getQueryParameter("challenge") ?: return false
            val callback  = uri.getQueryParameter("callback")  ?: return false

            uri.scheme == "zkauth" && uri.host == "auth"
                && challenge.length >= 32
                && (callback.startsWith("https://")
                    || callback.contains("railway.app")
                    || callback.startsWith("http://localhost"))
        } catch (e: Exception) { false }
    }

    // ── Helpers ───────────────────────────────────────────────

    private fun hasCameraPermission() =
        ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
            PackageManager.PERMISSION_GRANTED
}