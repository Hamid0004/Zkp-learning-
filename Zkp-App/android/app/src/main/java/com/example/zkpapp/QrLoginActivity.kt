package com.example.zkpapp

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
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

class QrLoginActivity : AppCompatActivity() {

    private lateinit var viewFinder: PreviewView
    private val cameraExecutor = Executors.newSingleThreadExecutor()
    private val scanLocked = AtomicBoolean(false)

    companion object {
        private const val REQUEST_CAMERA = 200
        private const val TAG = "QrLoginActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_qr_login)

        viewFinder = findViewById(R.id.viewFinder)

        if (hasCameraPermission()) {
            startCamera()
        } else {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.CAMERA),
                REQUEST_CAMERA
            )
        }
    }

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
                    it.setAnalyzer(cameraExecutor) { imageProxy ->
                        processImageProxy(imageProxy)
                    }
                }

            val cameraSelector = CameraSelector.DEFAULT_BACK_CAMERA

            cameraProvider.unbindAll()
            cameraProvider.bindToLifecycle(
                this,
                cameraSelector,
                preview,
                analyzer
            )

        }, ContextCompat.getMainExecutor(this))
    }

    @androidx.camera.core.ExperimentalGetImage
    private fun processImageProxy(imageProxy: ImageProxy) {

        val mediaImage = imageProxy.image ?: run {
            imageProxy.close()
            return
        }

        val image = InputImage.fromMediaImage(
            mediaImage,
            imageProxy.imageInfo.rotationDegrees
        )

        val scanner = BarcodeScanning.getClient()

        scanner.process(image)
            .addOnSuccessListener { barcodes ->
                for (barcode in barcodes) {
                    if (barcode.format == Barcode.FORMAT_QR_CODE) {
                        handleQrDetected(barcode.rawValue)
                    }
                }
            }
            .addOnFailureListener {
                Log.w(TAG, "QR scanning failed", it)
            }
            .addOnCompleteListener {
                imageProxy.close()
            }
    }

    private fun handleQrDetected(rawValue: String?) {

        if (rawValue == null) return
        if (scanLocked.get()) return

        if (!isValidZkpQr(rawValue)) {
            runOnUiThread {
                Toast.makeText(this, "Invalid ZKP Login QR", Toast.LENGTH_SHORT).show()
            }
            return
        }

        scanLocked.set(true)

        runOnUiThread {
            val intent = Intent(this, LoginActivity::class.java)
            intent.putExtra("QR_DATA", rawValue)
            startActivity(intent)
            finish()
        }
    }

    private fun isValidZkpQr(data: String): Boolean {
        return try {
            val json = JSONObject(data)

            val type = json.optString("type")
            val sessionId = json.optString("sessionId")
            val challenge = json.optString("challenge")

            type == "ZKP_LOGIN" &&
                    sessionId.isNotEmpty() &&
                    challenge.isNotEmpty()

        } catch (e: Exception) {
            false
        }
    }

    private fun hasCameraPermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.CAMERA
        ) == PackageManager.PERMISSION_GRANTED
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
    }
}
