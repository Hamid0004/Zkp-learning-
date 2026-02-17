package com.example.zkpapp

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
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
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

// ─────────────────────────────────────────────────────────────────────────────
// QR payload schema (all fields required unless noted):
//
//  {
//    "ver":       2,                        // int  – schema version
//    "type":      "ZKP_LOGIN",              // str  – must be exact
//    "sessionId": "<uuid>",                 // str  – unique per session
//    "challenge": "<hex>",                  // str  – server nonce
//    "origin":    "https://auth.example.com",// str  – issuing domain
//    "iat":       1713000000,               // long – issued-at  (Unix seconds)
//    "exp":       1713000300,               // long – expiry     (Unix seconds)
//    "sig":       "<base64url>",            // str  – ECDSA-SHA256 over canonical payload
//    "kid":       "v1"                      // str  – key-id used to sign (optional)
//  }
//
//  Canonical payload for signature = compact JSON with keys sorted
//  alphabetically, "sig" field excluded, e.g.:
//
//  {"challenge":"...","exp":...,"iat":...,"kid":"v1","origin":"...","sessionId":"...","type":"ZKP_LOGIN","ver":2}
// ─────────────────────────────────────────────────────────────────────────────

class QrLoginActivity : AppCompatActivity() {

    // ── Camera ───────────────────────────────────────────────────────────────
    private lateinit var viewFinder: PreviewView
    private val cameraExecutor = Executors.newSingleThreadExecutor()
    private val scanLocked     = AtomicBoolean(false)

    companion object {
        private const val TAG            = "QrLoginActivity"
        private const val REQUEST_CAMERA = 200

        // ── Versioning ───────────────────────────────────────────────────────
        /** Minimum QR schema version this build accepts.  */
        private const val MIN_SUPPORTED_VERSION = 2
        /** Maximum QR schema version this build accepts.
         *  Bump when a new schema is deployed and validated. */
        private const val MAX_SUPPORTED_VERSION = 2

        // ── Anti-replay window ───────────────────────────────────────────────
        /** Seconds into the past  a QR is still accepted (clock skew buffer). */
        private const val MAX_AGE_SECONDS    = 300L   // 5 min
        /** Seconds into the future a QR may be pre-issued (server clock skew). */
        private const val MAX_FUTURE_SECONDS = 30L

        // ── Origin whitelist ─────────────────────────────────────────────────
        // Keep this list tight.  All origins must use HTTPS.
        // Trailing slashes are normalised away during validation.
        private val ALLOWED_ORIGINS: Set<String> = setOf(
            "https://auth.example.com",
            "https://auth.staging.example.com"
            // Add additional trusted issuers here; never add http:// entries.
        )

        // ── Signature verification ────────────────────────────────────────────
        // Raw (DER-encoded) EC public keys embedded as Base64.
        // In production, load these from the Android Keystore or a pinned
        // certificate bundle; they are inlined here for illustrative clarity.
        //
        // Generate with:
        //   openssl ecparam -name prime256v1 -genkey -noout -out ec.pem
        //   openssl ec -in ec.pem -pubout -out ec_pub.pem
        //   base64 < ec_pub.pem | tr -d '\n'
        private val TRUSTED_PUBLIC_KEYS: Map<String, String> = mapOf(
            "v1" to "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE<REPLACE_WITH_REAL_BASE64_KEY>"
            // Add key-rotation entries:  "v2" to "MFkw..."
        )
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
        ) {
            startCamera()
        } else {
            showError("Camera permission is required to scan QR codes.")
            finish()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        cameraExecutor.shutdown()
    }

    // ── Camera setup ──────────────────────────────────────────────────────────

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
            .addOnFailureListener { Log.w(TAG, "Barcode processing error", it) }
            .addOnCompleteListener { imageProxy.close() }
    }

    // ── QR dispatch ───────────────────────────────────────────────────────────

    private fun handleQrDetected(rawValue: String?) {
        if (rawValue == null)      return
        if (scanLocked.get())      return

        val result = validateQrPayload(rawValue)

        if (result is ValidationResult.Failure) {
            Log.w(TAG, "QR rejected [${result.reason}]")
            runOnUiThread { showError(result.userMessage) }
            return
        }

        // Atomically claim the scan lock – only one success path proceeds.
        if (!scanLocked.compareAndSet(false, true)) return

        runOnUiThread {
            val intent = Intent(this, LoginActivity::class.java)
                .putExtra("QR_DATA", rawValue)
            startActivity(intent)
            finish()
        }
    }

    // ── Validation pipeline ───────────────────────────────────────────────────

    /**
     * Runs every security check in order.  Returns [ValidationResult.Success]
     * only when *all* checks pass.
     */
    private fun validateQrPayload(raw: String): ValidationResult {
        val json = try {
            JSONObject(raw)
        } catch (e: Exception) {
            return ValidationResult.Failure("PARSE_ERROR", "Invalid QR code format.")
        }

        return checkVersion(json)
            ?: checkType(json)
            ?: checkRequiredFields(json)
            ?: checkOrigin(json)
            ?: checkTimestamps(json)
            ?: checkSignature(json, raw)
            ?: ValidationResult.Success
    }

    // ── Check 1 – Version ─────────────────────────────────────────────────────

    private fun checkVersion(json: JSONObject): ValidationResult.Failure? {
        val ver = json.optInt("ver", -1)
        if (ver < MIN_SUPPORTED_VERSION || ver > MAX_SUPPORTED_VERSION) {
            return ValidationResult.Failure(
                "UNSUPPORTED_VERSION",
                "This QR code version is not supported. Please update the app."
            )
        }
        return null
    }

    // ── Check 2 – Type ────────────────────────────────────────────────────────

    private fun checkType(json: JSONObject): ValidationResult.Failure? {
        if (json.optString("type") != "ZKP_LOGIN") {
            return ValidationResult.Failure(
                "WRONG_TYPE",
                "Invalid QR Login code."
            )
        }
        return null
    }

    // ── Check 3 – Required fields ─────────────────────────────────────────────

    private fun checkRequiredFields(json: JSONObject): ValidationResult.Failure? {
        val missing = listOf("sessionId", "challenge", "origin", "iat", "exp", "sig")
            .filter { !json.has(it) || json.optString(it).isEmpty() }
        if (missing.isNotEmpty()) {
            Log.w(TAG, "Missing fields: $missing")
            return ValidationResult.Failure(
                "MISSING_FIELDS",
                "QR code is incomplete or malformed."
            )
        }
        return null
    }

    // ── Check 4 – Origin whitelist ────────────────────────────────────────────

    private fun checkOrigin(json: JSONObject): ValidationResult.Failure? {
        val origin = json.optString("origin").trimEnd('/')
        if (origin !in ALLOWED_ORIGINS) {
            Log.w(TAG, "Untrusted origin: $origin")
            return ValidationResult.Failure(
                "UNTRUSTED_ORIGIN",
                "QR code was issued by an unrecognised source."
            )
        }
        if (!origin.startsWith("https://")) {
            return ValidationResult.Failure(
                "INSECURE_ORIGIN",
                "QR code origin must use HTTPS."
            )
        }
        return null
    }

    // ── Check 5 – Anti-replay timestamps ─────────────────────────────────────

    private fun checkTimestamps(json: JSONObject): ValidationResult.Failure? {
        val nowSeconds  = System.currentTimeMillis() / 1000L
        val iat         = json.optLong("iat", 0L)
        val exp         = json.optLong("exp", 0L)

        // Issued-at sanity: must not be in the far future
        if (iat > nowSeconds + MAX_FUTURE_SECONDS) {
            return ValidationResult.Failure(
                "TIMESTAMP_FUTURE",
                "QR code timestamp is invalid (issued in the future)."
            )
        }

        // Explicit expiry check
        if (nowSeconds > exp) {
            return ValidationResult.Failure(
                "EXPIRED",
                "This QR code has expired. Please refresh and try again."
            )
        }

        // Defence-in-depth: cap max age even if exp is set far in the future
        if (nowSeconds - iat > MAX_AGE_SECONDS) {
            return ValidationResult.Failure(
                "MAX_AGE_EXCEEDED",
                "This QR code is too old. Please refresh and try again."
            )
        }

        // Guard against iat > exp (server misconfiguration)
        if (iat > exp) {
            return ValidationResult.Failure(
                "TIMESTAMP_INCOHERENT",
                "QR code contains invalid timestamps."
            )
        }

        return null
    }

    // ── Check 6 – Signature ───────────────────────────────────────────────────

    private fun checkSignature(json: JSONObject, @Suppress("UNUSED_PARAMETER") raw: String): ValidationResult.Failure? {
        val kid = json.optString("kid", "v1").ifEmpty { "v1" }
        val b64PublicKey = TRUSTED_PUBLIC_KEYS[kid]
            ?: return ValidationResult.Failure(
                "UNKNOWN_KEY_ID",
                "QR code was signed with an unknown key."
            )

        val sigB64 = json.optString("sig")
        val sigBytes = try {
            Base64.decode(sigB64, Base64.URL_SAFE or Base64.NO_WRAP)
        } catch (e: Exception) {
            return ValidationResult.Failure("SIG_DECODE_ERROR", "QR code signature is malformed.")
        }

        val canonical = buildCanonicalPayload(json)
        if (canonical == null) {
            return ValidationResult.Failure("CANONICAL_BUILD_ERROR", "Unable to verify QR code.")
        }

        val valid = try {
            val keyBytes  = Base64.decode(b64PublicKey, Base64.DEFAULT)
            val keySpec   = X509EncodedKeySpec(keyBytes)
            val publicKey = KeyFactory.getInstance("EC").generatePublic(keySpec)
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(publicKey)
                update(canonical.toByteArray(Charsets.UTF_8))
                verify(sigBytes)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Signature verification exception", e)
            false
        }

        if (!valid) {
            return ValidationResult.Failure(
                "SIG_INVALID",
                "QR code signature is invalid."
            )
        }
        return null
    }

    /**
     * Rebuilds the canonical JSON string the server signed.
     *
     * Rules:
     *  - All fields present in the JSON are included **except** "sig".
     *  - Keys are sorted alphabetically (to match the server's implementation).
     *  - No extra whitespace (compact serialisation).
     */
    private fun buildCanonicalPayload(json: JSONObject): String? {
        return try {
            val out = JSONObject()
            // Sort keys and exclude "sig"
            json.keys()
                .asSequence()
                .filter { it != "sig" }
                .sorted()
                .forEach { key -> out.put(key, json.get(key)) }
            out.toString()          // JSONObject.toString() is compact by default
        } catch (e: Exception) {
            Log.w(TAG, "Failed to build canonical payload", e)
            null
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun hasCameraPermission() =
        ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) ==
                PackageManager.PERMISSION_GRANTED

    private fun showError(message: String) =
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()

    // ── Validation result ADT ─────────────────────────────────────────────────

    private sealed class ValidationResult {
        /** All checks passed. */
        object Success : ValidationResult()

        /**
         * A check failed.
         *
         * @param reason      Machine-readable code for logs/analytics.
         * @param userMessage Safe, non-technical string for the Toast.
         */
        data class Failure(
            val reason:      String,
            val userMessage: String
        ) : ValidationResult()
    }
}