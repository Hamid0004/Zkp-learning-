package com.example.zkpapp

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Color
import android.media.AudioManager
import android.media.ToneGenerator
import android.os.*
import android.util.Log
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.journeyapps.barcodescanner.BarcodeCallback
import com.journeyapps.barcodescanner.BarcodeResult
import com.journeyapps.barcodescanner.DecoratedBarcodeView
import kotlinx.coroutines.*
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.zip.CRC32

class VerifierActivity : AppCompatActivity() {

    companion object {
        private const val TAG = "VerifierActivity"
        
        init {
            try {
                System.loadLibrary("zkp_mobile")
                Log.i(TAG, "Native library loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load native library", e)
            }
        }

        private const val MAX_CHUNK_SIZE = 2048 
        private const val MAX_TOTAL_CHUNKS = 500 
        private const val MAX_PROOF_SIZE = 1_000_000 
        private const val REQUEST_CAMERA_PERMISSION = 1001
        private const val TIMEOUT_DURATION_MS = 60000L 
        private const val VERIFICATION_TIMEOUT_MS = 30000L 
        private const val WATCHDOG_INTERVAL_MS = 1000L
        private const val MIN_SCAN_INTERVAL_MS = 50L 
        private const val MIN_UI_UPDATE_INTERVAL_MS = 100L
        private const val AUTO_RESET_DELAY_SUCCESS_MS = 5000L
        private const val AUTO_RESET_DELAY_FAILURE_MS = 3000L
    }

    private external fun verifyProofFromRust(proof: String): String

    private lateinit var barcodeView: DecoratedBarcodeView
    private lateinit var statusText: TextView
    private lateinit var progressBar: ProgressBar

    private val receivedChunks = ConcurrentHashMap<Int, ChunkData>()
    private val totalChunksExpected = AtomicInteger(-1)
    private val lastScannedTime = AtomicLong(0L)
    private val isProcessing = AtomicBoolean(false)
    private val isVerifying = AtomicBoolean(false)
    private var currentSessionId: String? = null
    private var lastUiUpdateTime = 0L
    private var lastScanTime = 0L 
    
    private val verificationScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val watchdogHandler = Handler(Looper.getMainLooper())
    private var watchdogRunnable: Runnable? = null

    private val toneGen by lazy { 
        try { ToneGenerator(AudioManager.STREAM_NOTIFICATION, 100) } 
        catch (e: Exception) { null }
    }
    
    private var scanStartTime = 0L

    data class ChunkData(
        val index: Int,
        val payload: String,
        val checksum: Long,
        val receivedAt: Long = System.currentTimeMillis()
    )

    sealed class VerificationResult {
        data class Success(val report: String, val verificationTimeMs: Long) : VerificationResult()
        data class Failure(val reason: String, val errorCode: ErrorCode) : VerificationResult()
        data class Error(val message: String, val exception: Exception?) : VerificationResult()
    }
    
    enum class ErrorCode {
        INVALID_PROOF, TIMEOUT, CHECKSUM_MISMATCH, ASSEMBLY_FAILED, NATIVE_CRASH, MEMORY_LIMIT_EXCEEDED, INVALID_FORMAT
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_verifier)
        initializeComponents()
        requestCameraPermissionIfNeeded()
    }

    private fun initializeComponents() {
        try {
            barcodeView = findViewById(R.id.scannerView)
            statusText = findViewById(R.id.tvStatus)
            progressBar = findViewById(R.id.progressBar)
            updateStatus("🔍 Ready to Scan", Color.TRANSPARENT)
        } catch (e: Exception) {
            finish()
        }
    }

    private fun requestCameraPermissionIfNeeded() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.CAMERA), REQUEST_CAMERA_PERMISSION)
        } else {
            startScanning()
            startTimeoutWatchdog()
        }
    }

    override fun onResume() { super.onResume(); barcodeView.resume() }
    override fun onPause() { super.onPause(); barcodeView.pause() }
    override fun onDestroy() { super.onDestroy(); cleanup() }

    private fun cleanup() {
        watchdogRunnable?.let { watchdogHandler.removeCallbacks(it) }
        verificationScope.cancel()
        toneGen?.release()
        receivedChunks.clear()
    }

    private fun startScanning() {
        scanStartTime = System.currentTimeMillis()
        barcodeView.decodeContinuous(object : BarcodeCallback {
            override fun barcodeResult(result: BarcodeResult?) {
                if (isProcessing.get() || result?.text.isNullOrBlank()) return
                val now = System.currentTimeMillis()
                if (now - lastScanTime < MIN_SCAN_INTERVAL_MS) return
                lastScanTime = now
                lastScannedTime.set(now)
                processQrData(result!!.text)
            }
        })
    }

    private fun processQrData(data: String) {
        if (data.length > MAX_CHUNK_SIZE * 2) {
            showError("⚠️ Invalid QR Size", ErrorCode.INVALID_FORMAT)
            return
        }
        if (!data.contains("|") || !data.contains("/")) return
        processChunkedData(data)
    }

    private fun processChunkedData(data: String) {
        try {
            val parts = data.split("|")
            if (parts.size < 2) return
            val header = parts[0].split("/")
            if (header.size != 2) return

            val currentIndex = header[0].toIntOrNull() ?: return
            val total = header[1].toIntOrNull() ?: return
            val payload = parts[1]

            if (!validateChunkSecurity(currentIndex, total, payload)) return

            if (parts.size >= 4) {
                val crc32Str = parts[2]
                if (!validateChecksum(payload, crc32Str)) {
                    showError("⚠️ CRC32 Failed", ErrorCode.CHECKSUM_MISMATCH)
                    return
                }
                
                val providedSig = parts[3]
                val calculatedSig = calculateChunkSignature(currentIndex, total, payload, crc32Str)
                if (!providedSig.equals(calculatedSig, ignoreCase = true)) {
                    showError("⚠️ Tampering Detected", ErrorCode.CHECKSUM_MISMATCH)
                    return
                }
            }

            if (totalChunksExpected.get() != -1 && totalChunksExpected.get() != total) {
                resetSession("🔄 New Identity")
                return
            }

            if (totalChunksExpected.get() == -1) initializeSession(total)
            
            val checksum = parts.getOrNull(2)?.toLongOrNull() ?: 0L
            storeChunk(currentIndex, payload, checksum)
            
            if (receivedChunks.size == total) verifyCompleteProof()

        } catch (e: Exception) {
            showError("⚠️ Processing Error", ErrorCode.INVALID_FORMAT)
        }
    }

    private fun validateChunkSecurity(index: Int, total: Int, payload: String): Boolean {
        if (index < 1 || index > total) return false
        if (total > MAX_TOTAL_CHUNKS) return false
        if (payload.length > MAX_CHUNK_SIZE) return false
        return true
    }

    private fun initializeSession(total: Int) {
        totalChunksExpected.set(total)
        progressBar.max = total
        currentSessionId = "session_${System.currentTimeMillis()}"
    }

    private fun storeChunk(index: Int, payload: String, checksum: Long) {
        if (!receivedChunks.containsKey(index)) {
            receivedChunks[index] = ChunkData(index, payload, checksum)
            updateProgressUI()
        }
    }

    private fun updateProgressUI() {
        val progress = receivedChunks.size
        val total = totalChunksExpected.get()
        runOnUiThread {
            progressBar.progress = progress
            statusText.text = "📥 Loading: $progress/$total"
        }
    }

    private fun verifyCompleteProof() {
        if (!isProcessing.compareAndSet(false, true)) return
        isVerifying.set(true)
        barcodeView.pause()
        updateStatus("🔐 Verifying...", Color.parseColor("#FF9800"))

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { performVerification() }
            handleVerificationResult(result)
        }
    }

    private suspend fun performVerification(): VerificationResult {
        return try {
            val expected = totalChunksExpected.get()
            val sb = StringBuilder()
            for (i in 1..expected) {
                val chunk = receivedChunks[i] ?: return VerificationResult.Failure("Missing chunk $i", ErrorCode.ASSEMBLY_FAILED)
                sb.append(chunk.payload)
            }
            val fullProof = sb.toString()
            
            val report = withTimeout(VERIFICATION_TIMEOUT_MS) { verifyProofFromRust(fullProof) }
            VerificationResult.Success(report, 0)
        } catch (e: Exception) {
            VerificationResult.Error(e.message ?: "Unknown Error", e)
        }
    }

    private suspend fun handleVerificationResult(result: VerificationResult) {
        when (result) {
            is VerificationResult.Success -> {
                updateStatus("✅ ${result.report}", Color.parseColor("#2E7D32"))
                delay(AUTO_RESET_DELAY_SUCCESS_MS)
                resetSession("🔍 Ready")
            }
            is VerificationResult.Failure -> {
                updateStatus("❌ ${result.reason}", Color.RED)
                delay(AUTO_RESET_DELAY_FAILURE_MS)
                resetSession("♻️ Ready")
            }
            is VerificationResult.Error -> {
                updateStatus("🔥 Error", Color.RED)
                delay(AUTO_RESET_DELAY_FAILURE_MS)
                resetSession("♻️ Ready")
            }
        }
    }

    private fun resetSession(msg: String) {
        isProcessing.set(false)
        isVerifying.set(false)
        receivedChunks.clear()
        totalChunksExpected.set(-1)
        runOnUiThread {
            updateStatus(msg, Color.TRANSPARENT)
            progressBar.progress = 0
            barcodeView.resume()
        }
    }

    private fun startTimeoutWatchdog() {
        watchdogRunnable = object : Runnable {
            override fun run() {
                if (!isProcessing.get() && receivedChunks.isNotEmpty()) {
                    if (System.currentTimeMillis() - lastScannedTime.get() > TIMEOUT_DURATION_MS) {
                        resetSession("⚠️ Timeout")
                    }
                }
                watchdogHandler.postDelayed(this, WATCHDOG_INTERVAL_MS)
            }
        }
        watchdogHandler.post(watchdogRunnable!!)
    }

    private fun validateChecksum(payload: String, checksumStr: String): Boolean {
        return try {
            val expected = checksumStr.toLongOrNull() ?: return false
            val crc = CRC32()
            crc.update(payload.toByteArray())
            crc.value == expected
        } catch (e: Exception) { false }
    }

    private fun calculateChunkSignature(index: Int, total: Int, payload: String, crc32Str: String): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            
            // Little Endian conversion for i32 (Matching Rust index_i32.to_le_bytes())
            val indexBytes = byteArrayOf((index and 0xFF).toByte(), (index shr 8 and 0xFF).toByte(), (index shr 16 and 0xFF).toByte(), (index shr 24 and 0xFF).toByte())
            val totalBytes = byteArrayOf((total and 0xFF).toByte(), (total shr 8 and 0xFF).toByte(), (total shr 16 and 0xFF).toByte(), (total shr 24 and 0xFF).toByte())
            
            // CRC32 parsing (Matching Rust crc32.to_le_bytes())
            val crc32Val = crc32Str.toLongOrNull() ?: 0L
            val crc32Bytes = byteArrayOf((crc32Val and 0xFF).toByte(), (crc32Val shr 8 and 0xFF).toByte(), (crc32Val shr 16 and 0xFF).toByte(), (crc32Val shr 24 and 0xFF).toByte())
            
            digest.update(indexBytes)
            digest.update(totalBytes)
            digest.update(payload.toByteArray(Charsets.UTF_8))
            digest.update(crc32Bytes)
            
            digest.digest().joinToString("") { "%02x".format(it) }
        } catch (e: Exception) { "" }
    }

    private fun updateStatus(text: String, color: Int) {
        runOnUiThread {
            statusText.text = text
            statusText.setBackgroundColor(color)
        }
    }

    private fun showError(msg: String, code: ErrorCode) {
        updateStatus(msg, Color.RED)
    }
}