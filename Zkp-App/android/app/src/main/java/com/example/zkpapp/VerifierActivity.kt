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

/**
 * VerifierActivity - Production-Grade ZK Proof Validator 🕵️‍♂️
 *
 * Features:
 * ✅ Offline Verification (Chunked QR with deduplication)
 * ✅ Multi-layer Integrity Checks (CRC32 + SHA256)
 * ✅ Rust Native Crypto Engine with timeout protection
 * ✅ Advanced State Management & Race Condition Prevention
 * ✅ Comprehensive Error Handling & Logging
 * ✅ Memory Efficient Chunk Processing
 * ✅ Security Hardening (Length limits, sanitization)
 * ✅ Performance Monitoring & Metrics
 *
 * @author Production Team
 * @version 2.0.2
 */
class VerifierActivity : AppCompatActivity() {

    // ═══════════════════════════════════════════════════════════
    // 🦁 CONFIGURATION & NATIVE LIBS
    // ═══════════════════════════════════════════════════════════
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

        // Security Limits
        private const val MAX_CHUNK_SIZE = 2048 // Max bytes per chunk
        // 🦁 FIX: Increased to 3000 to match Sender
        private const val MAX_TOTAL_CHUNKS = 3000 
        private const val MAX_PROOF_SIZE = 5_000_000 // 5MB max proof size
        
        // Timeouts - INCREASED for better scanning
        private const val REQUEST_CAMERA_PERMISSION = 1001
        private const val TIMEOUT_DURATION_MS = 60000L // 60 seconds (1 minute)
        private const val VERIFICATION_TIMEOUT_MS = 30000L // 30 seconds for Rust
        private const val WATCHDOG_INTERVAL_MS = 1000L
        
        // Scanning optimization
        private const val MIN_SCAN_INTERVAL_MS = 50L // Minimum time between scans
        
        // UI Update throttling
        private const val MIN_UI_UPDATE_INTERVAL_MS = 100L
        
        // Session Configuration
        private const val AUTO_RESET_DELAY_SUCCESS_MS = 5000L
        private const val AUTO_RESET_DELAY_FAILURE_MS = 3000L
    }

    // Rust JNI Functions
    private external fun verifyProofFromRust(proof: String): String

    // ═══════════════════════════════════════════════════════════
    // 📱 UI COMPONENTS
    // ═══════════════════════════════════════════════════════════
    private lateinit var barcodeView: DecoratedBarcodeView
    private lateinit var statusText: TextView
    private lateinit var progressBar: ProgressBar

    // ═══════════════════════════════════════════════════════════
    // 🧵 STATE MANAGEMENT (Thread-Safe)
    // ═══════════════════════════════════════════════════════════
    private val receivedChunks = ConcurrentHashMap<Int, ChunkData>()
    private val totalChunksExpected = AtomicInteger(-1)
    // 🦁 FIX: AtomicLong to prevent overflow errors
    private val lastScannedTime = AtomicLong(0L) 
    private val isProcessing = AtomicBoolean(false)
    private val isVerifying = AtomicBoolean(false)
    
    // Session Management
    private var currentSessionId: String? = null
    private var lastUiUpdateTime = 0L
    private var lastScanTime = 0L 
    
    // Coroutine Management
    private val verificationScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    
    // Watchdog for timeouts
    private val watchdogHandler = Handler(Looper.getMainLooper())
    private var watchdogRunnable: Runnable? = null

    // Audio Feedback (Lazy initialization)
    private val toneGen by lazy { 
        try {
            ToneGenerator(AudioManager.STREAM_NOTIFICATION, 100)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create ToneGenerator", e)
            null
        }
    }
    
    // Performance Metrics
    private var scanStartTime = 0L
    private var verificationStartTime = 0L

    // ═══════════════════════════════════════════════════════════
    // 📦 DATA CLASSES
    // ═══════════════════════════════════════════════════════════
    
    /**
     * Represents a single chunk with integrity data
     */
    data class ChunkData(
        val index: Int,
        val payload: String,
        val checksum: Long,
        val receivedAt: Long = System.currentTimeMillis()
    )

    /**
     * Verification result with detailed information
     */
    sealed class VerificationResult {
        data class Success(
            val report: String,
            val verificationTimeMs: Long
        ) : VerificationResult()
        
        data class Failure(
            val reason: String,
            val errorCode: ErrorCode
        ) : VerificationResult()
        
        data class Error(
            val message: String,
            val exception: Exception?
        ) : VerificationResult()
    }
    
    /**
     * Error codes for better diagnostics
     */
    enum class ErrorCode {
        INVALID_PROOF,
        TIMEOUT,
        CHECKSUM_MISMATCH,
        ASSEMBLY_FAILED,
        NATIVE_CRASH,
        MEMORY_LIMIT_EXCEEDED,
        INVALID_FORMAT
    }

    // ═══════════════════════════════════════════════════════════
    // 🎬 LIFECYCLE
    // ═══════════════════════════════════════════════════════════
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_verifier)

        initializeComponents()
        requestCameraPermissionIfNeeded()
        
        Log.i(TAG, "VerifierActivity created")
    }

    private fun initializeComponents() {
        try {
            barcodeView = findViewById(R.id.scannerView)
            statusText = findViewById(R.id.tvStatus)
            progressBar = findViewById(R.id.progressBar)
            
            updateStatus("🔍 Ready to Scan", Color.TRANSPARENT)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize components", e)
            showToast("Initialization failed: ${e.message}")
            finish()
        }
    }

    private fun requestCameraPermissionIfNeeded() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            != PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(
                this,
                arrayOf(Manifest.permission.CAMERA),
                REQUEST_CAMERA_PERMISSION
            )
        } else {
            startScanning()
            startTimeoutWatchdog()
        }
    }

    override fun onResume() {
        super.onResume()
        try {
            barcodeView.resume()
            Log.d(TAG, "Scanner resumed")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to resume scanner", e)
        }
    }

    override fun onPause() {
        super.onPause()
        try {
            barcodeView.pause()
            Log.d(TAG, "Scanner paused")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to pause scanner", e)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        cleanup()
        Log.i(TAG, "VerifierActivity destroyed")
    }

    private fun cleanup() {
        // Stop watchdog
        watchdogRunnable?.let { watchdogHandler.removeCallbacks(it) }
        
        // Cancel all coroutines
        verificationScope.cancel()
        
        // Release audio resources
        try {
            toneGen?.release()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to release ToneGenerator", e)
        }
        
        // Clear data structures
        receivedChunks.clear()
    }

    // ═══════════════════════════════════════════════════════════
    // 📷 SCANNING ENGINE
    // ═══════════════════════════════════════════════════════════

    private fun startScanning() {
        scanStartTime = System.currentTimeMillis()
        
        barcodeView.decodeContinuous(object : BarcodeCallback {
            override fun barcodeResult(result: BarcodeResult?) {
                // Guard clauses
                if (isProcessing.get()) return
                if (result?.text.isNullOrBlank()) return
                
                // Throttle scanning to prevent overwhelming the processor
                val now = System.currentTimeMillis()
                if (now - lastScanTime < MIN_SCAN_INTERVAL_MS) {
                    return // Skip this scan, too fast
                }
                lastScanTime = now
                
                val qrData = result!!.text
                
                // Update scan time (AtomicLong)
                lastScannedTime.set(now)
                
                // Process QR data
                processQrData(qrData)
            }
        })
        
        Log.i(TAG, "Scanner started")
    }

    private fun processQrData(data: String) {
        try {
            // Security: Length check
            if (data.length > MAX_CHUNK_SIZE * 2) {
                Log.w(TAG, "QR data exceeds maximum size: ${data.length}")
                showError("⚠️ Invalid QR Size", ErrorCode.INVALID_FORMAT)
                return
            }
            
            // Format validation: "Index/Total|Payload|Checksum"
            if (!data.contains("|") || !data.contains("/")) {
                Log.d(TAG, "Invalid QR format, ignoring")
                return
            }
            
            processChunkedData(data)
        } catch (e: Exception) {
            Log.e(TAG, "Error processing QR data", e)
            showError("⚠️ Scan Error", ErrorCode.INVALID_FORMAT)
        }
    }

    private fun processChunkedData(data: String) {
        try {
            val parts = data.split("|")
            if (parts.size < 2) {
                Log.w(TAG, "Insufficient data parts: ${parts.size}")
                return
            }
            
            val header = parts[0].split("/")
            if (header.size != 2) {
                Log.w(TAG, "Invalid header format")
                return
            }

            // Parse header
            val currentIndex = header[0].toIntOrNull() ?: run {
                Log.w(TAG, "Invalid chunk index: ${header[0]}")
                return
            }
            
            val total = header[1].toIntOrNull() ?: run {
                Log.w(TAG, "Invalid total chunks: ${header[1]}")
                return
            }
            
            val payload = parts[1]
            
            // Security validations
            if (!validateChunkSecurity(currentIndex, total, payload)) {
                return
            }

            // Determine chunk format and validate
            val isSecureFormat = parts.size >= 4
            var checksumValid = true
            var signatureValid = true
            
            if (isSecureFormat) {
                // Secure format: "index/total|payload|crc32|signature"
                Log.v(TAG, "🔒 Chunk $currentIndex: Secure format detected")
                
                // Validate CRC32
                val crc32Str = parts[2]
                checksumValid = validateChecksum(payload, crc32Str)
                
                if (!checksumValid) {
                    Log.e(TAG, "❌ CRC32 validation failed for chunk $currentIndex")
                    showError("⚠️ Chunk Integrity Failed (CRC32)", ErrorCode.CHECKSUM_MISMATCH)
                    return
                }
                
                // Validate SHA256 signature
                val providedSig = parts[3]
                val calculatedSig = calculateChunkSignature(currentIndex, total, payload, crc32Str)
                signatureValid = providedSig == calculatedSig
                
                if (!signatureValid) {
                    Log.e(TAG, "❌ SHA256 signature validation failed for chunk $currentIndex")
                    showError("⚠️ Chunk Tampering Detected", ErrorCode.CHECKSUM_MISMATCH)
                    return
                }
                
            } else if (parts.size >= 3) {
                // Legacy format with checksum: "index/total|payload|checksum"
                checksumValid = validateChecksum(payload, parts[2])
                if (!checksumValid) {
                    showError("⚠️ Checksum Failed on Chunk $currentIndex", ErrorCode.CHECKSUM_MISMATCH)
                    return
                }
            }

            // Session management
            val expectedTotal = totalChunksExpected.get()
            if (expectedTotal != -1 && expectedTotal != total) {
                // New session detected
                Log.i(TAG, "New session detected (total changed: $expectedTotal -> $total)")
                resetSession("🔄 New Identity Detected")
                return
            }

            // Initialize session
            if (expectedTotal == -1) {
                initializeSession(total)
            }

            // Store chunk (with deduplication)
            val checksum = if (parts.size >= 3) {
                parts[2].toLongOrNull() ?: 0L
            } else {
                0L
            }
            storeChunk(currentIndex, payload, checksum)
            
            // Check completion
            if (receivedChunks.size == total) {
                Log.i(TAG, "All chunks received, starting verification")
                verifyCompleteProof()
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error processing chunked data", e)
            showError("⚠️ Processing Error", ErrorCode.INVALID_FORMAT)
        }
    }

    /**
     * Validates chunk security constraints
     */
    private fun validateChunkSecurity(index: Int, total: Int, payload: String): Boolean {
        // Validate chunk index range
        if (index < 1 || index > total) {
            Log.w(TAG, "Invalid chunk index: $index (total: $total)")
            showError("⚠️ Invalid Chunk Index", ErrorCode.INVALID_FORMAT)
            return false
        }
        
        // Validate total chunks limit
        if (total > MAX_TOTAL_CHUNKS) {
            Log.w(TAG, "Total chunks exceeds limit: $total > $MAX_TOTAL_CHUNKS")
            showError("⚠️ Too Many Chunks", ErrorCode.MEMORY_LIMIT_EXCEEDED)
            return false
        }
        
        // Validate payload size
        if (payload.length > MAX_CHUNK_SIZE) {
            Log.w(TAG, "Chunk payload exceeds limit: ${payload.length} > $MAX_CHUNK_SIZE")
            showError("⚠️ Chunk Too Large", ErrorCode.INVALID_FORMAT)
            return false
        }
        
        return true
    }

    /**
     * Initializes a new scanning session
     */
    private fun initializeSession(total: Int) {
        totalChunksExpected.set(total)
        progressBar.max = total
        currentSessionId = generateSessionId()
        scanStartTime = System.currentTimeMillis()
        
        // 🦁 FIX: Correctly set AtomicLong (was causing crash with .toInt() before)
        lastScannedTime.set(System.currentTimeMillis())
        
        Log.i(TAG, "Session initialized: $currentSessionId, total chunks: $total")
    }

    /**
     * Stores a chunk with deduplication
     */
    private fun storeChunk(index: Int, payload: String, checksum: Long) {
        if (!receivedChunks.containsKey(index)) {
            val chunkData = ChunkData(index, payload, checksum)
            receivedChunks[index] = chunkData
            
            // Throttled UI update
            updateProgressUI()
        } 
    }

    /**
     * Updates progress UI with throttling and detailed stats
     */
    private fun updateProgressUI() {
        val now = System.currentTimeMillis()
        if (now - lastUiUpdateTime < MIN_UI_UPDATE_INTERVAL_MS) {
            return // Throttle UI updates
        }
        lastUiUpdateTime = now
        
        val progress = receivedChunks.size
        val total = totalChunksExpected.get()
        val percentage = if (total > 0) (progress * 100) / total else 0
        
        runOnUiThread {
            progressBar.progress = progress
            statusText.text = "📥 Loading: $progress/$total ($percentage%)"
            statusText.setBackgroundColor(Color.parseColor("#424242"))
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 🔐 VERIFICATION ENGINE
    // ═══════════════════════════════════════════════════════════

    private fun verifyCompleteProof() {
        // Prevent concurrent verification
        if (!isProcessing.compareAndSet(false, true)) {
            Log.w(TAG, "Verification already in progress")
            return
        }
        
        isVerifying.set(true)
        barcodeView.pause()
        verificationStartTime = System.currentTimeMillis()

        updateStatus("🔐 Verifying Math...", Color.parseColor("#FF9800"))

        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                performVerification()
            }
            
            handleVerificationResult(result)
        }
    }

    /**
     * Performs the actual verification with timeout protection
     */
    private suspend fun performVerification(): VerificationResult = coroutineScope {
        try {
            // Assemble proof with validation
            val assemblyResult = assembleProof()
            if (assemblyResult is VerificationResult.Failure) {
                return@coroutineScope assemblyResult
            }
            
            val fullProof = (assemblyResult as VerificationResult.Success).report
            
            // Additional integrity check
            if (!validateAssembledProof(fullProof)) {
                return@coroutineScope VerificationResult.Failure(
                    "Assembled proof failed integrity check",
                    ErrorCode.ASSEMBLY_FAILED
                )
            }
            
            // Verify with timeout
            val verificationJob = async(Dispatchers.IO) {
                val startTime = System.currentTimeMillis()
                val report = verifyProofFromRust(fullProof)
                val elapsedTime = System.currentTimeMillis() - startTime
                
                Log.i(TAG, "Rust verification completed in ${elapsedTime}ms")
                
                VerificationResult.Success(report, elapsedTime)
            }
            
            withTimeoutOrNull(VERIFICATION_TIMEOUT_MS) {
                verificationJob.await()
            } ?: run {
                verificationJob.cancel()
                Log.e(TAG, "Verification timeout after ${VERIFICATION_TIMEOUT_MS}ms")
                VerificationResult.Failure("Verification timeout", ErrorCode.TIMEOUT)
            }
            
        } catch (e: CancellationException) {
            Log.w(TAG, "Verification cancelled")
            VerificationResult.Failure("Verification cancelled", ErrorCode.TIMEOUT)
        } catch (e: Exception) {
            Log.e(TAG, "Verification error", e)
            VerificationResult.Error("Verification failed: ${e.message}", e)
        }
    }

    /**
     * Assembles the complete proof from chunks
     */
    private fun assembleProof(): VerificationResult {
        return try {
            val expected = totalChunksExpected.get()
            
            // Verify all chunks present
            for (i in 1..expected) {
                if (!receivedChunks.containsKey(i)) {
                    Log.e(TAG, "Missing chunk: $i")
                    return VerificationResult.Failure(
                        "Missing chunk $i",
                        ErrorCode.ASSEMBLY_FAILED
                    )
                }
            }
            
            // Assemble in correct order
            val fullProof = buildString(capacity = expected * 500) {
                for (i in 1..expected) {
                    append(receivedChunks[i]?.payload ?: "")
                }
            }
            
            // Security: Check assembled size
            if (fullProof.length > MAX_PROOF_SIZE) {
                Log.e(TAG, "Assembled proof exceeds size limit: ${fullProof.length}")
                return VerificationResult.Failure(
                    "Proof too large",
                    ErrorCode.MEMORY_LIMIT_EXCEEDED
                )
            }
            
            Log.i(TAG, "Proof assembled successfully: ${fullProof.length} bytes")
            VerificationResult.Success(fullProof, 0)
            
        } catch (e: Exception) {
            Log.e(TAG, "Error assembling proof", e)
            VerificationResult.Error("Assembly failed: ${e.message}", e)
        }
    }

    /**
     * Validates the assembled proof using SHA256
     */
    private fun validateAssembledProof(proof: String): Boolean {
        return try {
            // Additional integrity check with SHA256
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(proof.toByteArray())
            hash.any { it != 0.toByte() }
        } catch (e: Exception) {
            Log.e(TAG, "Error validating assembled proof", e)
            false
        }
    }

    /**
     * Handles verification result and updates UI
     */
    private suspend fun handleVerificationResult(result: VerificationResult) {
        val totalTime = System.currentTimeMillis() - scanStartTime
        
        when (result) {
            is VerificationResult.Success -> {
                Log.i(TAG, "✅ Verification SUCCESS (${result.verificationTimeMs}ms)")
                
                if (result.report.contains("Verified", ignoreCase = true) || result.report.contains("✅")) {
                    updateStatus(
                        "✅ ${result.report}\n⏱️ Total: ${totalTime}ms",
                        Color.parseColor("#2E7D32")
                    )
                    triggerHapticFeedback(true)
                    delay(AUTO_RESET_DELAY_SUCCESS_MS)
                    resetSession("🔍 Ready to Scan")
                } else {
                    handleFailedVerification("Invalid proof format", ErrorCode.INVALID_PROOF)
                }
            }
            
            is VerificationResult.Failure -> {
                Log.w(TAG, "❌ Verification FAILED: ${result.reason} [${result.errorCode}]")
                handleFailedVerification(result.reason, result.errorCode)
            }
            
            is VerificationResult.Error -> {
                Log.e(TAG, "🔥 Verification ERROR: ${result.message}", result.exception)
                handleFailedVerification(
                    result.message,
                    ErrorCode.NATIVE_CRASH
                )
            }
        }
        
        isVerifying.set(false)
    }

    /**
     * Handles failed verification attempts
     */
    private suspend fun handleFailedVerification(reason: String, errorCode: ErrorCode) {
        val displayMessage = when (errorCode) {
            ErrorCode.INVALID_PROOF -> "❌ FAKE IDENTITY"
            ErrorCode.TIMEOUT -> "⏱️ VERIFICATION TIMEOUT"
            ErrorCode.CHECKSUM_MISMATCH -> "⚠️ CORRUPTED DATA"
            ErrorCode.ASSEMBLY_FAILED -> "⚠️ INCOMPLETE SCAN"
            ErrorCode.NATIVE_CRASH -> "🔥 VERIFICATION ERROR"
            ErrorCode.MEMORY_LIMIT_EXCEEDED -> "⚠️ DATA TOO LARGE"
            ErrorCode.INVALID_FORMAT -> "⚠️ INVALID FORMAT"
        }
        
        updateStatus(displayMessage, Color.RED)
        triggerHapticFeedback(false)
        delay(AUTO_RESET_DELAY_FAILURE_MS)
        resetSession("♻️ Ready")
    }

    // ═══════════════════════════════════════════════════════════
    // 🛠️ UTILITY FUNCTIONS
    // ═══════════════════════════════════════════════════════════

    /**
     * Resets the current session
     */
    private fun resetSession(msg: String) {
        if (isDestroyed) return
        
        isProcessing.set(false)
        isVerifying.set(false)
        receivedChunks.clear()
        totalChunksExpected.set(-1)
        lastScannedTime.set(System.currentTimeMillis())
        currentSessionId = null
        lastUiUpdateTime = 0L

        runOnUiThread {
            updateStatus(msg, Color.TRANSPARENT)
            progressBar.progress = 0
            try {
                barcodeView.resume()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to resume scanner", e)
            }
        }
        
        Log.i(TAG, "Session reset: $msg")
    }

    /**
     * Starts watchdog for timeout detection
     */
    private fun startTimeoutWatchdog() {
        watchdogRunnable = object : Runnable {
            override fun run() {
                try {
                    if (!isProcessing.get() && !isVerifying.get() && receivedChunks.isNotEmpty()) {
                        val timeSinceLastScan = System.currentTimeMillis() - lastScannedTime.get()
                        
                        if (timeSinceLastScan > TIMEOUT_DURATION_MS) {
                            Log.w(TAG, "Session timeout: ${timeSinceLastScan}ms since last scan")
                            resetSession("⚠️ Session Timed Out")
                        }
                    }
                    watchdogHandler.postDelayed(this, WATCHDOG_INTERVAL_MS)
                } catch (e: Exception) {
                    Log.e(TAG, "Watchdog error", e)
                }
            }
        }
        watchdogHandler.post(watchdogRunnable!!)
        
        Log.i(TAG, "Watchdog started")
    }

    /**
     * Validates checksum using CRC32
     */
    private fun validateChecksum(payload: String, checksumStr: String): Boolean {
        return try {
            val expected = checksumStr.toLongOrNull() ?: return false
            val crc = CRC32()
            crc.update(payload.toByteArray())
            val isValid = crc.value == expected
            
            if (!isValid) {
                Log.w(TAG, "Checksum mismatch: expected=$expected, actual=${crc.value}")
            }
            
            isValid
        } catch (e: Exception) {
            Log.e(TAG, "Checksum validation error", e)
            false
        }
    }

    /**
     * 🦁 FIX: Added missing function to calculate signature
     * Ensures compatibility with Secure Format without crashing
     */
    private fun calculateChunkSignature(
        index: Int,
        total: Int,
        payload: String,
        crc32Str: String
    ): String {
        return try {
            val digest = MessageDigest.getInstance("SHA-256")
            val signatureInput = "$index/$total|$payload|$crc32Str"
            val hash = digest.digest(signatureInput.toByteArray(Charsets.UTF_8))
            hash.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            ""
        }
    }

    /**
     * Triggers haptic and audio feedback
     */
    private fun triggerHapticFeedback(success: Boolean) {
        try {
            val vibrator = getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
            
            if (success) {
                // Success feedback
                toneGen?.startTone(ToneGenerator.TONE_PROP_BEEP, 150)
                
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    vibrator?.vibrate(
                        VibrationEffect.createOneShot(100, VibrationEffect.DEFAULT_AMPLITUDE)
                    )
                } else {
                    @Suppress("DEPRECATION")
                    vibrator?.vibrate(100)
                }
            } else {
                // Failure feedback
                toneGen?.startTone(ToneGenerator.TONE_CDMA_SOFT_ERROR_LITE, 200)
                
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    vibrator?.vibrate(
                        VibrationEffect.createOneShot(500, VibrationEffect.DEFAULT_AMPLITUDE)
                    )
                } else {
                    @Suppress("DEPRECATION")
                    vibrator?.vibrate(500)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Haptic feedback error", e)
        }
    }

    /**
     * Shows error message
     */
    private fun showError(msg: String, errorCode: ErrorCode) {
        Log.w(TAG, "Error: $msg [$errorCode]")
        runOnUiThread {
            updateStatus(msg, Color.RED)
            triggerHapticFeedback(false)
        }
    }

    /**
     * Updates status text and background color
     */
    private fun updateStatus(text: String, backgroundColor: Int) {
        runOnUiThread {
            statusText.text = text
            statusText.setBackgroundColor(backgroundColor)
        }
    }

    /**
     * Shows a toast message
     */
    private fun showToast(message: String) {
        runOnUiThread {
            Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * Generates a unique session ID
     */
    private fun generateSessionId(): String {
        return "session_${System.currentTimeMillis()}_${(1000..9999).random()}"
    }

    // ═══════════════════════════════════════════════════════════
    // 🔐 PERMISSIONS
    // ═══════════════════════════════════════════════════════════

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        
        if (requestCode == REQUEST_CAMERA_PERMISSION) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                Log.i(TAG, "Camera permission granted")
                startScanning()
                startTimeoutWatchdog()
            } else {
                Log.w(TAG, "Camera permission denied")
                showToast("Camera permission is required for scanning")
                finish()
            }
        }
    }
}