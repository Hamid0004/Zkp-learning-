package com.example.zkpapp

import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.WindowManager
import android.widget.Button
import android.widget.ImageView
import android.widget.ProgressBar
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatWriter
import com.google.zxing.WriterException
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import com.journeyapps.barcodescanner.BarcodeEncoder
import kotlinx.coroutines.*
import org.json.JSONArray
import org.json.JSONException
import java.util.EnumMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * OfflineMenuActivity - Production-Grade QR Transmission System 📡
 *
 * Features:
 * ✅ Animated QR Code Broadcasting (Fountain Strategy)
 * ✅ Rust Native Proof Generation
 * ✅ Three-Phase Transmission (FWD → RWD → RND)
 * ✅ Advanced Resource Management
 * ✅ Comprehensive Error Handling
 * ✅ Performance Optimization & Metrics
 * ✅ Memory Efficient Bitmap Handling
 * ✅ State Management & Thread Safety
 * ✅ Screen Wake Lock for Continuous Broadcast
 * ✅ Graceful Degradation
 *
 * Transmission Strategy:
 * 1. Forward Pass: 1 → N (Sequential coverage)
 * 2. Reverse Pass: N → 1 (Catch missed frames)
 * 3. Random Pass: Shuffled (Statistical redundancy)
 *
 * @author Production Team
 * @version 2.0.2
 */
class OfflineMenuActivity : AppCompatActivity() {

    // ═══════════════════════════════════════════════════════════
    // 🦁 CONFIGURATION & NATIVE LIBS
    // ═══════════════════════════════════════════════════════════
    companion object {
        private const val TAG = "OfflineMenuActivity"
        
        init {
            try {
                System.loadLibrary("zkp_mobile")
                Log.i(TAG, "Native library loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.e(TAG, "Failed to load Rust Library", e)
            }
        }

        // QR Code Configuration
        private const val QR_SIZE = 800
        private const val QR_MARGIN = 2
        
        // Transmission Timing - HIGHLY OPTIMIZED for reliable scanning
        // 🦁 400ms is the sweet spot. Too fast = Camera blur = Timeout.
        private const val FRAME_DELAY_MS = 200L 
        private const val ERROR_DISPLAY_DURATION_MS = 4000L
        
        // Performance Limits
        // 🦁 FIX: Increased to 3000 to match Verifier.
        private const val MAX_CHUNKS = 3000 
        private const val MAX_CHUNK_SIZE = 2048 // Max data per QR
        private const val PROOF_GENERATION_TIMEOUT_MS = 30000L // 30 seconds
        
        // Bitmap Cache Configuration
        private const val ENABLE_BITMAP_CACHE = true
        private const val MAX_CACHE_SIZE = 50 // Cache up to 50 QR codes
        
        // Transmission Modes
        private const val MODE_FORWARD = "FWD"
        private const val MODE_REVERSE = "RWD"
        private const val MODE_RANDOM = "RND"
    }

    // Rust JNI Function
    private external fun stringFromRust(): String

    // ═══════════════════════════════════════════════════════════
    // 📱 UI COMPONENTS
    // ═══════════════════════════════════════════════════════════
    private lateinit var imgQr: ImageView
    private lateinit var tvStatus: TextView
    private lateinit var tvFrameCounter: TextView
    private lateinit var loader: ProgressBar
    private lateinit var btnTransmit: Button
    private lateinit var btnVerifyOffline: Button

    // ═══════════════════════════════════════════════════════════
    // 🧵 STATE MANAGEMENT (Thread-Safe)
    // ═══════════════════════════════════════════════════════════
    private var animationJob: Job? = null
    private var proofGenerationJob: Job? = null
    
    private val isTransmitting = AtomicBoolean(false)
    private val isGeneratingProof = AtomicBoolean(false)
    private val currentFrameIndex = AtomicInteger(0)
    
    // Session Tracking
    private var sessionId: String? = null
    private var transmissionStartTime = 0L
    private var totalFramesTransmitted = 0
    private var currentCycleNumber = 0
    
    // Wake Lock for continuous transmission
    private var wakeLock: android.os.PowerManager.WakeLock? = null

    // ═══════════════════════════════════════════════════════════
    // 📦 DATA STRUCTURES
    // ═══════════════════════════════════════════════════════════
    
    /**
     * Bitmap cache for QR codes to avoid regeneration
     */
    private val bitmapCache = mutableMapOf<Int, Bitmap>()
    
    /**
     * QR Encoder configuration
     */
    private val qrHints = EnumMap<EncodeHintType, Any>(EncodeHintType::class.java).apply {
        put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L)
        put(EncodeHintType.MARGIN, QR_MARGIN)
        put(EncodeHintType.CHARACTER_SET, "UTF-8")
    }
    
    /**
     * Transmission statistics
     */
    data class TransmissionStats(
        val totalFrames: Int,
        val framesTransmitted: Int,
        val cyclesCompleted: Int,
        val durationMs: Long,
        val framesPerSecond: Double
    ) {
        override fun toString(): String {
            return "Stats(frames: $framesTransmitted/$totalFrames, cycles: $cyclesCompleted, " +
                   "fps: ${"%.1f".format(framesPerSecond)}, duration: ${durationMs}ms)"
        }
    }
    
    /**
     * Result types for proof generation
     */
    sealed class ProofGenerationResult {
        data class Success(val chunks: JSONArray, val generationTimeMs: Long) : ProofGenerationResult()
        data class Failure(val reason: String, val exception: Exception?) : ProofGenerationResult()
        object Cancelled : ProofGenerationResult()
    }

    // ═══════════════════════════════════════════════════════════
    // 🎬 LIFECYCLE
    // ═══════════════════════════════════════════════════════════
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_offline_menu)

        initializeComponents()
        setupClickListeners()
        initializeWakeLock()
        
        Log.i(TAG, "OfflineMenuActivity created")
    }

    private fun initializeComponents() {
        try {
            imgQr = findViewById(R.id.imgOfflineQr)
            tvStatus = findViewById(R.id.tvQrStatus)
            tvFrameCounter = findViewById(R.id.tvFrameCounter)
            loader = findViewById(R.id.loader)
            btnTransmit = findViewById(R.id.btnTransmit)
            btnVerifyOffline = findViewById(R.id.btnVerifyOffline)
            
            resetUI()
            
            Log.i(TAG, "Components initialized successfully")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize components", e)
            showError("Initialization failed: ${e.message}")
            finish()
        }
    }

    private fun setupClickListeners() {
        btnTransmit.setOnClickListener {
            if (!isTransmitting.get() && !isGeneratingProof.get()) {
                startTransmission()
            } else {
                stopTransmission()
            }
        }

        btnVerifyOffline.setOnClickListener {
            stopTransmission()
            navigateToVerifier()
        }
    }

    private fun initializeWakeLock() {
        try {
            val powerManager = getSystemService(Context.POWER_SERVICE) as? android.os.PowerManager
            powerManager?.let {
                wakeLock = it.newWakeLock(
                    android.os.PowerManager.PARTIAL_WAKE_LOCK,
                    "$TAG::TransmissionWakeLock"
                )
                wakeLock?.setReferenceCounted(false)
                Log.d(TAG, "Wake lock initialized")
            } ?: run {
                Log.e(TAG, "PowerManager not available")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize wake lock", e)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        cleanup()
        Log.i(TAG, "OfflineMenuActivity destroyed")
    }

    override fun onPause() {
        super.onPause()
        releaseWakeLock()
    }

    override fun onResume() {
        super.onResume()
        if (isTransmitting.get()) {
            acquireWakeLock()
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 📡 TRANSMISSION CONTROL
    // ═══════════════════════════════════════════════════════════

    /**
     * Starts the proof generation and transmission process
     */
    private fun startTransmission() {
        if (!isGeneratingProof.compareAndSet(false, true)) {
            Log.w(TAG, "Proof generation already in progress")
            return
        }
        
        sessionId = generateSessionId()
        Log.i(TAG, "Starting transmission session: $sessionId")
        
        updateUIForComputing()
        acquireWakeLock()

        proofGenerationJob = lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                generateProof()
            }
            
            handleProofGenerationResult(result)
        }
    }

    /**
     * Generates proof from Rust with timeout protection
     */
    private suspend fun generateProof(): ProofGenerationResult = coroutineScope {
        return@coroutineScope try {
            val startTime = System.currentTimeMillis()
            
            // Timeout protection
            val proofJob = async(Dispatchers.IO) {
                stringFromRust()
            }
            
            val jsonResponse = withTimeoutOrNull(PROOF_GENERATION_TIMEOUT_MS) {
                proofJob.await()
            } ?: run {
                proofJob.cancel()
                Log.e(TAG, "Proof generation timeout")
                return@coroutineScope ProofGenerationResult.Failure(
                    "Proof generation timeout",
                    null
                )
            }
            
            // Validate and parse JSON
            val chunks = parseAndValidateChunks(jsonResponse)
                ?: return@coroutineScope ProofGenerationResult.Failure(
                    "Invalid proof format",
                    null
                )
            
            val generationTime = System.currentTimeMillis() - startTime
            Log.i(TAG, "Proof generated successfully: ${chunks.length()} chunks in ${generationTime}ms")
            
            ProofGenerationResult.Success(chunks, generationTime)
            
        } catch (e: CancellationException) {
            Log.w(TAG, "Proof generation cancelled")
            ProofGenerationResult.Cancelled
        } catch (e: Exception) {
            Log.e(TAG, "Proof generation error", e)
            ProofGenerationResult.Failure(
                "Generation failed: ${e.message}",
                e
            )
        }
    }

    /**
     * Parses and validates chunk data
     */
    private fun parseAndValidateChunks(jsonResponse: String): JSONArray? {
        return try {
            val jsonArray = JSONArray(jsonResponse)
            
            // Validation
            if (jsonArray.length() == 0) {
                Log.e(TAG, "Empty proof data received")
                return null
            }
            
            if (jsonArray.length() > MAX_CHUNKS) {
                Log.e(TAG, "Too many chunks: ${jsonArray.length()} > $MAX_CHUNKS")
                return null
            }
            
            // Validate chunk sizes and format
            var secureChunks = 0
            var legacyChunks = 0
            
            for (i in 0 until jsonArray.length()) {
                val chunkStr = jsonArray.getString(i)
                
                // Check total size
                if (chunkStr.length > MAX_CHUNK_SIZE * 2) {
                    Log.e(TAG, "Chunk $i exceeds size limit: ${chunkStr.length} > ${MAX_CHUNK_SIZE * 2}")
                    return null
                }
                
                // Detect format
                // Secure: "index/total|payload|crc32|signature"
                // Legacy: "index/total|payload"
                val parts = chunkStr.split("|")
                when (parts.size) {
                    4 -> {
                        secureChunks++
                        Log.v(TAG, "Chunk $i: Secure format ✓")
                    }
                    2 -> {
                        legacyChunks++
                        Log.v(TAG, "Chunk $i: Legacy format")
                    }
                    else -> {
                        Log.w(TAG, "Chunk $i: Unknown format (${parts.size} parts)")
                    }
                }
            }
            
            Log.i(TAG, "Chunks validated: ${jsonArray.length()} total " +
                      "(secure: $secureChunks, legacy: $legacyChunks)")
            
            jsonArray
            
        } catch (e: JSONException) {
            Log.e(TAG, "JSON parsing error", e)
            null
        }
    }

    /**
     * Handles proof generation result
     */
    private suspend fun handleProofGenerationResult(result: ProofGenerationResult) {
        isGeneratingProof.set(false)
        
        when (result) {
            is ProofGenerationResult.Success -> {
                Log.i(TAG, "✅ Proof generation SUCCESS (${result.generationTimeMs}ms)")
                startBroadcasting(result.chunks)
            }
            
            is ProofGenerationResult.Failure -> {
                Log.e(TAG, "❌ Proof generation FAILED: ${result.reason}", result.exception)
                showError("Proof Error: ${result.reason}")
            }
            
            ProofGenerationResult.Cancelled -> {
                Log.i(TAG, "Proof generation cancelled by user")
                resetUI()
            }
        }
    }

    /**
     * Starts QR code broadcasting
     */
    private fun startBroadcasting(dataChunks: JSONArray) {
        if (!isTransmitting.compareAndSet(false, true)) {
            Log.w(TAG, "Broadcasting already in progress")
            return
        }
        
        transmissionStartTime = System.currentTimeMillis()
        totalFramesTransmitted = 0
        currentCycleNumber = 0
        
        updateUIForTransmitting()
        startQrAnimation(dataChunks)
        
        Log.i(TAG, "Broadcasting started: ${dataChunks.length()} frames")
    }

    /**
     * Stops transmission and cleanup
     */
    private fun stopTransmission() {
        val wasTransmitting = isTransmitting.getAndSet(false)
        isGeneratingProof.set(false)
        
        if (wasTransmitting) {
            logTransmissionStats()
        }
        
        cleanup()
        resetUI()
        releaseWakeLock()
        
        Log.i(TAG, "Transmission stopped")
    }

    /**
     * Logs transmission statistics
     */
    private fun logTransmissionStats() {
        val duration = System.currentTimeMillis() - transmissionStartTime
        val stats = TransmissionStats(
            totalFrames = currentFrameIndex.get(),
            framesTransmitted = totalFramesTransmitted,
            cyclesCompleted = currentCycleNumber,
            durationMs = duration,
            framesPerSecond = if (duration > 0) {
                (totalFramesTransmitted * 1000.0) / duration
            } else 0.0
        )
        
        Log.i(TAG, "📊 Transmission Stats: $stats")
    }

    // ═══════════════════════════════════════════════════════════
    // 🎬 QR ANIMATION ENGINE (FOUNTAIN STRATEGY)
    // ═══════════════════════════════════════════════════════════

    /**
     * Main animation loop with three-phase fountain strategy
     * Phase 1: Forward (1 → N)
     * Phase 2: Reverse (N → 1)
     * Phase 3: Random (Shuffled)
     */
    private fun startQrAnimation(dataChunks: JSONArray) {
        stopAnimation()

        animationJob = lifecycleScope.launch(Dispatchers.Default) {
            try {
                val encoder = BarcodeEncoder()
                val writer = MultiFormatWriter()
                val totalFrames = dataChunks.length()
                
                Log.i(TAG, "Animation started: $totalFrames frames, cache: $ENABLE_BITMAP_CACHE")

                // Pre-generate QR codes if caching enabled
                if (ENABLE_BITMAP_CACHE && totalFrames <= MAX_CACHE_SIZE) {
                    preGenerateQRCodes(dataChunks, writer, encoder)
                }

                // Main transmission loop
                while (currentCoroutineContext().isActive && isTransmitting.get()) {
                    currentCycleNumber++
                    
                    Log.d(TAG, "Cycle $currentCycleNumber started")

                    // Phase 1: Forward Pass
                    if (!transmitPhase(
                            dataChunks, 
                            writer, 
                            encoder, 
                            MODE_FORWARD,
                            generateSequence(0) { if (it < totalFrames - 1) it + 1 else null }
                        )) break

                    // Phase 2: Reverse Pass
                    if (!transmitPhase(
                            dataChunks,
                            writer,
                            encoder,
                            MODE_REVERSE,
                            generateSequence(totalFrames - 1) { if (it > 0) it - 1 else null }
                        )) break

                    // Phase 3: Random Pass
                    val randomIndices = (0 until totalFrames).toMutableList().apply { shuffle() }
                    if (!transmitPhase(
                            dataChunks,
                            writer,
                            encoder,
                            MODE_RANDOM,
                            randomIndices.asSequence()
                        )) break
                    
                    Log.d(TAG, "Cycle $currentCycleNumber completed")
                }
                
                Log.i(TAG, "Animation ended after $currentCycleNumber cycles")
                
            } catch (e: CancellationException) {
                Log.w(TAG, "Animation cancelled")
            } catch (e: Exception) {
                Log.e(TAG, "Animation error", e)
                withContext(Dispatchers.Main) {
                    showError("Animation Error: ${e.message}")
                }
            } finally {
                clearBitmapCache()
            }
        }
    }

    /**
     * Pre-generates all QR codes for smooth playback
     */
    private suspend fun preGenerateQRCodes(
        dataChunks: JSONArray,
        writer: MultiFormatWriter,
        encoder: BarcodeEncoder
    ) {
        val startTime = System.currentTimeMillis()
        
        withContext(Dispatchers.IO) {
            for (i in 0 until dataChunks.length()) {
                if (!currentCoroutineContext().isActive || !isTransmitting.get()) break
                
                try {
                    val bitmap = generateQRBitmap(
                        dataChunks.getString(i),
                        writer,
                        encoder
                    )
                    bitmapCache[i] = bitmap
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to pre-generate QR $i", e)
                }
            }
        }
        
        val elapsed = System.currentTimeMillis() - startTime
        Log.i(TAG, "Pre-generated ${bitmapCache.size} QR codes in ${elapsed}ms")
    }

    /**
     * Transmits a single phase of the fountain strategy
     */
    private suspend fun transmitPhase(
        dataChunks: JSONArray,
        writer: MultiFormatWriter,
        encoder: BarcodeEncoder,
        mode: String,
        indices: Sequence<Int>
    ): Boolean {
        val totalFrames = dataChunks.length()
        
        for (index in indices) {
            // 🦁 FIX: Use currentCoroutineContext() for correct compilation
            if (!currentCoroutineContext().isActive || !isTransmitting.get()) {
                return false
            }
            
            try {
                renderFrame(
                    index = index,
                    totalFrames = totalFrames,
                    chunkData = dataChunks.getString(index),
                    mode = mode,
                    writer = writer,
                    encoder = encoder
                )
                
                totalFramesTransmitted++
                currentFrameIndex.set(index)
                
            } catch (e: Exception) {
                Log.e(TAG, "Failed to render frame $index in $mode mode", e)
                // Continue with next frame
            }
            
            delay(FRAME_DELAY_MS)
        }
        
        return true
    }

    /**
     * Renders a single QR frame
     */
    private suspend fun renderFrame(
        index: Int,
        totalFrames: Int,
        chunkData: String,
        mode: String,
        writer: MultiFormatWriter,
        encoder: BarcodeEncoder
    ) {
        try {
            // Get bitmap from cache or generate
            val bitmap = if (ENABLE_BITMAP_CACHE && bitmapCache.containsKey(index)) {
                bitmapCache[index]!!
            } else {
                generateQRBitmap(chunkData, writer, encoder)
            }

            // Update UI
            withContext(Dispatchers.Main) {
                if (isTransmitting.get()) {
                    displayQRCode(bitmap, index, totalFrames, mode)
                }
            }
            
        } catch (e: WriterException) {
            Log.e(TAG, "QR encoding error for frame $index", e)
            throw e
        }
    }

    /**
     * Generates QR code bitmap
     */
    private fun generateQRBitmap(
        data: String,
        writer: MultiFormatWriter,
        encoder: BarcodeEncoder
    ): Bitmap {
        val matrix = writer.encode(
            data,
            BarcodeFormat.QR_CODE,
            QR_SIZE,
            QR_SIZE,
            qrHints
        )
        return encoder.createBitmap(matrix)
    }

    /**
     * Displays QR code on UI
     */
    private fun displayQRCode(
        bitmap: Bitmap,
        index: Int,
        totalFrames: Int,
        mode: String
    ) {
        imgQr.clearColorFilter()
        imgQr.imageTintList = null
        imgQr.setImageBitmap(bitmap)

        // Update frame counter with mode indicator
        tvFrameCounter.text = "$mode: ${index + 1} / $totalFrames"

        // Color coding for different modes
        val modeColor = when (mode) {
            MODE_FORWARD -> Color.parseColor("#00E676") // Green
            MODE_REVERSE -> Color.parseColor("#FF9800") // Orange
            MODE_RANDOM -> Color.parseColor("#2979FF")  // Blue
            else -> Color.WHITE
        }
        tvFrameCounter.setTextColor(modeColor)
    }

    /**
     * Stops animation job
     */
    private fun stopAnimation() {
        animationJob?.cancel()
        animationJob = null
        Log.d(TAG, "Animation stopped")
    }

    /**
     * Clears bitmap cache to free memory
     */
    private fun clearBitmapCache() {
        bitmapCache.values.forEach { bitmap ->
            try {
                if (!bitmap.isRecycled) {
                    bitmap.recycle()
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to recycle bitmap", e)
            }
        }
        bitmapCache.clear()
        Log.d(TAG, "Bitmap cache cleared")
    }

    // ═══════════════════════════════════════════════════════════
    // 🔧 RESOURCE MANAGEMENT
    // ═══════════════════════════════════════════════════════════

    /**
     * Comprehensive resource cleanup
     */
    private fun cleanup() {
        stopAnimation()
        
        proofGenerationJob?.cancel()
        proofGenerationJob = null
        
        clearBitmapCache()
        
        sessionId = null
        currentCycleNumber = 0
        totalFramesTransmitted = 0
        
        Log.d(TAG, "Resources cleaned up")
    }

    /**
     * Acquires wake lock to prevent screen dimming
     */
    private fun acquireWakeLock() {
        try {
            wakeLock?.let { lock ->
                if (!lock.isHeld) {
                    lock.acquire(10 * 60 * 1000L) // 10 minutes max
                    Log.d(TAG, "Wake lock acquired")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to acquire wake lock", e)
        }
    }

    /**
     * Releases wake lock
     */
    private fun releaseWakeLock() {
        try {
            wakeLock?.let { lock ->
                if (lock.isHeld) {
                    lock.release()
                    Log.d(TAG, "Wake lock released")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to release wake lock", e)
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 🎨 UI UPDATES
    // ═══════════════════════════════════════════════════════════

    /**
     * Updates UI for computing state
     */
    private fun updateUIForComputing() {
        btnTransmit.text = "⏳ COMPUTING..."
        btnTransmit.setBackgroundColor(Color.parseColor("#FF6F00"))
        btnTransmit.isEnabled = false

        tvStatus.text = "🦁 Computing Proof..."
        tvStatus.setTextColor(Color.WHITE)

        tvFrameCounter.visibility = View.INVISIBLE
        loader.visibility = View.VISIBLE
        
        imgQr.setColorFilter(Color.DKGRAY)
        
        Log.d(TAG, "UI updated: Computing")
    }

    /**
     * Updates UI for transmitting state
     */
    private fun updateUIForTransmitting() {
        btnTransmit.text = "⏹ STOP BROADCAST"
        btnTransmit.setBackgroundColor(Color.parseColor("#D32F2F"))
        btnTransmit.isEnabled = true

        tvStatus.text = "📡 Broadcasting Identity..."
        tvStatus.setTextColor(Color.parseColor("#00E676"))

        tvFrameCounter.visibility = View.VISIBLE
        loader.visibility = View.GONE

        imgQr.clearColorFilter()
        imgQr.imageTintList = null
        imgQr.setBackgroundColor(Color.WHITE)
        
        Log.d(TAG, "UI updated: Transmitting")
    }

    /**
     * Resets UI to initial state
     */
    private fun resetUI() {
        btnTransmit.text = "📡 TRANSMIT"
        btnTransmit.setBackgroundColor(Color.parseColor("#2E7D32"))
        btnTransmit.isEnabled = true

        tvStatus.text = "Ready to Transmit"
        tvStatus.setTextColor(Color.LTGRAY)

        tvFrameCounter.visibility = View.INVISIBLE
        loader.visibility = View.GONE

        imgQr.setImageResource(android.R.drawable.ic_menu_gallery)
        imgQr.setColorFilter(Color.DKGRAY)
        imgQr.imageTintList = null
        imgQr.setBackgroundColor(Color.TRANSPARENT)
        
        Log.d(TAG, "UI reset")
    }

    /**
     * Shows error message
     */
    private fun showError(message: String) {
        Log.e(TAG, "Error displayed: $message")
        
        stopTransmission()
        
        tvStatus.text = "❌ $message"
        tvStatus.setTextColor(Color.RED)
        
        // Auto-reset after delay
        lifecycleScope.launch {
            delay(ERROR_DISPLAY_DURATION_MS)
            if (!isTransmitting.get()) {
                resetUI()
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 🔀 NAVIGATION
    // ═══════════════════════════════════════════════════════════

    /**
     * Navigates to verifier activity
     */
    private fun navigateToVerifier() {
        try {
            val intent = Intent(this, VerifierActivity::class.java)
            startActivity(intent)
            Log.i(TAG, "Navigated to VerifierActivity")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to navigate to VerifierActivity", e)
            showError("Navigation failed")
        }
    }

    // ═══════════════════════════════════════════════════════════
    // 🛠️ UTILITY FUNCTIONS
    // ═══════════════════════════════════════════════════════════

    /**
     * Generates unique session ID
     */
    private fun generateSessionId(): String {
        return "tx_${System.currentTimeMillis()}_${(1000..9999).random()}"
    }
}