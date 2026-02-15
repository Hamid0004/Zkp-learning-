package com.example.zkpapp

import android.animation.ObjectAnimator
import android.animation.PropertyValuesHolder
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.util.Log
import android.view.View
import android.view.animation.AccelerateDecelerateInterpolator
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
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.*
import org.json.JSONArray
import org.json.JSONException
import java.util.EnumMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * OfflineMenuActivity - Production-Grade QR Transmission System 📡
 */
class OfflineMenuActivity : AppCompatActivity() {

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

        private const val QR_SIZE = 800
        private const val QR_MARGIN = 2
        private const val FRAME_DELAY_MS = 200L 
        private const val ERROR_DISPLAY_DURATION_MS = 4000L
        private const val MAX_CHUNKS = 3000 
        private const val MAX_CHUNK_SIZE = 2048
        private const val PROOF_GENERATION_TIMEOUT_MS = 30000L
        private const val ENABLE_BITMAP_CACHE = true
        private const val MAX_CACHE_SIZE = 50 

        private const val MODE_FORWARD = "FWD"
        private const val MODE_REVERSE = "RWD"
        private const val MODE_RANDOM = "RND"
    }

    private external fun stringFromRust(): String

    private lateinit var imgQr: ImageView
    private lateinit var tvStatus: TextView
    private lateinit var tvFrameCounter: TextView
    private lateinit var loader: ProgressBar
    private lateinit var btnTransmit: Button
    private lateinit var btnVerifyOffline: Button

    // ═══════════════════════════════════════════════════════════
    // 🧵 STATE MANAGEMENT
    // ═══════════════════════════════════════════════════════════
    private var animationJob: Job? = null
    private var proofGenerationJob: Job? = null
    
    // Class-level animator to handle lifecycle correctly
    private var breathingAnimator: ObjectAnimator? = null 

    private val isTransmitting = AtomicBoolean(false)
    private val isGeneratingProof = AtomicBoolean(false)
    private val currentFrameIndex = AtomicInteger(0)

    private var sessionId: String? = null
    private var transmissionStartTime = 0L
    private var totalFramesTransmitted = 0
    private var currentCycleNumber = 0
    private var wakeLock: android.os.PowerManager.WakeLock? = null

    private val bitmapCache = mutableMapOf<Int, Bitmap>()

    private val qrHints = EnumMap<EncodeHintType, Any>(EncodeHintType::class.java).apply {
        put(EncodeHintType.ERROR_CORRECTION, ErrorCorrectionLevel.L)
        put(EncodeHintType.MARGIN, QR_MARGIN)
        put(EncodeHintType.CHARACTER_SET, "UTF-8")
    }

    data class TransmissionStats(
        val totalFrames: Int,
        val framesTransmitted: Int,
        val cyclesCompleted: Int,
        val durationMs: Long,
        val framesPerSecond: Double
    )

    sealed class ProofGenerationResult {
        data class Success(val chunks: JSONArray, val generationTimeMs: Long) : ProofGenerationResult()
        data class Failure(val reason: String, val exception: Exception?) : ProofGenerationResult()
        object Cancelled : ProofGenerationResult()
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_offline_menu)

        initializeComponents()
        setupClickListeners()
        initializeWakeLock()
        
        // Start breathing animation
        startBreathingAnimation()

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
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize components", e)
            showError("Initialization failed")
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
        val powerManager = getSystemService(Context.POWER_SERVICE) as? android.os.PowerManager
        wakeLock = powerManager?.newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK, "$TAG::WakeLock")
    }

    override fun onDestroy() {
        super.onDestroy()
        breathingAnimator?.cancel()
        cleanup()
    }

    override fun onPause() {
        super.onPause()
        releaseWakeLock()
    }

    override fun onResume() {
        super.onResume()
        if (isTransmitting.get()) acquireWakeLock()
    }

    private fun startTransmission() {
        if (!isGeneratingProof.compareAndSet(false, true)) return
        sessionId = generateSessionId()
        updateUIForComputing()
        acquireWakeLock()

        proofGenerationJob = lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) { generateProof() }
            handleProofGenerationResult(result)
        }
    }

    private suspend fun generateProof(): ProofGenerationResult = coroutineScope {
        try {
            val startTime = System.currentTimeMillis()
            val proofJob = async(Dispatchers.IO) { stringFromRust() }
            val jsonResponse = withTimeoutOrNull(PROOF_GENERATION_TIMEOUT_MS) { proofJob.await() }
                ?: run {
                    proofJob.cancel()
                    return@coroutineScope ProofGenerationResult.Failure("Timeout", null)
                }

            val chunks = parseAndValidateChunks(jsonResponse)
                ?: return@coroutineScope ProofGenerationResult.Failure("Invalid Format", null)

            ProofGenerationResult.Success(chunks, System.currentTimeMillis() - startTime)
        } catch (e: Exception) {
            ProofGenerationResult.Failure(e.message ?: "Error", e)
        }
    }

    private fun parseAndValidateChunks(jsonResponse: String): JSONArray? {
        return try {
            val jsonArray = JSONArray(jsonResponse)
            if (jsonArray.length() == 0 || jsonArray.length() > MAX_CHUNKS) null else jsonArray
        } catch (e: JSONException) { null }
    }

    private suspend fun handleProofGenerationResult(result: ProofGenerationResult) {
        isGeneratingProof.set(false)
        when (result) {
            is ProofGenerationResult.Success -> startBroadcasting(result.chunks)
            is ProofGenerationResult.Failure -> showError(result.reason)
            is ProofGenerationResult.Cancelled -> resetUI()
        }
    }

    private fun startBroadcasting(dataChunks: JSONArray) {
        if (!isTransmitting.compareAndSet(false, true)) return
        transmissionStartTime = System.currentTimeMillis()
        updateUIForTransmitting()
        startQrAnimation(dataChunks)
    }

    private fun stopTransmission() {
        val wasTransmitting = isTransmitting.getAndSet(false)
        isGeneratingProof.set(false)
        if (wasTransmitting) logTransmissionStats()
        cleanup()
        resetUI()
        releaseWakeLock()
    }

    private fun logTransmissionStats() {
        val duration = System.currentTimeMillis() - transmissionStartTime
        Log.i(TAG, "Transmission Duration: $duration ms")
    }

    private fun startQrAnimation(dataChunks: JSONArray) {
        stopAnimation()
        animationJob = lifecycleScope.launch(Dispatchers.Default) {
            try {
                val encoder = BarcodeEncoder()
                val writer = MultiFormatWriter()
                val totalFrames = dataChunks.length()

                if (ENABLE_BITMAP_CACHE && totalFrames <= MAX_CACHE_SIZE) {
                    preGenerateQRCodes(dataChunks, writer, encoder)
                }

                while (currentCoroutineContext().isActive && isTransmitting.get()) {
                    currentCycleNumber++
                    if (!transmitPhase(dataChunks, writer, encoder, MODE_FORWARD, (0 until totalFrames).asSequence())) break
                    if (!transmitPhase(dataChunks, writer, encoder, MODE_REVERSE, (totalFrames - 1 downTo 0).asSequence())) break
                    val randomIndices = (0 until totalFrames).shuffled()
                    if (!transmitPhase(dataChunks, writer, encoder, MODE_RANDOM, randomIndices.asSequence())) break
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) { showError("Animation Error") }
            } finally {
                clearBitmapCache()
            }
        }
    }

    private suspend fun preGenerateQRCodes(dataChunks: JSONArray, writer: MultiFormatWriter, encoder: BarcodeEncoder) {
        withContext(Dispatchers.IO) {
            for (i in 0 until dataChunks.length()) {
                if (!currentCoroutineContext().isActive || !isTransmitting.get()) break
                try {
                    bitmapCache[i] = generateQRBitmap(dataChunks.getString(i), writer, encoder)
                } catch (e: Exception) { }
            }
        }
    }

    private suspend fun transmitPhase(
        dataChunks: JSONArray, 
        writer: MultiFormatWriter, 
        encoder: BarcodeEncoder, 
        mode: String, 
        indices: Sequence<Int>
    ): Boolean {
        for (index in indices) {
            if (!currentCoroutineContext().isActive || !isTransmitting.get()) return false
            
            try {
                val bitmap = bitmapCache[index] ?: generateQRBitmap(dataChunks.getString(index), writer, encoder)
                withContext(Dispatchers.Main) {
                    if (isTransmitting.get()) displayQRCode(bitmap, index, dataChunks.length(), mode)
                }
            } catch (e: Exception) { }
            delay(FRAME_DELAY_MS)
        }
        return true
    }

    private fun generateQRBitmap(data: String, writer: MultiFormatWriter, encoder: BarcodeEncoder): Bitmap {
        val matrix = writer.encode(data, BarcodeFormat.QR_CODE, QR_SIZE, QR_SIZE, qrHints)
        return encoder.createBitmap(matrix)
    }

    private fun displayQRCode(bitmap: Bitmap, index: Int, total: Int, mode: String) {
        imgQr.setImageBitmap(bitmap)
        tvFrameCounter.text = "$mode: ${index + 1} / $total"
        tvFrameCounter.setTextColor(when (mode) {
            MODE_FORWARD -> Color.GREEN
            MODE_REVERSE -> Color.YELLOW
            else -> Color.CYAN
        })
    }

    private fun stopAnimation() {
        animationJob?.cancel()
        animationJob = null
    }

    private fun clearBitmapCache() {
        bitmapCache.values.forEach { if (!it.isRecycled) it.recycle() }
        bitmapCache.clear()
    }

    private fun cleanup() {
        stopAnimation()
        proofGenerationJob?.cancel()
        clearBitmapCache()
    }

    private fun acquireWakeLock() {
        try { wakeLock?.takeIf { !it.isHeld }?.acquire(10 * 60 * 1000L) } catch (e: Exception) { }
    }

    private fun releaseWakeLock() {
        try { wakeLock?.takeIf { it.isHeld }?.release() } catch (e: Exception) { }
    }

    private fun updateUIForComputing() {
        btnTransmit.text = "⏳ COMPUTING..."
        btnTransmit.isEnabled = false
        loader.visibility = View.VISIBLE
    }

    // 🦁 2. Jab QR Chal raha ho (Transmitting State) - UPDATED
    private fun updateUIForTransmitting() {
        btnTransmit.text = "⏹ STOP BROADCAST"
        btnTransmit.setBackgroundColor(Color.parseColor("#D32F2F"))
        btnTransmit.isEnabled = true
        
        tvStatus.text = "📡 Broadcasting Identity..."
        tvStatus.setTextColor(Color.parseColor("#00E676"))
        
        tvFrameCounter.visibility = View.VISIBLE
        loader.visibility = View.GONE
        
        // QR Display Setup (Sabse Zaroori Hissa) 👇
        imgQr.clearColorFilter() // Tint hatao
        imgQr.imageTintList = null // Pakka hatao
        imgQr.setBackgroundColor(Color.WHITE) // QR ke peeche White lagao (Scanning ke liye zaroori)

        // Pause breathing so it doesn't distract from scanning
        breathingAnimator?.pause()
    }

    // 🦁 1. Jab App Ruki hui ho (Ready State) - UPDATED
    private fun resetUI() {
        btnTransmit.text = "📡 TRANSMIT"
        btnTransmit.setBackgroundColor(Color.parseColor("#2E7D32"))
        btnTransmit.isEnabled = true
        
        tvStatus.text = "Ready to Transmit"
        tvStatus.setTextColor(Color.LTGRAY)
        
        tvFrameCounter.visibility = View.INVISIBLE
        loader.visibility = View.GONE
        
        // Image Reset
        imgQr.setImageResource(android.R.drawable.ic_menu_gallery)
        imgQr.setBackgroundColor(Color.TRANSPARENT) // Background saaf
        imgQr.setColorFilter(Color.parseColor("#00F0FF")) // Placeholder ko Cyan banao
        imgQr.imageTintList = null

        // Resume breathing when idle
        if (breathingAnimator != null && breathingAnimator!!.isPaused) {
            breathingAnimator?.resume()
        } else if (breathingAnimator != null && !breathingAnimator!!.isRunning) {
            breathingAnimator?.start()
        }
    }

    private fun showError(message: String) {
        tvStatus.text = "❌ $message"
        lifecycleScope.launch {
            delay(ERROR_DISPLAY_DURATION_MS)
            if (!isTransmitting.get()) resetUI()
        }
    }

    private fun navigateToVerifier() {
        startActivity(Intent(this, VerifierActivity::class.java))
    }

    private fun generateSessionId() = "tx_${System.currentTimeMillis()}"

    private fun startBreathingAnimation() {
        if (breathingAnimator != null && breathingAnimator!!.isRunning) return

        val cardView = findViewById<View>(R.id.cardQrContainer)
        
        if (cardView == null) {
            Log.w(TAG, "cardQrContainer not found, skipping animation")
            return
        }

        val scaleX = PropertyValuesHolder.ofFloat(View.SCALE_X, 1.0f, 1.02f)
        val scaleY = PropertyValuesHolder.ofFloat(View.SCALE_Y, 1.0f, 1.02f)
        
        breathingAnimator = ObjectAnimator.ofPropertyValuesHolder(cardView, scaleX, scaleY).apply {
            duration = 1500
            repeatCount = ObjectAnimator.INFINITE
            repeatMode = ObjectAnimator.REVERSE
            interpolator = AccelerateDecelerateInterpolator()
            start()
        }
        
        Log.d(TAG, "Breathing animation started")
    }
}