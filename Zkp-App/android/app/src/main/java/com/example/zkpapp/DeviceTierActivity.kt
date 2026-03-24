package com.example.zkpapp

import android.graphics.*
import android.graphics.drawable.*
import android.os.Build
import android.os.Bundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.view.*
import android.view.animation.*
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.cardview.widget.CardView
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

/**
 * DeviceTierActivity.kt v1.0
 *
 * ═══════════════════════════════════════════════════════════════
 * Tier 3 — Device + Biometric ZK Proof Screen
 *
 * Flow:
 *   1. Screen loads → ensureDeviceKeyExists() + warmup() [background]
 *   2. User taps "SCAN BIOMETRIC" → BiometricPrompt
 *   3. Biometric success → DeviceTierGate.generateProof()
 *   4. Proof result shown → claims displayed
 *   5. Auto-finish (deep link) or stay (registration mode)
 *
 * Intent extras (deep link flow):
 *   "domain"    → verifier domain e.g. "discord.com"
 *   "challenge" → server challenge hex
 *   "callback"  → POST url
 * ═══════════════════════════════════════════════════════════════
 */
class DeviceTierActivity : AppCompatActivity() {

    // ── Colors ────────────────────────────────────────────────────────────────
    private val colorBg     = Color.parseColor("#020810")
    private val colorCyan   = Color.parseColor("#00f5ff")
    private val colorGreen  = Color.parseColor("#00ff88")
    private val colorRed    = Color.parseColor("#ff3366")
    private val colorGold   = Color.parseColor("#ffd700")
    private val colorBorder = Color.parseColor("#1a3a4a")
    private val colorCardBg = Color.parseColor("#070e1a")

    // ── UI Refs ───────────────────────────────────────────────────────────────
    private lateinit var tvStatusDot:  TextView
    private lateinit var tvStatusMsg:  TextView
    private lateinit var tvStatusSub:  TextView
    private lateinit var statusBanner: CardView
    private lateinit var btnScan:      Button
    private lateinit var progressBar:  ProgressBar
    private lateinit var cardResult:   CardView
    private lateinit var tvResultRows: TextView
    private lateinit var tvProofTime:  TextView
    private lateinit var cardClaims:   CardView
    private lateinit var tvClaimsRows: TextView
    private lateinit var scrollView:   ScrollView

    // ── State ─────────────────────────────────────────────────────────────────
    private var isReady   = false
    private var isProving = false

    // ── Deep link params ──────────────────────────────────────────────────────
    private var zkDomain    = ""
    private var zkChallenge = ""
    private var zkCallback  = ""
    private var zkSession   = ""  // server session_id — needed to complete poll

    private val TAG = "DeviceTierActivity"

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.statusBarColor     = colorBg
        window.navigationBarColor = colorBg

        zkDomain    = intent.getStringExtra("domain")    ?: "zkpapp.local"
        zkSession   = intent.getStringExtra("session")   ?: ""
        // ✅ FIX: pad to even length — Rust hex::decode() requires even digits
        val rawChallenge = intent.getStringExtra("challenge")
            ?: System.currentTimeMillis().toString(16).let { h ->
                if (h.length % 2 != 0) "0$h" else h
            }
        zkChallenge = if (rawChallenge.length % 2 != 0) "0$rawChallenge" else rawChallenge
        zkCallback  = intent.getStringExtra("callback")  ?: ""

        buildUI()
        initInBackground()
    }

    // ── Background Init ───────────────────────────────────────────────────────
    private fun initInBackground() {
        updateStatus("⚡ INITIALIZING", colorGold, "SETTING UP SECURE ENCLAVE")
        btnScan.isEnabled = false
        btnScan.alpha     = 0.4f

        lifecycleScope.launch {
            try {
                // Step 1: KeyStore setup
                runOnUiThread { updateStatus("🔑 STEP 1/3", colorGold, "GENERATING DEVICE KEY") }
                DeviceTierGate.ensureDeviceKeyExists()

                // Step 2: Circuit warmup (slow on first install — Plonky2 build)
                runOnUiThread { updateStatus("⚙️ STEP 2/3", colorGold, "BUILDING ZK CIRCUIT · FIRST TIME ONLY") }
                DeviceTierGate.warmup()

                // Step 3: Ready
                runOnUiThread { updateStatus("✅ STEP 3/3", colorGold, "CIRCUIT READY") }
                kotlinx.coroutines.delay(300)

                isReady = true
                runOnUiThread {
                    btnScan.isEnabled = true
                    btnScan.alpha     = 1f

                    if (zkCallback.isNotEmpty()) {
                        updateStatus("👆 AUTHENTICATING", colorCyan, "PLACE FINGER ON SENSOR")
                        onScanTapped()
                    } else {
                        updateStatus("✅ READY", colorGreen, "TAP BUTTON BELOW TO SCAN BIOMETRIC")
                        btnScan.animate().scaleX(1.04f).scaleY(1.04f).setDuration(150).withEndAction {
                            btnScan.animate().scaleX(1f).scaleY(1f).setDuration(150).start()
                        }.start()
                    }
                }
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Init failed: ${e.message}", e)
                runOnUiThread {
                    updateStatus("❌ INIT FAILED", colorRed,
                        e.message?.take(60)?.uppercase() ?: "UNKNOWN ERROR · RESTART APP")
                    // Allow retry — enable btn
                    btnScan.isEnabled = true
                    btnScan.alpha     = 0.7f
                    btnScan.text      = "RETRY"
                }
            }
        }
    }

    // ── Biometric Flow ────────────────────────────────────────────────────────
    private fun onScanTapped() {
        if (isProving) return

        val bio = BiometricManager.from(this)
        if (bio.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            != BiometricManager.BIOMETRIC_SUCCESS) {
            updateStatus("❌ BIOMETRIC UNAVAILABLE", colorRed,
                "DEVICE DOES NOT SUPPORT BIOMETRIC AUTH")
            return
        }

        val cryptoObj = DeviceTierGate.buildCryptoObject()
        if (cryptoObj == null) {
            updateStatus("❌ KEY ERROR", colorRed, "DEVICE KEY MISSING — PLEASE RETRY")
            initInBackground()
            return
        }

        val executor = ContextCompat.getMainExecutor(this)
        val prompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val sig = result.cryptoObject?.signature ?: run {
                        updateStatus("❌ SIGNATURE ERROR", colorRed, "CRYPTO OBJECT NULL")
                        resetScanButton()
                        return
                    }
                    onBiometricSuccess(sig)
                }
                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    if (code != BiometricPrompt.ERROR_USER_CANCELED &&
                        code != BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                        updateStatus("❌ AUTH ERROR", colorRed, msg.toString().uppercase())
                    } else {
                        updateStatus("✅ READY", colorGreen, "TAP BUTTON BELOW TO SCAN BIOMETRIC")
                    }
                    resetScanButton()
                }
                override fun onAuthenticationFailed() {
                    updateStatus("⚠️ NOT RECOGNIZED", colorGold, "FINGERPRINT NOT MATCHED — TRY AGAIN")
                    haptic()
                }
            })

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("ZKAuth — Device Proof")
            .setSubtitle("Proving you are human · no data is shared")
            .setDescription("Domain: ${zkDomain.ifEmpty { "local" }}")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        isProving              = true
        btnScan.isEnabled      = false
        btnScan.alpha          = 0.5f
        progressBar.visibility = View.VISIBLE
        updateStatus("👆 AUTHENTICATING", colorCyan, "PLACE FINGER ON SENSOR")
        prompt.authenticate(info, cryptoObj)
    }

    // ── ZK Proof ──────────────────────────────────────────────────────────────
    private fun onBiometricSuccess(signature: java.security.Signature) {
        haptic()
        progressBar.visibility = View.VISIBLE

        lifecycleScope.launch {
            // Step 1: Collecting device data
            updateStatus("⚡ STEP 1/3", colorCyan, "COLLECTING DEVICE DATA...")

            val result = DeviceTierGate.generateProof(
                context    = this@DeviceTierActivity,
                signature  = signature,
                domain     = zkDomain,
                challenge  = zkChallenge,
                callback   = zkCallback,
                sessionId  = zkSession,
                onProgress = { step ->
                    runOnUiThread {
                        updateStatus("⚡ $step", colorCyan, "")
                    }
                }
            )

            runOnUiThread {
                progressBar.visibility = View.GONE
                resetScanButton()
                when (result) {
                    is DeviceTierGate.DeviceTierResult.Success -> onProofSuccess(result)
                    is DeviceTierGate.DeviceTierResult.Error   -> onProofError(result.message)
                }
            }
        }
    }

    private fun onProofSuccess(result: DeviceTierGate.DeviceTierResult.Success) {
        haptic()
        updateStatus("✅ IDENTITY VERIFIED", colorGreen, "BASIC TRUST · ZK PROOF ACCEPTED")

        tvProofTime.text = "${result.proofMs}ms"
        val nullPrefix   = result.nullifier.take(16).uppercase().ifEmpty { "ZK COMMITTED" }

        cardResult.visibility = View.VISIBLE
        tvResultRows.text =
            "⚡  Plonky2  ·  ${result.proofMs}ms\n" +
            "🔑  Nullifier:  $nullPrefix…\n" +
            "🛡️  Trust:      ${result.trustLevel}\n" +
            "🌐  Domain:     ${zkDomain.ifEmpty { "local" }}"
        animateFadeIn(cardResult)

        cardClaims.visibility = View.VISIBLE
        tvClaimsRows.text =
            "✅  is_human        — Biometric verified\n" +
            "✅  is_real_device  — Hardware attested\n" +
            "✅  is_unique       — Domain nullifier\n" +
            "✅  account_age_ok  — Device registered > 30d\n" +
            "❌  Name / DOB / ID — Never revealed"
        animateFadeIn(cardClaims)

        scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }

        if (zkCallback.isNotEmpty()) {
            // Deep link / auth mode — auto finish, website gets notified
            android.os.Handler(mainLooper).postDelayed({
                setResult(RESULT_OK)
                finish()
            }, 2000)
        } else {
            // Registration mode — stay on screen, show success
            updateStatus("✅ DEVICE REGISTERED", colorGreen,
                "TIER 3 IDENTITY READY · USE FROM WEBSITE")
        }
    }

    private fun onProofError(message: String) {
        // Show full error on screen — no logcat needed for debugging
        val displayMsg = message.take(80).uppercase()
        updateStatus("❌ PROOF FAILED", colorRed, displayMsg)
        cardResult.visibility = View.VISIBLE
        tvProofTime.text      = "FAILED"
        tvProofTime.setTextColor(colorRed)
        tvResultRows.text = buildString {
            appendLine("❌  Error:")
            appendLine(message.take(200))
            appendLine()
            appendLine("Domain:    ${zkDomain.ifEmpty { "none" }}")
            appendLine("Challenge: ${zkChallenge.take(16).ifEmpty { "none" }}…")
            appendLine("Callback:  ${zkCallback.take(60).ifEmpty { "none" }}")
        }
        animateFadeIn(cardResult)
        hapticError()
    }

    // ── Full UI Build ─────────────────────────────────────────────────────────
    private fun buildUI() {
        val root = FrameLayout(this).apply { setBackgroundColor(colorBg) }

        scrollView = ScrollView(this).apply {
            layoutParams   = FrameLayout.LayoutParams(MATCH, MATCH)
            overScrollMode = View.OVER_SCROLL_NEVER
        }
        val container = LinearLayout(this).apply {
            orientation  = LinearLayout.VERTICAL
            layoutParams = FrameLayout.LayoutParams(MATCH, WRAP)
        }
        progressBar = ProgressBar(this).apply { visibility = View.GONE }

        container.addView(buildHeader())
        container.addView(buildStatusBanner())
        container.addView(spacer(14))
        container.addView(buildClaimsPreview())
        container.addView(spacer(6))
        container.addView(buildSectionLabel("PROOF RESULT"))
        container.addView(buildResultCard())
        container.addView(buildSectionLabel("ZK CLAIMS PROVEN"))
        container.addView(buildClaimsCard())
        container.addView(progressBar)
        container.addView(spacer(16))
        container.addView(buildScanButton())
        container.addView(spacer(36))

        scrollView.addView(container)
        root.addView(scrollView)
        setContentView(root)
    }

    // ── Header ────────────────────────────────────────────────────────────────
    private fun buildHeader(): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(px(20), px(20), px(20), px(16))
            gravity     = Gravity.CENTER_VERTICAL
            setBackgroundColor(colorBg)
        }
        val back = TextView(this).apply {
            text = "←"; textSize = 20f; setTextColor(colorCyan)
            setPadding(px(12), px(10), px(12), px(10))
            background = cyberBorder(colorBorder, 12f)
            setOnClickListener { finish() }
        }
        val titleBlock = LinearLayout(this).apply {
            orientation  = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, WRAP, 1f).apply { setMargins(px(14), 0, 0, 0) }
        }
        titleBlock.addView(TextView(this).apply {
            text = "DEVICE IDENTITY"; textSize = 14f; setTextColor(colorGold)
            letterSpacing = 0.15f; typeface = Typeface.DEFAULT_BOLD
        })
        titleBlock.addView(TextView(this).apply {
            text = "TIER 3  ·  BIOMETRIC  ·  HARDWARE BACKED"
            textSize = 9f; setTextColor(Color.parseColor("#776633")); letterSpacing = 0.1f
        })
        val badge = TextView(this).apply {
            text = "📱"; textSize = 20f; setPadding(px(10), px(8), px(10), px(8))
            background = cyberBorder(Color.parseColor("#332200"), 10f)
        }
        row.addView(back); row.addView(titleBlock); row.addView(badge)
        val divider = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH, 1); setBackgroundColor(colorBorder)
        }
        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; addView(row); addView(divider)
        }
    }

    // ── Status Banner ─────────────────────────────────────────────────────────
    private fun buildStatusBanner(): View {
        val wrapper = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(px(16), px(12), px(16), 0)
        }
        statusBanner = CardView(this).apply {
            radius = px(14).toFloat(); cardElevation = 0f
            setCardBackgroundColor(Color.parseColor("#040e1a"))
        }
        val inner = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(px(14), px(14), px(14), px(14)); gravity = Gravity.CENTER_VERTICAL
        }
        tvStatusDot = TextView(this).apply {
            text = "●"; textSize = 10f; setTextColor(colorGold)
            layoutParams = LinearLayout.LayoutParams(WRAP, WRAP).apply { setMargins(0, 0, px(10), 0) }
        }
        val textCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, WRAP, 1f)
        }
        tvStatusMsg = TextView(this).apply {
            text = "INITIALIZING"; textSize = 11f; setTextColor(colorGold)
            typeface = Typeface.DEFAULT_BOLD; letterSpacing = 0.12f
        }
        tvStatusSub = TextView(this).apply {
            text = "LOADING PLONKY2 CIRCUIT"; textSize = 9f
            setTextColor(Color.parseColor("#776633")); letterSpacing = 0.08f
        }
        textCol.addView(tvStatusMsg); textCol.addView(tvStatusSub)
        inner.addView(tvStatusDot); inner.addView(textCol)
        statusBanner.addView(inner); wrapper.addView(statusBanner)
        return wrapper
    }

    // ── Claims Preview ────────────────────────────────────────────────────────
    private fun buildClaimsPreview(): View {
        val wrapper = LinearLayout(this).apply { setPadding(px(16), 0, px(16), 0) }
        val card = CardView(this).apply {
            radius = px(16).toFloat(); cardElevation = 0f
            setCardBackgroundColor(colorCardBg)
            layoutParams = LinearLayout.LayoutParams(MATCH, WRAP)
        }
        val inner = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(px(16), px(16), px(16), px(16))
        }
        inner.addView(TextView(this).apply {
            text = "WHAT WILL BE PROVEN"; textSize = 9f
            setTextColor(Color.parseColor("#445566"))
            letterSpacing = 0.15f; typeface = Typeface.DEFAULT_BOLD
        })
        inner.addView(spacer(12))
        inner.addView(buildMerkleVisual())
        inner.addView(spacer(14))

        listOf(
            colorGreen                   to "✅  is_human"       to "Real biometric — nothing revealed",
            colorGold                    to "✅  is_real_device" to "Hardware KeyStore attestation",
            colorCyan                    to "✅  is_unique"      to "Poseidon nullifier — replay-proof",
            Color.parseColor("#aa88ff")  to "✅  account_age_ok" to "Device registered > 30 days",
            colorRed                     to "❌  Name / ID / DOB" to "Never sent — ZK guarantee",
        ).forEach { (colorLabel, desc) ->
            val (color, label) = colorLabel
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER_VERTICAL
                layoutParams = LinearLayout.LayoutParams(MATCH, WRAP).apply { setMargins(0, 0, 0, px(8)) }
            }
            row.addView(TextView(this).apply {
                text = label; textSize = 11f; setTextColor(color)
                typeface = Typeface.DEFAULT_BOLD
                layoutParams = LinearLayout.LayoutParams(0, WRAP, 1f)
            })
            row.addView(TextView(this).apply {
                text = desc; textSize = 9f; setTextColor(Color.parseColor("#4a6677"))
            })
            inner.addView(row)
        }
        card.addView(inner); wrapper.addView(card)
        return wrapper
    }

    // ── 4-Leaf Merkle Tree Visual ─────────────────────────────────────────────
    private fun buildMerkleVisual(): View {
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; gravity = Gravity.CENTER_HORIZONTAL
        }
        container.addView(buildMerkleNode("MERKLE ROOT", colorGold))
        container.addView(spacer(4))
        container.addView(TextView(this).apply {
            text = "       │                    │"; textSize = 9f
            setTextColor(Color.parseColor("#334455")); typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
        })
        val midRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER
        }
        midRow.addView(buildMerkleNode("  L  ", colorCyan))
        midRow.addView(TextView(this).apply {
            text = "  ─────  "; textSize = 9f
            setTextColor(Color.parseColor("#334455")); typeface = Typeface.MONOSPACE
        })
        midRow.addView(buildMerkleNode("  R  ", colorCyan))
        container.addView(midRow)
        container.addView(spacer(4))
        container.addView(TextView(this).apply {
            text = "  │      │              │      │"; textSize = 9f
            setTextColor(Color.parseColor("#334455")); typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
        })
        val leafRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL; gravity = Gravity.CENTER
        }
        listOf(
            "Bio"  to colorGreen,
            "Dev"  to colorGold,
            "Null" to colorCyan,
            "Age"  to Color.parseColor("#aa88ff")
        ).forEachIndexed { i, (label, color) ->
            leafRow.addView(buildMerkleLeaf(label, color))
            if (i < 3) leafRow.addView(View(this).apply {
                layoutParams = LinearLayout.LayoutParams(px(8), 1)
            })
        }
        container.addView(leafRow)
        return container
    }

    private fun buildMerkleNode(label: String, color: Int) = TextView(this).apply {
        text = label; textSize = 9f; setTextColor(color)
        typeface = Typeface.DEFAULT_BOLD; gravity = Gravity.CENTER
        setPadding(px(12), px(6), px(12), px(6))
        background = GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE; cornerRadius = px(8).toFloat()
            setColor(adjustAlpha(color, 0.08f)); setStroke(1, adjustAlpha(color, 0.35f))
        }
    }

    private fun buildMerkleLeaf(label: String, color: Int) = TextView(this).apply {
        text = label; textSize = 9f; setTextColor(color)
        typeface = Typeface.DEFAULT_BOLD; gravity = Gravity.CENTER
        setPadding(px(10), px(5), px(10), px(5))
        background = GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE; cornerRadius = px(6).toFloat()
            setColor(adjustAlpha(color, 0.12f)); setStroke(1, adjustAlpha(color, 0.45f))
        }
    }

    // ── Result Card ───────────────────────────────────────────────────────────
    private fun buildResultCard(): View {
        val wrapper = LinearLayout(this).apply { setPadding(px(16), 0, px(16), 0) }
        cardResult = CardView(this).apply {
            radius = px(14).toFloat(); cardElevation = 0f
            setCardBackgroundColor(Color.parseColor("#041a0d")); visibility = View.GONE
        }
        val inner = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(px(14), px(12), px(14), px(12)); gravity = Gravity.CENTER_VERTICAL
        }
        val icon = TextView(this).apply {
            text = "⚡"; textSize = 22f
            layoutParams = LinearLayout.LayoutParams(WRAP, WRAP).apply { setMargins(0, 0, px(12), 0) }
        }
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, WRAP, 1f)
        }
        tvProofTime = TextView(this).apply {
            text = "—"; textSize = 12f; setTextColor(colorGreen); typeface = Typeface.DEFAULT_BOLD
        }
        tvResultRows = TextView(this).apply {
            textSize = 10f; setTextColor(Color.parseColor("#4a8a6a"))
            letterSpacing = 0.04f; lineHeight = (textSize * 1.9f).toInt()
        }
        col.addView(tvProofTime); col.addView(tvResultRows)
        inner.addView(icon); inner.addView(col)
        cardResult.addView(inner); wrapper.addView(cardResult)
        return wrapper
    }

    // ── Claims Card ───────────────────────────────────────────────────────────
    private fun buildClaimsCard(): View {
        val wrapper = LinearLayout(this).apply { setPadding(px(16), 0, px(16), 0) }
        cardClaims = CardView(this).apply {
            radius = px(14).toFloat(); cardElevation = 0f
            setCardBackgroundColor(colorCardBg); visibility = View.GONE
        }
        val inner = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(px(14), px(14), px(14), px(14))
        }
        tvClaimsRows = TextView(this).apply {
            textSize = 11f; setTextColor(Color.parseColor("#4a8a6a"))
            letterSpacing = 0.03f; lineHeight = (textSize * 1.9f).toInt()
        }
        inner.addView(tvClaimsRows); cardClaims.addView(inner); wrapper.addView(cardClaims)
        return wrapper
    }

    // ── Scan Button ───────────────────────────────────────────────────────────
    private fun buildScanButton(): View {
        val wrapper = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL; setPadding(px(16), 0, px(16), 0)
        }
        btnScan = Button(this).apply {
            text          = "👆  SCAN BIOMETRIC"
            textSize      = 13f; typeface = Typeface.DEFAULT_BOLD; letterSpacing = 0.12f
            setTextColor(Color.parseColor("#020810"))
            background = GradientDrawable(
                GradientDrawable.Orientation.LEFT_RIGHT,
                intArrayOf(Color.parseColor("#cc7700"), Color.parseColor("#ffcc00"))
            ).apply { cornerRadius = px(14).toFloat() }
            layoutParams  = LinearLayout.LayoutParams(MATCH, px(56))
            isEnabled     = false; alpha = 0.4f; setPadding(0, 0, 0, 0)
            setOnClickListener { onScanTapped() }
        }
        wrapper.addView(btnScan)
        return wrapper
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    private fun resetScanButton() {
        isProving         = false
        btnScan.isEnabled = true
        btnScan.alpha     = 1f
        progressBar.visibility = View.GONE
    }

    private fun updateStatus(msg: String, color: Int, sub: String) {
        runOnUiThread {
            tvStatusDot.setTextColor(color)
            tvStatusMsg.text = msg; tvStatusMsg.setTextColor(color)
            tvStatusSub.text = sub
        }
    }

    private fun animateFadeIn(view: View) {
        view.alpha = 0f; view.translationY = px(12).toFloat()
        view.animate().alpha(1f).translationY(0f)
            .setDuration(350).setInterpolator(DecelerateInterpolator()).start()
    }

    private fun haptic() {
        try {
            val v = getSystemService(VIBRATOR_SERVICE) as Vibrator
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                v.vibrate(VibrationEffect.createOneShot(60, VibrationEffect.DEFAULT_AMPLITUDE))
            else @Suppress("DEPRECATION") v.vibrate(60)
        } catch (_: Exception) {}
    }

    private fun hapticError() {
        try {
            val v = getSystemService(VIBRATOR_SERVICE) as Vibrator
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                v.vibrate(VibrationEffect.createWaveform(longArrayOf(0, 80, 60, 80), -1))
            else @Suppress("DEPRECATION") v.vibrate(longArrayOf(0, 80, 60, 80), -1)
        } catch (_: Exception) {}
    }

    private fun cyberBorder(color: Int, radius: Float) = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE; cornerRadius = px(radius.toInt()).toFloat()
        setStroke(1, color); setColor(Color.TRANSPARENT)
    }

    private fun adjustAlpha(color: Int, factor: Float): Int {
        val alpha = (Color.alpha(color) * factor).toInt().coerceIn(0, 255)
        return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color))
    }

    private fun buildSectionLabel(text: String) = TextView(this).apply {
        this.text = text; textSize = 9f; setTextColor(Color.parseColor("#334455"))
        letterSpacing = 0.15f; typeface = Typeface.DEFAULT_BOLD
        setPadding(px(20), px(16), px(20), px(8))
    }

    private fun spacer(dp: Int) = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(MATCH, px(dp))
    }

    private fun px(dp: Int) = (dp * resources.displayMetrics.density).toInt()

    private val MATCH = LinearLayout.LayoutParams.MATCH_PARENT
    private val WRAP  = LinearLayout.LayoutParams.WRAP_CONTENT
}