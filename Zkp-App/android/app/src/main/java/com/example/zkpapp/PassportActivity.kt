package com.example.zkpapp

import android.animation.*
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.*
import android.graphics.drawable.*
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.TagLostException
import android.nfc.tech.IsoDep
import android.os.*
import android.view.*
import android.view.animation.*
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.*
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class PassportActivity : AppCompatActivity() {

    // ── Security ──────────────────────────────────────────────────────────────
    private val keyStoreManager  = com.example.zkpapp.security.KeyStoreManager()
    private val biometricManager by lazy { com.example.zkpapp.security.ZkBiometricManager(this) }

    // ── NFC ───────────────────────────────────────────────────────────────────
    private var nfcAdapter: NfcAdapter? = null
    private val isNfcBusy    = AtomicBoolean(false)
    private val lastScanTime = AtomicLong(0)
    private val NFC_COOLDOWN = 3000L

    // ── Session ───────────────────────────────────────────────────────────────
    private var session  = PassportSession()
    private var rustJob: Job? = null

    // ── UI References ─────────────────────────────────────────────────────────
    private lateinit var tvHeader:        TextView
    private lateinit var tvSubHeader:     TextView
    private lateinit var statusBanner:    CardView
    private lateinit var tvStatusDot:     TextView
    private lateinit var tvStatusMsg:     TextView
    private lateinit var tvStatusSub:     TextView
    private lateinit var photoFrame:      CardView
    private lateinit var photoView:       ImageView
    private lateinit var tvPhotoLabel:    TextView
    private lateinit var cardIdentity:    CardView
    private lateinit var tvName:          TextView
    private lateinit var tvDocNum:        TextView
    private lateinit var tvNationality:   TextView
    private lateinit var tvSodStatus:     TextView
    private lateinit var tvMode:          TextView
    private lateinit var cardProof:       CardView
    private lateinit var tvProofHash:     TextView
    private lateinit var tvProofTime:     TextView
    private lateinit var cardIntegrity:   CardView
    private lateinit var tvIntegrityRows: TextView
    private lateinit var cardCrypto:      CardView
    private lateinit var tvCryptoRows:    TextView
    private lateinit var progressBar:     ProgressBar
    private lateinit var stepBar:         LinearLayout
    private lateinit var btnScanMrz:      Button
    private lateinit var btnSimulate:     Button
    private lateinit var scrollView:      ScrollView

    // Colors
    private val colorBg       = Color.parseColor("#020810")
    private val colorBg2      = Color.parseColor("#050f1e")
    private val colorCyan     = Color.parseColor("#00f5ff")
    private val colorGreen    = Color.parseColor("#00ff88")
    private val colorRed      = Color.parseColor("#ff3366")
    private val colorGold     = Color.parseColor("#ffd700")
    private val colorBorder   = Color.parseColor("#1a3a4a")
    private val colorCardBg   = Color.parseColor("#070e1a")

    // ── Camera Launcher ───────────────────────────────────────────────────────
    private val cameraLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode != RESULT_OK) return@registerForActivityResult
            val rawMrz = result.data?.getStringExtra("MRZ_DATA") ?: return@registerForActivityResult

            // [SESSION v2.0] MrzInfo.fromRaw() — no more PENDING placeholders
            // Parses documentNumber, DOB, expiry, nationality, gender from raw MRZ immediately
            val mrzInfo = MrzInfo.fromRaw(rawMrz)
            val validationError = mrzInfo.validate()
            if (validationError != null) {
                showToast("⚠️ MRZ Error: $validationError")
                return@registerForActivityResult
            }
            session = PassportSession(
                mrzInfo   = mrzInfo,
                state     = SessionState.MRZ_SCANNED,
                tier      = mrzInfo.docType   // DocumentTier.PASSPORT or NATIONAL_ID
            )
            // [SESSION v2.0] DRY strings from SessionState — no hardcoded text
            updateStatus(session.state.displayString, colorCyan, session.state.statusSub)
            updateStepBar(session.state.stepIndex)
        }

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        window.statusBarColor = colorBg
        window.navigationBarColor = colorBg

        buildUI()

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null) {
            updateStatus("⚠️ NFC NOT AVAILABLE", colorRed, "SIMULATION MODE ONLY")
            btnScanMrz.isEnabled = false
            btnScanMrz.alpha = 0.4f
        }

        // Warmup Rust ZK circuit on app start — saves ~600ms on first proof
        lifecycleScope.launch(Dispatchers.IO) {
            IdentityStorage.warmup()
        }
    }

    override fun onResume() {
        super.onResume()
        enableNfcDispatch()
    }

    override fun onPause() {
        super.onPause()
        try { nfcAdapter?.disableForegroundDispatch(this) } catch (_: Exception) {}
    }

    // ── NFC ───────────────────────────────────────────────────────────────────
    private fun enableNfcDispatch() {
        nfcAdapter?.let { adapter ->
            val intent = Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
            val flags = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) PendingIntent.FLAG_MUTABLE else 0
            val pending = PendingIntent.getActivity(this, 0, intent, flags)
            adapter.enableForegroundDispatch(
                this, pending,
                arrayOf(IntentFilter(NfcAdapter.ACTION_TECH_DISCOVERED)),
                arrayOf(arrayOf(IsoDep::class.java.name))
            )
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val now = System.currentTimeMillis()
        if (now - lastScanTime.get() < NFC_COOLDOWN) return
        lastScanTime.set(now)
        if (isNfcBusy.get()) return
        if (!SecurityGate.canStartNfc(session)) {
            showToast("⚠️ Scan MRZ first!")
            return
        }
        val tag: Tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG) ?: return
        val isoDep = IsoDep.get(tag) ?: run {
            updateStatus("❌ NOT AN E-PASSPORT", colorRed, "ISO DEP NOT FOUND")
            return
        }
        startEngine(PassportMode.REAL, isoDep)
    }

    // ── Engine ────────────────────────────────────────────────────────────────
    private fun runSimulation() {
        session = PassportSession()
        startEngine(PassportMode.SIMULATION, null)
    }

    private fun startEngine(mode: PassportMode, isoDep: IsoDep?) {
        isNfcBusy.set(true)
        resetResultUI()
        progressBar.visibility = View.VISIBLE
        btnScanMrz.isEnabled  = false
        btnSimulate.isEnabled = false

        // [SESSION v2.0] Advance to CONNECTING state — DRY status strings
        session = session.copy(state = SessionState.CONNECTING)
        updateStatus(session.state.displayString, colorCyan, session.state.statusSub)
        updateStepBar(session.state.stepIndex)

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                isoDep?.apply { timeout = 8000; if (!isConnected) connect() }
                val engine = PassportEngine(mode, isoDep, session.mrzInfo?.raw)
                val data   = engine.start()
                withContext(Dispatchers.Main) {
                    if (!isFinishing && !isDestroyed) handleSuccess(data)
                }
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    if (!isFinishing && !isDestroyed) handleError(e)
                }
            } finally {
                try { isoDep?.close() } catch (_: Exception) {}
                isNfcBusy.set(false)
            }
        }
    }

    private fun handleSuccess(data: PassportData) {
        progressBar.visibility = View.GONE
        btnScanMrz.isEnabled  = true
        btnSimulate.isEnabled = true

        // [SESSION v2.0] DONE state
        session = session.copy(state = SessionState.DONE)
        performHapticFeedback()
        updateStatus(session.state.displayString, colorGreen, session.state.statusSub)
        updateStepBar(session.state.stepIndex)

        // Photo — use PassportData.getCachedPhoto() first (survives Parcel roundtrip)
        val photo = data.facePhoto
            ?: PassportData.getCachedPhoto(data.documentNumber)
        photo?.let {
            val scaled = Bitmap.createScaledBitmap(it, 300, 400, true)
            photoView.setImageBitmap(scaled)
            photoView.visibility = View.VISIBLE
            tvPhotoLabel.visibility = View.GONE
        }

        // Identity
        tvName.text        = "${data.firstName} ${data.lastName}"
        tvDocNum.text      = data.documentNumber
        tvNationality.text = nationalityDisplay(data.nationality)
        val sodSize = data.sodRaw?.size ?: 0
        tvSodStatus.text = if (sodSize > 0) "✅ FOUND · ${sodSize}B" else "❌ MISSING"
        tvSodStatus.setTextColor(if (sodSize > 0) colorGreen else colorRed)
        tvMode.text = if (session.mrzInfo == null) "SIMULATION" else "REAL NFC"
        cardIdentity.visibility = View.VISIBLE
        animateFadeIn(cardIdentity)

        // [v3.0] Biometric-gated encrypted save
        // KeyStoreManager AES → encrypt DG1/SOD → EncryptedSharedPreferences
        // User never needs to rescan passport on this device after this.
        try {
            val cipher    = keyStoreManager.getCipherForEncryption()
            val cryptoObj = androidx.biometric.BiometricPrompt.CryptoObject(cipher)

            biometricManager.authenticateUser(
                activity     = this,
                cryptoObject = cryptoObj,
                subtitle     = "Passport ko secure karne ke liye fingerprint lagayein",
                onSuccess    = { result ->
                    val encCipher = result.cryptoObject?.cipher ?: run {
                        saveIdentityRamOnly(data)
                        startZkProofGeneration(data)
                        return@authenticateUser
                    }
                    IdentityStorage.saveIdentityEncrypted(
                        context     = this,
                        cipher      = encCipher,
                        secret      = data.dg1SecretHex,
                        country     = data.nationality.ifEmpty { "PAK" },
                        docNumber   = data.documentNumber,
                        fName       = data.firstName,
                        lName       = data.lastName,
                        nationality = data.nationality,
                        dob         = data.dateOfBirth,
                        expiry      = data.expiryDate,
                        dg1         = data.dg1Hex,
                        sod         = data.sodHex,
                        mrz         = data.mrzLine.ifEmpty { session.mrzInfo?.raw ?: "" },
                        dsCert      = data.dsCertHex,
                        domain      = "zkpapp.local"
                    )
                    startZkProofGeneration(data)
                },
                onError = { errMsg ->
                    saveIdentityRamOnly(data)
                    showToast("⚠️ Biometric skipped — identity not persisted: $errMsg")
                    startZkProofGeneration(data)
                },
                onFailed = {
                    showToast("⚠️ Wrong fingerprint — try again")
                }
            )
            return
        } catch (e: com.example.zkpapp.security.KeyStoreManager.KeyInvalidatedException) {
            keyStoreManager.deleteKey()
            IdentityStorage.clearPersistent(this)
            showToast("🔑 New biometric detected — identity cleared. Rescan passport.")
            saveIdentityRamOnly(data)
        } catch (e: Exception) {
            saveIdentityRamOnly(data)
        }
        startZkProofGeneration(data)
    }

    // ── RAM-only fallback (biometric cancelled / key error) ───────────────────
    private fun saveIdentityRamOnly(data: PassportData) {
        IdentityStorage.saveIdentity(
            secret      = data.dg1SecretHex,
            country     = data.nationality.ifEmpty { "PAK" },
            docNumber   = data.documentNumber,
            fName       = data.firstName,
            lName       = data.lastName,
            nationality = data.nationality,
            dob         = data.dateOfBirth,
            expiry      = data.expiryDate,
            dg1         = data.dg1Hex,
            sod         = data.sodHex,
            mrz         = data.mrzLine.ifEmpty { session.mrzInfo?.raw ?: "" },
            dsCert      = data.dsCertHex,
            domain      = "zkpapp.local"
        )
    }

    // ── ZK Proof Generation ───────────────────────────────────────────────────
    private fun startZkProofGeneration(data: PassportData) {
        rustJob?.cancel()
        session = session.copy(state = SessionState.ZKP_GENERATING)
        updateStatus(session.state.displayString, colorCyan, session.state.statusSub)
        updateStepBar(session.state.stepIndex)

        rustJob = lifecycleScope.launch {
            try {
                IdentityStorage.setVerifierDomain("zkpapp.local")

                val rustResult = SecurityGate.generateClaim(
                    claimType = "is_adult",
                    domain    = "zkpapp.local",
                    context   = this@PassportActivity
                )

                if (isFinishing || isDestroyed) return@launch

                when (rustResult) {
                    is SecurityGate.ProofResult.Success -> {
                        session = session.copy(state = SessionState.ZKP_READY)
                        updateStatus(session.state.displayString, colorGreen, session.state.statusSub)
                        updateStepBar(session.state.stepIndex)
                        showRustSuccess(data, rustResult.result)
                        showToast("🦁 ZK Proof Ready · ${session.minutesRemaining}min session")
                    }
                    is SecurityGate.ProofResult.Failure -> {
                        showRustError(rustResult.reason)
                        performErrorVibration()
                    }
                }
            } catch (e: Exception) {
                if (!isFinishing && !isDestroyed) {
                    showRustError(e.message ?: "Proof generation failed")
                    performErrorVibration()
                }
            } finally {
                isNfcBusy.set(false)
            }
        }
    }

    private fun showRustSuccess(data: PassportData, result: SecurityGate.PassportProofResult) {
        val modeLabel = if (result.inputMode == "NFC_PASSPORT") "REAL NFC" else "SIMULATED"
        updateStatus("✅ PASSPORT AUTHENTIC", colorGreen, "$modeLabel · ZK PROOF GENERATED")

        // Proof bar
        cardProof.visibility = View.VISIBLE
        tvProofTime.text = "${result.zkProofMs}ms"
        val nullifierPrefix = result.nullifier.take(16).uppercase().ifEmpty { "ZK COMMITTED" }
        tvProofHash.text = "Plonky2 · v5.1 · $nullifierPrefix…"
        animateFadeIn(cardProof)

        // Integrity card
        cardIntegrity.visibility = View.VISIBLE
        tvIntegrityRows.text =
            "👤  ${result.holderName.ifEmpty { "${data.firstName} ${data.lastName}" }}\n" +
            "🔒  Integrity:  ${result.integrityCheck}\n" +
            "🛡️  Trust:      ${result.trustLevel}"
        animateFadeIn(cardIntegrity)

        // Crypto card
        val zkOutput  = result.zkOutput
        val proofType = if (zkOutput != null) "RECURSIVE v${zkOutput.version}" else "NONE"
        cardCrypto.visibility = View.VISIBLE
        tvCryptoRows.text =
            "🛡️  Integrity:  ${result.integrityCheck}\n" +
            "✅  Signature:  ${result.signatureCheck}\n" +
            "🔑  Algorithm:  RSA-2048 + Poseidon\n" +
            "⚡  ZK Proof:   ${result.zkProofStatus}\n" +
            "📦  Proof Type: $proofType\n" +
            if (zkOutput != null) "⏰  Expires:    ${
                java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
                    .format(java.util.Date(zkOutput.validUntil * 1000))
            }" else "🔗  HW Binding: NONE"
        animateFadeIn(cardCrypto)

        scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
    }

    private fun showRustError(reason: String) {
        updateStatus("❌ PASSPORT REJECTED", colorRed, reason.take(40).uppercase())
        cardIntegrity.visibility = View.VISIBLE
        tvIntegrityRows.text = "❌ Verification failed\n$reason"
    }

    // Nationality flag + name lookup
    private fun nationalityDisplay(code: String): String {
        val map = mapOf(
            "PAK" to "🇵🇰 PAKISTAN",  "USA" to "🇺🇸 USA",
            "GBR" to "🇬🇧 UK",        "ARE" to "🇦🇪 UAE",
            "SAU" to "🇸🇦 SAUDI",     "IND" to "🇮🇳 INDIA",
            "DEU" to "🇩🇪 GERMANY",   "FRA" to "🇫🇷 FRANCE",
            "CHN" to "🇨🇳 CHINA",     "TUR" to "🇹🇷 TURKEY"
        )
        return map[code.uppercase()] ?: "🌐 ${code.uppercase()}"
    }

    private fun handleError(e: Exception) {
        progressBar.visibility = View.GONE
        btnScanMrz.isEnabled  = true
        btnSimulate.isEnabled = true

        val (msg, sub) = when (e) {
            is TagLostException -> "⚠️ CHIP CONNECTION LOST" to "Hold phone steady & retry"
            is IOException      -> "⚠️ READ FAILED"         to "Remove case & retry"
            is SecurityException-> "❌ SECURITY ERROR"      to (e.message ?: "")
            else                -> "❌ ENGINE ERROR"         to (e.localizedMessage ?: "Unknown")
        }
        // [SESSION v2.0] withError() — preserves mrzInfo, sets ERROR state + message
        session = session.withError("$msg — $sub")
        updateStatus(msg, colorRed, sub.uppercase())
        performErrorVibration()
    }

    // ── UI Builders ───────────────────────────────────────────────────────────

    private fun buildUI() {
        val root = FrameLayout(this).apply { setBackgroundColor(colorBg) }

        scrollView = ScrollView(this).apply {
            layoutParams = FrameLayout.LayoutParams(MATCH, MATCH)
            overScrollMode = View.OVER_SCROLL_NEVER
        }

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = FrameLayout.LayoutParams(MATCH, WRAP)
        }

        progressBar = ProgressBar(this).apply { visibility = View.GONE }

        container.addView(buildHeader())
        container.addView(buildStepBar())
        container.addView(buildStatusBanner())
        container.addView(buildPhotoIdentityRow())
        container.addView(buildProofBar())
        container.addView(buildSectionLabel("RUST INTEGRITY REPORT"))
        container.addView(buildResultCard(isIntegrity = true))
        container.addView(buildSectionLabel("CRYPTO REPORT"))
        container.addView(buildResultCard(isIntegrity = false))
        container.addView(progressBar)
        container.addView(buildButtons())
        container.addView(spacer(32))

        scrollView.addView(container)
        root.addView(scrollView)
        setContentView(root)
    }

    private fun buildHeader(): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(px(20), px(20), px(20), px(16))
            gravity = Gravity.CENTER_VERTICAL
            setBackgroundColor(colorBg)
        }

        val back = TextView(this).apply {
            text = "←"
            textSize = 20f
            setTextColor(colorCyan)
            setPadding(px(12), px(10), px(12), px(10))
            background = cyberBorder(colorBorder, 12f)
            setOnClickListener { finish() }
        }

        val titleBlock = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, WRAP, 1f).apply { setMargins(px(14), 0, 0, 0) }
        }
        tvHeader = TextView(this).apply {
            text = "NFC PASSPORT"
            textSize = 14f
            setTextColor(colorCyan)
            letterSpacing = 0.15f
            typeface = Typeface.DEFAULT_BOLD
        }
        tvSubHeader = TextView(this).apply {
            text = "ICAO 9303  ·  BAC  ·  ZK PROOF"
            textSize = 9f
            setTextColor(Color.parseColor("#447788"))
            letterSpacing = 0.1f
        }
        titleBlock.addView(tvHeader)
        titleBlock.addView(tvSubHeader)

        val shield = TextView(this).apply {
            text = "🛡️"
            textSize = 20f
            setPadding(px(10), px(8), px(10), px(8))
            background = cyberBorder(Color.parseColor("#003322"), 10f)
        }

        row.addView(back)
        row.addView(titleBlock)
        row.addView(shield)

        val divider = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH, 1)
            setBackgroundColor(colorBorder)
        }

        return LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(row)
            addView(divider)
        }
    }

    private fun buildStepBar(): View {
        stepBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(px(16), px(12), px(16), px(4))
            gravity = Gravity.CENTER_VERTICAL
        }
        val steps = listOf("MRZ", "NFC", "READ", "SOD", "ZKP")
        steps.forEachIndexed { i, s ->
            val chip = TextView(this).apply {
                text = s
                textSize = 9f
                typeface = Typeface.DEFAULT_BOLD
                setPadding(px(12), px(6), px(12), px(6))
                setTextColor(Color.parseColor("#334455"))
                background = cyberBorder(colorBorder, 20f)
                letterSpacing = 0.1f
                layoutParams = LinearLayout.LayoutParams(WRAP, WRAP).apply {
                    if (i > 0) setMargins(px(6), 0, 0, 0)
                }
                tag = "step_$i"
            }
            stepBar.addView(chip)
        }
        updateStepBar(0)
        return stepBar
    }

    private fun buildStatusBanner(): View {
        val wrapper = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(px(16), px(12), px(16), 0)
        }
        statusBanner = CardView(this).apply {
            radius = px(14).toFloat()
            cardElevation = 0f
            setCardBackgroundColor(Color.parseColor("#040e1a"))
        }
        val inner = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(px(14), px(14), px(14), px(14))
            gravity = Gravity.CENTER_VERTICAL
        }
        tvStatusDot = TextView(this).apply {
            text = "●"
            textSize = 10f
            setTextColor(Color.GRAY)
            layoutParams = LinearLayout.LayoutParams(WRAP, WRAP).apply { setMargins(0, 0, px(10), 0) }
        }
        val textCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, WRAP, 1f)
        }
        tvStatusMsg = TextView(this).apply {
            // [SESSION v2.0] Initial text from SessionState.IDLE.displayString
            text = SessionState.IDLE.displayString
            textSize = 11f
            setTextColor(Color.GRAY)
            typeface = Typeface.DEFAULT_BOLD
            letterSpacing = 0.12f
        }
        tvStatusSub = TextView(this).apply {
            text = SessionState.IDLE.statusSub
            textSize = 9f
            setTextColor(Color.parseColor("#334455"))
            letterSpacing = 0.08f
        }
        textCol.addView(tvStatusMsg)
        textCol.addView(tvStatusSub)
        inner.addView(tvStatusDot)
        inner.addView(textCol)
        statusBanner.addView(inner)
        wrapper.addView(statusBanner)
        return wrapper
    }

    private fun buildPhotoIdentityRow(): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(px(16), px(14), px(16), 0)
        }

        photoFrame = CardView(this).apply {
            radius = px(16).toFloat()
            cardElevation = 0f
            setCardBackgroundColor(Color.parseColor("#040e1a"))
            layoutParams = LinearLayout.LayoutParams(px(130), px(170)).apply {
                setMargins(0, 0, px(14), 0)
            }
        }
        val photoInner = FrameLayout(this)
        photoView = ImageView(this).apply {
            layoutParams = FrameLayout.LayoutParams(MATCH, MATCH)
            scaleType = ImageView.ScaleType.CENTER_CROP
            visibility = View.GONE
        }
        tvPhotoLabel = TextView(this).apply {
            text = "👤\nPHOTO"
            textSize = 10f
            setTextColor(Color.parseColor("#334455"))
            gravity = Gravity.CENTER
            letterSpacing = 0.1f
            layoutParams = FrameLayout.LayoutParams(MATCH, MATCH, Gravity.CENTER)
        }
        photoInner.addView(photoView)
        photoInner.addView(tvPhotoLabel)
        photoFrame.addView(photoInner)

        cardIdentity = CardView(this).apply {
            radius = px(16).toFloat()
            cardElevation = 0f
            setCardBackgroundColor(colorCardBg)
            layoutParams = LinearLayout.LayoutParams(0, WRAP, 1f)
            visibility = View.INVISIBLE
        }
        val idInner = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(px(14), px(14), px(14), px(14))
        }

        fun idRow(label: String): Pair<TextView, TextView> {
            val lbl = TextView(this).apply {
                text = label
                textSize = 9f
                setTextColor(Color.parseColor("#445566"))
                letterSpacing = 0.1f
            }
            val `val` = TextView(this).apply {
                textSize = 12f
                setTextColor(colorCyan)
                typeface = Typeface.DEFAULT_BOLD
            }
            idInner.addView(lbl)
            idInner.addView(`val`)
            idInner.addView(spacer(8))
            return lbl to `val`
        }

        val (_, n)   = idRow("FULL NAME");    tvName = n
        val (_, d)   = idRow("DOCUMENT");     tvDocNum = d
        val (_, nat) = idRow("NATIONALITY");  tvNationality = nat
        val (_, sod) = idRow("SOD STATUS");   tvSodStatus = sod
        val (_, mod) = idRow("MODE");         tvMode = mod
        mod.textSize = 10f
        mod.setTextColor(Color.parseColor("#445566"))

        cardIdentity.addView(idInner)
        row.addView(photoFrame)
        row.addView(cardIdentity)
        return row
    }

    private fun buildProofBar(): View {
        val wrapper = LinearLayout(this).apply {
            setPadding(px(16), px(14), px(16), 0)
        }
        cardProof = CardView(this).apply {
            radius = px(14).toFloat()
            cardElevation = 0f
            setCardBackgroundColor(Color.parseColor("#041a0d"))
            visibility = View.GONE
        }
        val inner = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(px(14), px(12), px(14), px(12))
            gravity = Gravity.CENTER_VERTICAL
        }
        val icon = TextView(this).apply {
            text = "⚡"
            textSize = 20f
            layoutParams = LinearLayout.LayoutParams(WRAP, WRAP).apply { setMargins(0, 0, px(12), 0) }
        }
        val infoCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(0, WRAP, 1f)
        }
        val proofTitle = TextView(this).apply {
            text = "PLONKY2 ZK PROOF"
            textSize = 9f
            setTextColor(colorGreen)
            typeface = Typeface.DEFAULT_BOLD
            letterSpacing = 0.15f
        }
        tvProofHash = TextView(this).apply {
            text = "SHA256 · aarch64"
            textSize = 9f
            setTextColor(Color.parseColor("#224433"))
        }
        infoCol.addView(proofTitle)
        infoCol.addView(tvProofHash)

        val timeCol = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.END
        }
        tvProofTime = TextView(this).apply {
            text = "—"
            textSize = 16f
            setTextColor(colorGreen)
            typeface = Typeface.DEFAULT_BOLD
            gravity = Gravity.END
        }
        val generatedLbl = TextView(this).apply {
            text = "GENERATED"
            textSize = 8f
            setTextColor(Color.parseColor("#224433"))
            letterSpacing = 0.1f
            gravity = Gravity.END
        }
        timeCol.addView(tvProofTime)
        timeCol.addView(generatedLbl)

        inner.addView(icon)
        inner.addView(infoCol)
        inner.addView(timeCol)
        cardProof.addView(inner)
        wrapper.addView(cardProof)
        return wrapper
    }

    private fun buildSectionLabel(text: String): View {
        return TextView(this).apply {
            this.text = text
            textSize = 9f
            setTextColor(Color.parseColor("#445566"))
            setPadding(px(16), px(14), px(16), px(6))
            letterSpacing = 0.2f
            typeface = Typeface.DEFAULT_BOLD
        }
    }

    private fun buildResultCard(isIntegrity: Boolean): View {
        val wrapper = LinearLayout(this).apply {
            setPadding(px(16), 0, px(16), 0)
        }
        val card = CardView(this).apply {
            radius = px(16).toFloat()
            cardElevation = 0f
            setCardBackgroundColor(colorCardBg)
            visibility = View.GONE
        }
        val inner = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
        }

        val header = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(px(14), px(12), px(14), px(12))
            setBackgroundColor(Color.parseColor("#060e1c"))
            gravity = Gravity.CENTER_VERTICAL
        }
        val icon = TextView(this).apply {
            text = if (isIntegrity) "🦁" else "🔐"
            textSize = 16f
            layoutParams = LinearLayout.LayoutParams(WRAP, WRAP).apply { setMargins(0,0,px(10),0) }
        }
        val title = TextView(this).apply {
            text = if (isIntegrity) "PASSPORT ENGINE" else "CRYPTO ENGINE"
            textSize = 10f
            setTextColor(colorCyan)
            typeface = Typeface.DEFAULT_BOLD
            letterSpacing = 0.15f
            layoutParams = LinearLayout.LayoutParams(0, WRAP, 1f)
        }
        val badge = TextView(this).apply {
            text = if (isIntegrity) "VERIFIED" else "SIMULATED"
            textSize = 9f
            setPadding(px(8), px(4), px(8), px(4))
            setTextColor(if (isIntegrity) colorGreen else colorCyan)
            background = cyberBorder(
                if (isIntegrity) Color.parseColor("#003322") else Color.parseColor("#002233"),
                20f
            )
        }
        header.addView(icon); header.addView(title); header.addView(badge)

        val div = View(this).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH, 1)
            setBackgroundColor(colorBorder)
        }

        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(px(14), px(8), px(14), px(8))
        }
        val tv = TextView(this).apply {
            text = "—"
            textSize = 12f
            setTextColor(Color.parseColor("#445566"))
            lineHeight = (textSize * 2.2f).toInt()
        }
        body.addView(tv)

        inner.addView(header); inner.addView(div); inner.addView(body)
        card.addView(inner)
        wrapper.addView(card)

        if (isIntegrity) { cardIntegrity = card; tvIntegrityRows = tv }
        else             { cardCrypto    = card; tvCryptoRows    = tv }

        return wrapper
    }

    private fun buildButtons(): View {
        val col = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(px(16), px(14), px(16), 0)
        }

        btnScanMrz = Button(this).apply {
            text = "📷  SCAN MRZ"
            textSize = 12f
            typeface = Typeface.DEFAULT_BOLD
            letterSpacing = 0.2f
            setTextColor(Color.WHITE)
            background = gradientBg(Color.parseColor("#0055cc"), Color.parseColor("#00bcd4"), 16f)
            layoutParams = LinearLayout.LayoutParams(MATCH, px(52)).apply { setMargins(0,0,0,px(10)) }
            setPadding(0, 0, 0, 0)
            setOnClickListener {
                cameraLauncher.launch(Intent(this@PassportActivity, CameraActivity::class.java))
            }
        }

        btnSimulate = Button(this).apply {
            text = "🧪  SIMULATE SCAN"
            textSize = 11f
            typeface = Typeface.DEFAULT_BOLD
            letterSpacing = 0.15f
            setTextColor(colorCyan)
            background = cyberBorder(colorBorder, 16f)
            layoutParams = LinearLayout.LayoutParams(MATCH, px(48))
            setPadding(0, 0, 0, 0)
            setOnClickListener { runSimulation() }
        }

        col.addView(btnScanMrz)
        col.addView(btnSimulate)
        return col
    }

    // ── UI Helpers ────────────────────────────────────────────────────────────

    private fun updateStatus(msg: String, color: Int, sub: String = "") {
        tvStatusMsg.text = msg
        tvStatusMsg.setTextColor(color)
        tvStatusDot.setTextColor(color)
        tvStatusSub.text = sub
    }

    private fun updateStepBar(activeIndex: Int) {
        val steps = listOf("MRZ", "NFC", "READ", "SOD", "ZKP")
        for (i in steps.indices) {
            val chip = stepBar.findViewWithTag<TextView>("step_$i") ?: continue
            when {
                i < activeIndex  -> { chip.setTextColor(colorCyan);  chip.background = cyberBorder(colorBorder, 20f) }
                i == activeIndex -> { chip.setTextColor(colorGreen); chip.background = cyberBorder(Color.parseColor("#003322"), 20f) }
                else             -> { chip.setTextColor(Color.parseColor("#223344")); chip.background = cyberBorder(colorBorder, 20f) }
            }
        }
    }

    private fun resetResultUI() {
        cardIdentity.visibility  = View.INVISIBLE
        cardProof.visibility     = View.GONE
        cardIntegrity.visibility = View.GONE
        cardCrypto.visibility    = View.GONE
        photoView.setImageDrawable(null)
        photoView.visibility    = View.GONE
        tvPhotoLabel.visibility = View.VISIBLE
    }

    private fun animateFadeIn(v: View) {
        v.visibility = View.VISIBLE
        v.alpha = 0f
        v.animate().alpha(1f).setDuration(400).start()
    }

    private fun showToast(msg: String) =
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()

    // ── Drawing Helpers ───────────────────────────────────────────────────────

    private fun cyberBorder(color: Int, radius: Float): GradientDrawable =
        GradientDrawable().apply {
            shape = GradientDrawable.RECTANGLE
            cornerRadius = px(radius.toInt()).toFloat()
            setStroke(1, color)
            setColor(Color.TRANSPARENT)
        }

    private fun gradientBg(start: Int, end: Int, radiusDp: Float): GradientDrawable =
        GradientDrawable(GradientDrawable.Orientation.LEFT_RIGHT, intArrayOf(start, end)).apply {
            cornerRadius = px(radiusDp.toInt()).toFloat()
        }

    private fun spacer(dp: Int) = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(MATCH, px(dp))
    }

    private fun px(dp: Int) = (dp * resources.displayMetrics.density).toInt()

    private val MATCH = LinearLayout.LayoutParams.MATCH_PARENT
    private val WRAP  = LinearLayout.LayoutParams.WRAP_CONTENT

    // ── Haptics ───────────────────────────────────────────────────────────────

    private fun performHapticFeedback() {
        try {
            val v = getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                v.vibrate(VibrationEffect.createOneShot(200, VibrationEffect.DEFAULT_AMPLITUDE))
            else v.vibrate(200)
        } catch (_: Exception) {}
    }

    private fun performErrorVibration() {
        try {
            val v = getSystemService(Context.VIBRATOR_SERVICE) as Vibrator
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                v.vibrate(VibrationEffect.createWaveform(longArrayOf(0,100,100,100), -1))
            else v.vibrate(300)
        } catch (_: Exception) {}
    }
}