package com.example.zkpapp

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.CountDownTimer
import android.util.Base64
import android.util.Log
import android.widget.EditText
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.lifecycle.lifecycleScope
import com.example.zkpapp.security.ZkBiometricManager
import com.example.zkpapp.security.KeyStoreManager
import com.example.zkpapp.ui.AuthScreen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.util.Arrays

/**
 * AuthActivity v2.0 — ZKAuth Deep Link + Passkey Model
 *
 * ═══════════════════════════════════════════════════════════════
 * v1.0 → v2.0 Upgrades:
 *
 * 🔴 [NEW] Deep Link Handler — handleZkAuthIntent()
 *    Receives: zkauth://auth?domain=X&claim=Y&challenge=Z&callback=W
 *    Parses + validates all 4 params. Routes to ZK proof flow.
 *
 * 🔴 [NEW] ZK Proof Flow — startZkProofFlow() — 3 paths:
 *    PATH A: hasIdentity() + isSessionValid() → proof immediately
 *    PATH B: hasPersistentIdentity() + session expired → biometric
 *            → loadFromDisk() → extendSession() → proof
 *    PATH C: no identity → redirect to PassportActivity
 *
 * 🔴 [NEW] Biometric subtitle = claim label
 *    "Age 18+ verify karne ke liye" shown on fingerprint dialog.
 *    User knows exactly what is being proven.
 *
 * 🔴 [NEW] generateAndSubmitProof() — full ZK pipeline
 *    proof cache check → buildPassportJson → SecurityGate.generateClaimProof
 *    → buildZkAuthPayload → ECDSA sign → HTTP POST → finish()
 *
 * 🟡 [NEW] isDeepLinkIntent() — routes ZKAuth vs vault unlock
 * 🟡 Existing vault unlock / create / restore — unchanged, preserved.
 * ═══════════════════════════════════════════════════════════════
 */
class AuthActivity : AppCompatActivity() {

    private val viewModel: AuthViewModel by viewModels()

    private lateinit var keyStoreManager:  KeyStoreManager
    private lateinit var biometricManager: ZkBiometricManager

    // Vault prefs (existing)
    private val PREFS_NAME         = "secure_prefs"
    private val KEY_ENCRYPTED_DATA = "data"
    private val KEY_IV             = "iv"

    private var rateLimitTimer: CountDownTimer? = null

    // ── Deep link params ─────────────────────────────────────────
    private var zkDomain:    String? = null
    private var zkClaim:     String? = null
    private var zkChallenge: String? = null
    private var zkCallback:  String? = null
    private var zkTier:      Int     = TIER_PASSPORT  // default = Tier 1

    companion object {
        private const val TAG = "AuthActivity"
        private val VALID_CLAIMS = setOf("is_adult", "nationality", "is_human")
        private val VALID_TIERS  = setOf(1, 3)   // 2 = coming soon
        const val TIER_PASSPORT  = 1
        const val TIER_DEVICE    = 3
    }

    // =========================================================
    // LIFECYCLE
    // =========================================================
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        biometricManager = ZkBiometricManager(this)
        keyStoreManager  = KeyStoreManager()

        runTamperCheck()

        if (!biometricManager.canAuthenticate()) {
            setContent {
                val uiState by viewModel.uiState.collectAsState()
                AuthScreen(
                    uiState        = uiState,
                    isVaultExists  = false,
                    onUnlockClick  = {},
                    onCreateClick  = {},
                    onRestoreClick = {},
                )
            }
            viewModel.emitError("Biometric hardware not available.\nPlease enroll a fingerprint in device settings.")
            return
        }

        initKeyStore()

        // ── Route: ZKAuth deep link vs normal vault unlock ───────
        if (isDeepLinkIntent(intent)) {
            setContent {
                val uiState by viewModel.uiState.collectAsState()
                AuthScreen(
                    uiState        = uiState,
                    isVaultExists  = viewModel.isVaultExists(this),
                    onUnlockClick  = {},
                    onCreateClick  = {},
                    onRestoreClick = {},
                )
            }
            handleZkAuthIntent(intent)
        } else {
            // Normal vault unlock flow (existing)
            setContent {
                val uiState by viewModel.uiState.collectAsState()
                AuthScreen(
                    uiState         = uiState,
                    isVaultExists   = viewModel.isVaultExists(this),
                    onUnlockClick   = { onFingerprintTapped() },
                    onCreateClick   = { onCreateTapped() },
                    onRestoreClick  = { showRestoreDialog() },
                    onExitApp       = {
                        finishAffinity()
                        System.exit(0)
                    }
                )
            }

            if (viewModel.uiState.value !is AuthUiState.TamperDetected) {
                viewModel.emitVaultState(this)
            }

            if (viewModel.isVaultExists(this) &&
                viewModel.uiState.value !is AuthUiState.TamperDetected) {
                val isFromGlobalLock = intent.getBooleanExtra("from_global_lock", false)
                window.decorView.postDelayed({ triggerAutoUnlock(isFromGlobalLock) }, 350)
            }
        }

        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                val fromGlobalLock = intent.getBooleanExtra("from_global_lock", false)
                if (fromGlobalLock) moveTaskToBack(true)
                else { isEnabled = false; onBackPressedDispatcher.onBackPressed() }
            }
        })
    }

    override fun onResume() {
        super.onResume()
        val isFromGlobalLock = intent.getBooleanExtra("from_global_lock", false)
        if (isFromGlobalLock && viewModel.isVaultExists(this) &&
            viewModel.uiState.value !is AuthUiState.TamperDetected) {
            if (!viewModel.isAuthInProgress.get()) {
                window.decorView.postDelayed({ triggerAutoUnlock(true) }, 200)
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        rateLimitTimer?.cancel()
    }

    // =========================================================
    // [NEW v2.0] DEEP LINK DETECTION
    // =========================================================

    /** zkauth://auth?... → true. Normal launch → false. */
    private fun isDeepLinkIntent(intent: Intent): Boolean {
        val uri = intent.data ?: return false
        return uri.scheme == "zkauth" && uri.host == "auth"
    }

    // =========================================================
    // [NEW v2.0] DEEP LINK HANDLER
    // =========================================================

    /**
     * Parses and validates zkauth:// intent params, then routes to ZK flow.
     *
     * Required params:
     *   domain    — website requesting proof (e.g. "discord.com")
     *   claim     — "is_adult" | "nationality" | "is_human"
     *   challenge — anti-replay nonce (min 32 hex chars)
     *   callback  — HTTPS POST URL for proof submission
     */
    private fun handleZkAuthIntent(intent: Intent) {
        val uri = intent.data ?: run { showZkError("Invalid login request.\nPlease try again from the website."); return }
        Log.i(TAG, "🔗 ZKAuth deep link: $uri")

        val domain    = uri.getQueryParameter("domain")?.trim()?.lowercase()
        val claim     = uri.getQueryParameter("claim")?.trim()?.lowercase()
        val challenge = uri.getQueryParameter("challenge")?.trim()
        val callback  = uri.getQueryParameter("callback")?.trim()
        val session   = uri.getQueryParameter("session")?.trim() ?: ""

        if (domain.isNullOrEmpty()) { showZkError("Invalid login request.\nPlease try again from the website."); return }
        if (claim.isNullOrEmpty() || claim !in VALID_CLAIMS) {
            showZkError("This website sent an unsupported request.\nPlease contact the website.")
            return
        }
        if (challenge.isNullOrEmpty() || challenge.length < 32) {
            showZkError("Invalid login request.\nPlease try again from the website."); return
        }
        // Allow https always; also allow http for localhost + railway dev environments
        val isSecureCallback = callback != null && (
            callback.startsWith("https://") ||
            callback.startsWith("http://localhost") ||
            callback.startsWith("http://127.0.0.1") ||
            callback.contains(".railway.app") ||
            callback.contains(".up.railway.app")
        )
        if (callback.isNullOrEmpty() || !isSecureCallback) {
            showZkError("Insecure login request rejected.\nWebsite must use HTTPS."); return
        }

        // ── Parse tier (optional param — default 1) ──────────────
        val tierParam = uri.getQueryParameter("tier")?.trim()?.toIntOrNull() ?: TIER_PASSPORT
        zkTier = if (tierParam in VALID_TIERS) tierParam else TIER_PASSPORT

        zkDomain    = domain
        zkClaim     = claim
        zkChallenge = challenge
        zkCallback  = callback

        Log.i(TAG, "✅ Params valid | domain=$domain | claim=$claim | tier=$zkTier")

        // ── Route by tier ─────────────────────────────────────────
        when (zkTier) {
            TIER_DEVICE -> {
                // Tier 3 — Device + Biometric
                // No passport needed — go straight to DeviceTierActivity
                Log.i(TAG, "📱 Routing to DeviceTierActivity (Tier 3)")
                val i = Intent(this, DeviceTierActivity::class.java).apply {
                    putExtra("domain",    domain)
                    putExtra("challenge", challenge)
                    putExtra("callback",  callback)
                    putExtra("session",   session)
                }
                startActivity(i)
                finish()
            }
            else -> {
                // Tier 1 — Passport (default)
                // Scope nullifier to requesting domain
                IdentityStorage.setVerifierDomain(domain)
                startZkProofFlow()
            }
        }
    }

    // =========================================================
    // [NEW v2.0] ZK PROOF FLOW — 3 PATHS
    // =========================================================

    private fun startZkProofFlow() {
        // Hard block — simulation data cannot satisfy website proof request
        // Only real NFC passport (dg1 length >= 180 hex chars) allowed
        if (IdentityStorage.hasIdentity() && !IdentityStorage.hasRealPassport()) {
            Log.e(TAG, "❌ Simulation identity rejected for external claim")
            showZkError("Real passport required.\nPlease scan your passport via NFC.")
            window.decorView.postDelayed({
                startActivity(Intent(this, PassportActivity::class.java))
                finish()
            }, 2000)
            return
        }

        when {
            // PATH A — session alive, identity in RAM → no biometric needed
            IdentityStorage.hasIdentity() && IdentityStorage.isSessionValid() -> {
                Log.i(TAG, "⚡ PATH A: session valid → proof directly")
                viewModel.emitLoading()
                lifecycleScope.launch(Dispatchers.Default) { generateAndSubmitProof() }
            }

            // PATH B — persistent identity on disk, session expired / cold start
            IdentityStorage.hasPersistentIdentity(this) -> {
                Log.i(TAG, "🔐 PATH B: disk identity found → biometric")
                requestBiometricForDiskRestore()
            }

            // PATH C — never registered passport
            else -> {
                Log.w(TAG, "📵 PATH C: no identity → PassportActivity")
                showZkError("No passport registered.\nPlease scan your passport first.")
                window.decorView.postDelayed({
                    startActivity(Intent(this, PassportActivity::class.java))
                    finish()
                }, 2000)
            }
        }
    }

    // =========================================================
    // [NEW v2.0] BIOMETRIC FOR DISK RESTORE (PATH B)
    // =========================================================

    private fun requestBiometricForDiskRestore() {
        if (!viewModel.isAuthInProgress.compareAndSet(false, true)) return

        try {
            val iv = IdentityStorage.getEncryptedDg1Iv(this) ?: run {
                viewModel.isAuthInProgress.set(false)
                showZkError("Passport data not found.\nPlease scan your passport again to continue.")
                return
            }

            val cipher    = keyStoreManager.getCipherForDecryption(iv)
            val cryptoObj = BiometricPrompt.CryptoObject(cipher)

            biometricManager.authenticateUser(
                activity     = this,
                cryptoObject = cryptoObj,
                onSuccess    = { result ->
                    val unlockedCipher = result.cryptoObject?.cipher ?: run {
                        viewModel.isAuthInProgress.set(false)
                        viewModel.emitError("Authentication error.\nPlease try again.")
                        return@authenticateUser
                    }
                    lifecycleScope.launch(Dispatchers.Default) {
                        val restored = IdentityStorage.loadFromDisk(this@AuthActivity, unlockedCipher)
                        if (!restored) {
                            viewModel.isAuthInProgress.set(false)
                            withContext(Dispatchers.Main) {
                                showZkError("Could not load your passport data.\nPlease scan your passport again.")
                            }
                            return@launch
                        }
                        IdentityStorage.extendSession()
                        Log.i(TAG, "✅ Identity restored — generating proof")
                        generateAndSubmitProof()
                        viewModel.isAuthInProgress.set(false)
                    }
                },
                onError = { errMsg ->
                    viewModel.isAuthInProgress.set(false)
                    viewModel.recordFailedAttempt(this)
                    showZkError("Fingerprint not recognized.\nPlease try again.")
                }
            )
        } catch (e: Exception) {
            viewModel.isAuthInProgress.set(false)
            showZkError("Could not start fingerprint authentication.\nPlease try again.")
        }
    }

    // =========================================================
    // [NEW v2.0] ZK PROOF GENERATION + SUBMISSION
    // =========================================================

    /**
     * Full ZK pipeline — call from Dispatchers.Default.
     *
     * 1. Proof cache check (5 min TTL)
     * 2. buildPassportJson() → domain-scoped JSON
     * 3. SecurityGate.generateClaimProof() → Plonky2 proof
     * 4. Cache proof result
     * 5. buildZkAuthPayload() + ECDSA sign
     * 6. HTTP POST → callback URL
     * 7. Toast + finish()
     */
    private suspend fun generateAndSubmitProof() {
        val domain    = zkDomain    ?: return
        val claim     = zkClaim     ?: return
        val challenge = zkChallenge ?: return
        val callback  = zkCallback  ?: return

        try {
            withContext(Dispatchers.Main) { viewModel.emitLoading() }

            // Step 1: proof cache
            val cached = IdentityStorage.getCachedProof()
            val proofJson: String

            if (cached != null) {
                Log.i(TAG, "⚡ Using cached proof")
                proofJson = cached
            } else {
                // Step 2: build JSON for Rust
                val passportJson = IdentityStorage.buildPassportJson(
                    claimType = claim,
                    domain    = domain,
                    context   = this@AuthActivity
                ) ?: run {
                    withContext(Dispatchers.Main) {
                        showZkError("Passport data unavailable.\nPlease scan your passport again.")
                    }
                    return
                }

                // Step 3: Plonky2 ZK proof
                Log.i(TAG, "🔐 Generating proof | claim=$claim | domain=$domain")
                val t        = System.currentTimeMillis()
                val proofResult = SecurityGate.generateClaim(claimType = claim, domain = domain, context = this@AuthActivity)
                val rawProof = when (proofResult) {
                    is SecurityGate.ProofResult.Success -> proofResult.result.zkOutput?.compressedProof
                    is SecurityGate.ProofResult.Failure -> null
                }
                    ?: run {
                        withContext(Dispatchers.Main) {
                            showZkError("Verification failed.\nPlease try again or rescan your passport.")
                        }
                        return
                    }
                Log.i(TAG, "✅ Proof in ${System.currentTimeMillis() - t}ms")

                // Step 4: cache
                IdentityStorage.cacheProofResult(rawProof, IdentityStorage.getIdentityVersion())
                proofJson = rawProof
            }

            // Step 5: sign payload
            val payload = buildZkAuthPayload(proofJson, domain, claim, challenge)

            // Step 6: submit
            Log.i(TAG, "📤 Posting to: $callback")
            val ok = postProofToCallback(callback, payload)

            // Step 7: result
            withContext(Dispatchers.Main) {
                if (ok) {
                    Toast.makeText(
                        this@AuthActivity,
                        "✅ ${claimToDisplayLabel(claim)}\n$domain",
                        Toast.LENGTH_LONG
                    ).show()
                    finish()
                } else {
                    showZkError("Could not connect to $domain.\nCheck your internet and try again.")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ generateAndSubmitProof: ${e.message}")
            withContext(Dispatchers.Main) { showZkError("Verification failed.\nPlease try again or rescan your passport.") }
        }
    }

    // =========================================================
    // [NEW v2.0] PAYLOAD BUILDER + SIGNER
    // =========================================================

    private fun buildZkAuthPayload(
        proofJson: String,
        domain:    String,
        claim:     String,
        challenge: String
    ): String {
        return try {
            val obj        = JSONObject(proofJson)
            val nullifier  = obj.optString("nullifier",         "")
            val hwBinding  = obj.optString("hw_binding",        "")
            val validUntil = obj.optLong  ("valid_until",       0L)
            val compProof  = obj.optString("compressed_proof",  "")

            val sigInput = "$challenge|$domain|$nullifier|$claim"
            val devSig   = signWithDeviceKey(sigInput)

            JSONObject().apply {
                put("version",          "2.0")
                put("domain",           domain)
                put("claim_type",       claim)
                put("challenge",        challenge)
                put("nullifier",        nullifier)
                put("hw_binding",       hwBinding)
                put("valid_until",      validUntil)
                put("compressed_proof", compProof)
                put("device_sig",       devSig)
                put("timestamp",        System.currentTimeMillis())
            }.toString()
        } catch (e: Exception) {
            Log.e(TAG, "❌ buildZkAuthPayload: ${e.message}")
            "{\"error\":\"payload_build_failed\"}"
        }
    }

    /** Signs data with ECDSA P-256 key from AndroidKeyStore. */
    private fun signWithDeviceKey(data: String): String {
        return try {
            val ks  = java.security.KeyStore.getInstance("AndroidKeyStore").also { it.load(null) }
            val key = ks.getKey("ZKAuthDeviceKey_v1", null) as java.security.PrivateKey
            val sig = java.security.Signature.getInstance("SHA256withECDSA")
            sig.initSign(key)
            sig.update(data.toByteArray(Charsets.UTF_8))
            Base64.encodeToString(sig.sign(), Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "❌ Device signing: ${e.message}")
            "sig_unavailable"
        }
    }

    private suspend fun postProofToCallback(url: String, payload: String): Boolean =
        withContext(Dispatchers.IO) {
            try {
                val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
                conn.requestMethod = "POST"
                conn.doOutput      = true
                conn.connectTimeout = 10_000
                conn.readTimeout    = 15_000
                conn.setRequestProperty("Content-Type",    "application/json")
                conn.setRequestProperty("X-ZKAuth-Version","2.0")
                conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
                val code = conn.responseCode
                Log.i(TAG, "📨 Callback HTTP $code")
                code in 200..299
            } catch (e: Exception) {
                Log.e(TAG, "❌ HTTP POST: ${e.message}")
                false
            }
        }

    // =========================================================
    // [NEW v2.0] HELPERS
    // =========================================================

    private fun claimToDisplayLabel(claim: String): String = when (claim) {
        "is_adult"    -> "Age 18+ verify karne ke liye"
        "nationality" -> "Nationality verify karne ke liye"
        "is_human"    -> "Passport identity verify karne ke liye"
        else          -> "ZK proof generate karne ke liye"
    }

    private fun showZkError(msg: String) {
        runOnUiThread {
            viewModel.emitError(msg)
            Toast.makeText(this, "❌ $msg", Toast.LENGTH_LONG).show()
        }
    }

    // =========================================================
    // EXISTING — VAULT UNLOCK / CREATE / RESTORE (unchanged)
    // =========================================================

    private fun onFingerprintTapped() {
        if (viewModel.isAuthInProgress.get()) return
        checkRateLimitThen { unlockVault() }
    }

    private fun onCreateTapped() {
        if (viewModel.isAuthInProgress.get()) return
        checkRateLimitThen { createNewVault() }
    }

    private fun triggerAutoUnlock(isFromGlobalLock: Boolean) {
        if (viewModel.isAuthInProgress.get()) return
        checkRateLimitThen { unlockVault() }
    }

    private fun checkRateLimitThen(action: () -> Unit) {
        when (val status = viewModel.checkRateLimit(this)) {
            is AuthViewModel.RateLimitStatus.Blocked -> startRateLimitCountdown(status.waitSeconds)
            else -> action()
        }
    }

    private fun startRateLimitCountdown(seconds: Int) {
        rateLimitTimer?.cancel()
        viewModel.emitRateLimited(seconds)
        rateLimitTimer = object : CountDownTimer(seconds * 1000L, 1000L) {
            override fun onTick(ms: Long) { viewModel.emitRateLimited(((ms / 1000) + 1).toInt()) }
            override fun onFinish() { viewModel.resetState(); viewModel.emitVaultState(this@AuthActivity) }
        }.start()
    }

    private fun runTamperCheck() {
        when (viewModel.runTamperChecks(this)) {
            is AuthViewModel.TamperResult.Compromised -> viewModel.emitTamperDetected()
            is AuthViewModel.TamperResult.Clean       -> { /* ok */ }
        }
    }

    private fun initKeyStore() {
        try {
            keyStoreManager.generateMasterKey(useStrongBox = viewModel.isStrongBoxAvailable(this))
        } catch (e: Exception) {
            viewModel.emitError("Could not set up secure storage.\nPlease restart the app.")
        }
    }

    private fun createNewVault() {
        viewModel.emitLoading()
        lifecycleScope.launch(Dispatchers.Default) {
            val mnemonic = viewModel.generateTrueBip39Mnemonic()
            withContext(Dispatchers.Main) { encryptAndSaveSeed(mnemonic, isRestore = false) }
        }
    }

    private fun unlockVault() {
        if (!viewModel.isAuthInProgress.compareAndSet(false, true)) return
        try {
            val prefs    = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val ivString = prefs.getString(KEY_IV, null)
            if (ivString.isNullOrEmpty()) {
                viewModel.isAuthInProgress.set(false)
                viewModel.emitError("Passport data not found.\nPlease scan your passport again to continue.")
                return
            }
            val cipher = keyStoreManager.getCipherForDecryption(Base64.decode(ivString, Base64.DEFAULT))

            biometricManager.authenticateUser(this, BiometricPrompt.CryptoObject(cipher),
                onSuccess = { result ->
                    lifecycleScope.launch(Dispatchers.Default) {
                        var decryptedBytes: ByteArray? = null
                        try {
                            val unlockedCipher = result.cryptoObject?.cipher
                                ?: throw IllegalStateException("Cipher unavailable")
                            val encData = prefs.getString(KEY_ENCRYPTED_DATA, null)
                                ?: throw IllegalStateException("Encrypted seed missing")
                            decryptedBytes = unlockedCipher.doFinal(Base64.decode(encData, Base64.DEFAULT))
                            if (decryptedBytes.isEmpty()) throw IllegalStateException("Decrypted data empty")
                            val proofResult = String(SecureVaultJni.generateSecureIdentityProof(decryptedBytes), Charsets.UTF_8)
                            viewModel.resetFailedAttempts(this@AuthActivity)
                            withContext(Dispatchers.Main) {
                                ZkpApplication.isAppLocked.set(false)
                                val isFromGlobalLock = intent.getBooleanExtra("from_global_lock", false)
                                if (isFromGlobalLock && !isTaskRoot) {
                                    viewModel.emitSuccess(proofResult, isGlobalUnlock = true)
                                    finish(); overridePendingTransition(0, 0)
                                } else {
                                    viewModel.emitSuccess(proofResult, isGlobalUnlock = false)
                                    startActivity(Intent(this@AuthActivity, MainActivity::class.java).apply {
                                        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                                    })
                                    overridePendingTransition(0, 0); finish()
                                }
                            }
                        } catch (e: Exception) {
                            viewModel.recordFailedAttempt(this@AuthActivity)
                            viewModel.emitError("Could not unlock your vault.\nPlease try again.")
                        } finally {
                            decryptedBytes?.let { Arrays.fill(it, 0.toByte()) }
                            viewModel.isAuthInProgress.set(false)
                        }
                    }
                },
                onError = { errMsg ->
                    viewModel.isAuthInProgress.set(false)
                    viewModel.recordFailedAttempt(this)
                    viewModel.emitError("Fingerprint not recognized.\nPlease try again.")
                }
            )
        } catch (e: KeyStoreManager.KeyInvalidatedException) {
            viewModel.isAuthInProgress.set(false)
            keyStoreManager.deleteKey()
            viewModel.emitError("New fingerprint detected.\nFor your security, please set up your vault again.")
        } catch (e: Exception) {
            viewModel.isAuthInProgress.set(false)
            viewModel.emitError("Something went wrong.\nPlease restart the app and try again.")
        }
    }

    private fun encryptAndSaveSeed(seed: String, isRestore: Boolean) {
        if (!viewModel.isAuthInProgress.compareAndSet(false, true)) return
        try {
            val cipher = keyStoreManager.getCipherForEncryption()
            biometricManager.authenticateUser(this, BiometricPrompt.CryptoObject(cipher),
                onSuccess = { result ->
                    lifecycleScope.launch(Dispatchers.Default) {
                        var seedBytes: ByteArray? = null
                        try {
                            val unlockedCipher = result.cryptoObject?.cipher
                                ?: throw IllegalStateException("Cipher unavailable")
                            seedBytes = seed.toByteArray(Charsets.UTF_8)
                            val encBytes = unlockedCipher.doFinal(seedBytes)
                            val saved = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
                                .putString(KEY_ENCRYPTED_DATA, Base64.encodeToString(encBytes, Base64.DEFAULT))
                                .putString(KEY_IV, Base64.encodeToString(unlockedCipher.iv, Base64.DEFAULT))
                                .commit()
                            if (!saved) throw IllegalStateException("Storage write failed")
                            viewModel.resetFailedAttempts(this@AuthActivity)
                            withContext(Dispatchers.Main) {
                                if (!isRestore) {
                                    AlertDialog.Builder(this@AuthActivity)
                                        .setTitle("🚨 SECRET RECOVERY PHRASE")
                                        .setMessage("Write these 12 words down safely.\nThey CANNOT be recovered if lost!\n\n$seed")
                                        .setPositiveButton("I WROTE IT DOWN") { _, _ -> recreate() }
                                        .setCancelable(false).show()
                                } else {
                                    Toast.makeText(this@AuthActivity, "✅ Identity Restored!", Toast.LENGTH_LONG).show()
                                    recreate()
                                }
                            }
                        } catch (e: Exception) {
                            viewModel.emitError("Could not save your vault.\nPlease try again.")
                        } finally {
                            seedBytes?.let { Arrays.fill(it, 0.toByte()) }
                            viewModel.isAuthInProgress.set(false)
                        }
                    }
                },
                onError = { errMsg ->
                    viewModel.isAuthInProgress.set(false)
                    viewModel.emitError("Fingerprint not recognized.\nPlease try again.")
                }
            )
        } catch (e: KeyStoreManager.KeyInvalidatedException) {
            viewModel.isAuthInProgress.set(false)
            keyStoreManager.deleteKey()
            viewModel.emitError("New fingerprint detected.\nFor your security, please set up your vault again.")
        } catch (e: Exception) {
            viewModel.isAuthInProgress.set(false)
            viewModel.emitError("Could not set up secure storage.\nPlease restart the app.")
        }
    }

    private fun showRestoreDialog() {
        val input = EditText(this).apply {
            hint = "Enter your 12 BIP39 words separated by spaces"
            setPadding(32, 24, 32, 24)
        }
        AlertDialog.Builder(this)
            .setTitle("Restore Identity")
            .setMessage("Enter your 12-word BIP39 recovery phrase:")
            .setView(input)
            .setPositiveButton("Restore") { _, _ ->
                val typedSeed = input.text.toString().trim().lowercase()
                val words = typedSeed.split("\\s+".toRegex())
                when {
                    words.size != 12 ->
                        viewModel.emitError("Got ${words.size} words — need exactly 12.")
                    words.any { it !in viewModel.bip39WordSet } ->
                        viewModel.emitError("Invalid BIP39 words: ${words.filter { it !in viewModel.bip39WordSet }.joinToString()}")
                    !viewModel.validateBip39Checksum(typedSeed) ->
                        viewModel.emitError("Invalid mnemonic: checksum mismatch.")
                    else -> encryptAndSaveSeed(typedSeed, isRestore = true)
                }
            }
            .setNegativeButton("Cancel", null).show()
    }
}