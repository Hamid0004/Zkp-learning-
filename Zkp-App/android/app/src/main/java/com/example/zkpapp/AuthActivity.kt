package com.example.zkpapp

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.CountDownTimer
import android.util.Base64
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
import com.example.zkpapp.security.BiometricManager
import com.example.zkpapp.security.KeyStoreManager
import com.example.zkpapp.ui.AuthScreen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Arrays

class AuthActivity : AppCompatActivity() {

    private val viewModel: AuthViewModel by viewModels()

    private lateinit var keyStoreManager: KeyStoreManager
    private lateinit var biometricManager: BiometricManager

    private val PREFS_NAME         = "secure_prefs"
    private val KEY_ENCRYPTED_DATA = "data"
    private val KEY_IV             = "iv"

    private var rateLimitTimer: CountDownTimer? = null

    // =========================================================
    // LIFECYCLE
    // =========================================================
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        biometricManager = BiometricManager(this)
        keyStoreManager  = KeyStoreManager()

        // ✅ Tamper detection — dialog before UI render
        runTamperCheck()

        // ✅ Biometric hardware check
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

        // ✅ StrongBox-aware key generation
        initKeyStore()

        // ✅ Compose UI — XML layout replace ho gaya
        setContent {
            val uiState by viewModel.uiState.collectAsState()
            AuthScreen(
                uiState        = uiState,
                isVaultExists  = viewModel.isVaultExists(this),
                onUnlockClick  = { onFingerprintTapped() },
                onCreateClick  = { onCreateTapped() },
                onRestoreClick = { showRestoreDialog() },
            )
        }

        viewModel.emitVaultState(this)

        // ✅ AUTO POPUP — WhatsApp style
        // Vault exists → seedha fingerprint popup kholna
        // User ko kuch tap nahi karna — bilkul WhatsApp jaisa
        if (viewModel.isVaultExists(this)) {
            val isFromGlobalLock = intent.getBooleanExtra("from_global_lock", false)
            window.decorView.postDelayed({
                triggerAutoUnlock(isFromGlobalLock)
            }, 350) // Compose render hone ka time
        }

        // ✅ Modern back press
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                val fromGlobalLock = intent.getBooleanExtra("from_global_lock", false)
                if (fromGlobalLock) {
                    // Global lock dismiss nahi hona chahiye
                    moveTaskToBack(true)
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                }
            }
        })
    }

    // ✅ onResume — minimize ke baad wapas aao to auto popup
    // Exactly WhatsApp fingerprint behavior
    override fun onResume() {
        super.onResume()

        val isFromGlobalLock = intent.getBooleanExtra("from_global_lock", false)
        if (isFromGlobalLock && viewModel.isVaultExists(this)) {
            if (!viewModel.isAuthInProgress.get()) {
                window.decorView.postDelayed({
                    triggerAutoUnlock(isFromGlobalLock = true)
                }, 200)
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        rateLimitTimer?.cancel()
    }

    // =========================================================
    // BUTTON / AUTO TRIGGER HANDLERS
    // =========================================================

    // Fingerprint icon tap — manual trigger
    private fun onFingerprintTapped() {
        if (viewModel.isAuthInProgress.get()) return
        checkRateLimitThen { unlockVault() }
    }

    // Create identity button tap
    private fun onCreateTapped() {
        if (viewModel.isAuthInProgress.get()) return
        checkRateLimitThen { createNewVault() }
    }

    // Auto trigger — onCreate aur onResume dono se
    private fun triggerAutoUnlock(isFromGlobalLock: Boolean) {
        if (viewModel.isAuthInProgress.get()) return
        checkRateLimitThen { unlockVault() }
    }

    // Rate limit check helper — DRY
    private fun checkRateLimitThen(action: () -> Unit) {
        when (val status = viewModel.checkRateLimit(this)) {
            is AuthViewModel.RateLimitStatus.Blocked -> startRateLimitCountdown(status.waitSeconds)
            else -> action()
        }
    }

    // =========================================================
    // RATE LIMIT COUNTDOWN — Compose state ke through update
    // =========================================================
    private fun startRateLimitCountdown(seconds: Int) {
        rateLimitTimer?.cancel()
        viewModel.emitRateLimited(seconds)

        rateLimitTimer = object : CountDownTimer(seconds * 1000L, 1000L) {
            override fun onTick(ms: Long) {
                viewModel.emitRateLimited(((ms / 1000) + 1).toInt())
            }
            override fun onFinish() {
                viewModel.resetState()
                viewModel.emitVaultState(this@AuthActivity)
            }
        }.start()
    }

    // =========================================================
    // TAMPER DETECTION — logic same
    // =========================================================
    private fun runTamperCheck() {
        when (val result = viewModel.runTamperChecks(this)) {
            is AuthViewModel.TamperResult.Compromised -> {
                val reasons = result.reasons.joinToString("\n• ", prefix = "• ")
                AlertDialog.Builder(this)
                    .setTitle("⚠️ Security Warning")
                    .setMessage(
                        "Suspicious environment detected:\n\n$reasons\n\n" +
                        "Using this app on a rooted/modified device puts your keys at risk."
                    )
                    .setPositiveButton("I understand, continue") { _, _ -> }
                    .setNegativeButton("Exit") { _, _ -> finish() }
                    .setCancelable(false)
                    .show()
            }
            is AuthViewModel.TamperResult.Clean -> { /* all good */ }
        }
    }

    // =========================================================
    // STRONGBOX KEY INIT — logic same
    // =========================================================
    private fun initKeyStore() {
        try {
            val useStrongBox = viewModel.isStrongBoxAvailable(this)
            keyStoreManager.generateMasterKey(useStrongBox = useStrongBox)
        } catch (e: Exception) {
            viewModel.emitError("Failed to initialize secure storage.\nReason: ${e.message ?: "Unknown"}")
        }
    }

    // =========================================================
    // VAULT CREATION — logic same
    // =========================================================
    private fun createNewVault() {
        viewModel.emitLoading()

        lifecycleScope.launch(Dispatchers.Default) {
            val mnemonic = viewModel.generateTrueBip39Mnemonic()
            withContext(Dispatchers.Main) {
                encryptAndSaveSeed(mnemonic, isRestore = false)
            }
        }
    }

    // =========================================================
    // UNLOCK VAULT — logic same
    // =========================================================
    private fun unlockVault() {
        if (!viewModel.isAuthInProgress.compareAndSet(false, true)) return

        try {
            val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

            val ivString = prefs.getString(KEY_IV, null)
            if (ivString.isNullOrEmpty()) {
                viewModel.isAuthInProgress.set(false)
                viewModel.emitError("Vault corrupted: IV missing.\nPlease recreate your identity.")
                return
            }

            val ivBytes = Base64.decode(ivString, Base64.DEFAULT)
            val cipher  = keyStoreManager.getCipherForDecryption(ivBytes)

            biometricManager.authenticateUser(this, BiometricPrompt.CryptoObject(cipher),
                onSuccess = { result ->
                    lifecycleScope.launch(Dispatchers.Default) {
                        var decryptedBytes: ByteArray? = null
                        try {
                            val unlockedCipher = result.cryptoObject?.cipher
                                ?: throw IllegalStateException("Cipher unavailable after auth")

                            val encData = prefs.getString(KEY_ENCRYPTED_DATA, null)
                                ?: throw IllegalStateException("Encrypted seed missing")

                            decryptedBytes = unlockedCipher.doFinal(Base64.decode(encData, Base64.DEFAULT))

                            if (decryptedBytes.isEmpty()) throw IllegalStateException("Decrypted data is empty")

                            // ✅ ByteArray directly to JNI — String RAM mein nahi banta
                            val proofBytes  = SecureVaultJni.generateSecureIdentityProof(decryptedBytes)
                            val proofResult = String(proofBytes, Charsets.UTF_8)

                            viewModel.resetFailedAttempts(this@AuthActivity)

                            val isFromGlobalLock = intent.getBooleanExtra("from_global_lock", false)

                            withContext(Dispatchers.Main) {
                                if (isFromGlobalLock) {
                                    ZkpApplication.isAppLocked.set(false)
                                    viewModel.emitSuccess(proofResult, isGlobalUnlock = true)
                                    finish()
                                } else {
                                    viewModel.emitSuccess(proofResult, isGlobalUnlock = false)
                                    val intent = Intent(this@AuthActivity, MainActivity::class.java)
                                    intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                                    startActivity(intent)
                                    finish()
                                }
                            }

                        } catch (e: Exception) {
                            viewModel.recordFailedAttempt(this@AuthActivity)
                            viewModel.emitError("Decryption failed.\nReason: ${e.message}")
                        } finally {
                            // 🔥 Zero sensitive bytes from RAM
                            decryptedBytes?.let { Arrays.fill(it, 0.toByte()) }
                            viewModel.isAuthInProgress.set(false)
                        }
                    }
                },
                onError = { errMsg ->
                    viewModel.isAuthInProgress.set(false)
                    viewModel.recordFailedAttempt(this@AuthActivity)
                    viewModel.emitError("Biometric failed.\nReason: $errMsg")
                }
            )
        } catch (e: Exception) {
            viewModel.isAuthInProgress.set(false)
            viewModel.emitError("Unexpected unlock error.\nReason: ${e.message}")
        }
    }

    // =========================================================
    // ENCRYPT AND SAVE SEED — logic same
    // =========================================================
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
                            val encryptedBytes = unlockedCipher.doFinal(seedBytes)
                            val ivBytes        = unlockedCipher.iv

                            val saved = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                                .edit()
                                .putString(KEY_ENCRYPTED_DATA, Base64.encodeToString(encryptedBytes, Base64.DEFAULT))
                                .putString(KEY_IV, Base64.encodeToString(ivBytes, Base64.DEFAULT))
                                .commit()

                            if (!saved) throw IllegalStateException("Storage write failed")

                            viewModel.resetFailedAttempts(this@AuthActivity)

                            withContext(Dispatchers.Main) {
                                if (!isRestore) {
                                    AlertDialog.Builder(this@AuthActivity)
                                        .setTitle("🚨 SECRET RECOVERY PHRASE")
                                        .setMessage(
                                            "Write these 12 words down safely.\n" +
                                            "They CANNOT be recovered if lost!\n\n$seed"
                                        )
                                        .setPositiveButton("I WROTE IT DOWN") { _, _ -> recreate() }
                                        .setCancelable(false)
                                        .show()
                                } else {
                                    Toast.makeText(this@AuthActivity, "✅ Identity Restored!", Toast.LENGTH_LONG).show()
                                    recreate()
                                }
                            }
                        } catch (e: Exception) {
                            viewModel.emitError("Encryption failed.\nReason: ${e.message}")
                        } finally {
                            // 🔥 Wipe seed bytes from RAM
                            seedBytes?.let { Arrays.fill(it, 0.toByte()) }
                            viewModel.isAuthInProgress.set(false)
                        }
                    }
                },
                onError = { errMsg ->
                    viewModel.isAuthInProgress.set(false)
                    viewModel.emitError("Biometric failed.\nReason: $errMsg")
                }
            )
        } catch (e: Exception) {
            viewModel.isAuthInProgress.set(false)
            viewModel.emitError("Encryption setup failed.\nReason: ${e.message}")
        }
    }

    // =========================================================
    // RESTORE DIALOG — logic same
    // =========================================================
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
                val words     = typedSeed.split("\\s+".toRegex())

                when {
                    words.size != 12 -> {
                        viewModel.emitError("Got ${words.size} words — need exactly 12.")
                    }
                    words.any { it !in viewModel.bip39WordSet } -> {
                        val bad = words.filter { it !in viewModel.bip39WordSet }
                        viewModel.emitError("Invalid BIP39 words: ${bad.joinToString(", ")}")
                    }
                    !viewModel.validateBip39Checksum(typedSeed) -> {
                        viewModel.emitError("Invalid mnemonic: checksum mismatch.\nDouble-check your words.")
                    }
                    else -> {
                        encryptAndSaveSeed(typedSeed, isRestore = true)
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
}