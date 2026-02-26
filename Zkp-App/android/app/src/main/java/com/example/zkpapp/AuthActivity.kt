package com.example.zkpapp

import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.CountDownTimer
import android.util.Base64
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.OnBackPressedCallback
import androidx.activity.viewModels
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.example.zkpapp.security.BiometricManager
import com.example.zkpapp.security.KeyStoreManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Arrays

class AuthActivity : AppCompatActivity() {

    // ✅ Auth state lives in ViewModel — survives rotation, process death
    private val viewModel: AuthViewModel by viewModels()

    private lateinit var keyStoreManager: KeyStoreManager
    private lateinit var biometricManager: BiometricManager

    private val PREFS_NAME         = "secure_prefs"
    private val KEY_ENCRYPTED_DATA = "data"
    private val KEY_IV             = "iv"

    private lateinit var btnLogin: Button
    private lateinit var btnRestore: Button
    private lateinit var tvStatus: TextView

    private var rateLimitTimer: CountDownTimer? = null

    // =========================================================
    // LIFECYCLE
    // =========================================================
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_auth)

        btnLogin   = findViewById(R.id.btnLogin)
        btnRestore = findViewById(R.id.btnRestore)
        tvStatus   = findViewById(R.id.tvStatus)

        biometricManager = BiometricManager(this)
        keyStoreManager  = KeyStoreManager()

        // ✅ UPGRADE: Observe ViewModel state (StateFlow)
        observeViewModel()

        // ✅ UPGRADE 7: Tamper detection on startup
        runTamperCheck()

        // ✅ Biometric hardware check
        if (!biometricManager.canAuthenticate()) {
            showError("Biometric hardware not available.\nPlease enroll a fingerprint in device settings.")
            disableButtons()
            return
        }

        // ✅ UPGRADE 5: StrongBox-aware key generation
        initKeyStore()

        viewModel.emitVaultState(this)

        // ✅ GLOBAL LOCK: Auto-trigger unlock if launched from background lock
        val isFromGlobalLock = intent.getBooleanExtra("from_global_lock", false)
        if (isFromGlobalLock && viewModel.isVaultExists(this)) {
            unlockVault()
        }

        btnLogin.setOnClickListener {
            if (viewModel.isAuthInProgress.get()) return@setOnClickListener

            // ✅ UPGRADE 6: Check rate limit before allowing auth
            when (val status = viewModel.checkRateLimit(this)) {
                is AuthViewModel.RateLimitStatus.Blocked -> {
                    startRateLimitCountdown(status.waitSeconds)
                    return@setOnClickListener
                }
                else -> { /* Allowed */ }
            }

            if (viewModel.isVaultExists(this)) {
                unlockVault()
            } else {
                createNewVault()
            }
        }

        btnRestore.setOnClickListener {
            showRestoreDialog()
        }

        // ✅ UPGRADE: Modern back press handling (replaces deprecated onBackPressed)
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                val fromGlobalLock = intent.getBooleanExtra("from_global_lock", false)
                if (fromGlobalLock) {
                    // Don't allow dismiss — keep lock screen up
                    moveTaskToBack(true)
                } else {
                    isEnabled = false
                    onBackPressedDispatcher.onBackPressed()
                }
            }
        })
    }

    override fun onDestroy() {
        super.onDestroy()
        rateLimitTimer?.cancel()
    }

    // =========================================================
    // VIEWMODEL STATE OBSERVER
    // =========================================================
    private fun observeViewModel() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                viewModel.uiState.collect { state ->
                    when (state) {
                        is AuthUiState.Idle -> { /* nothing */ }

                        is AuthUiState.Loading -> {
                            btnLogin.isEnabled   = false
                            btnRestore.isEnabled = false
                            tvStatus.text = "⏳ Processing..."
                        }

                        is AuthUiState.VaultExists -> {
                            refreshUIState(state.isLocked)
                        }

                        is AuthUiState.Success -> {
                            showSuccess(
                                if (state.isGlobalUnlock) "Vault Unlocked!"
                                else "Identity Verified!"
                            )
                            if (state.isGlobalUnlock) {
                                ZkpApplication.isAppLocked.set(false)
                                finish()
                            } else {
                                val intent = Intent(this@AuthActivity, MainActivity::class.java)
                                intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                                startActivity(intent)
                                finish()
                            }
                        }

                        is AuthUiState.Error -> {
                            showError(state.message)
                            enableButtons()
                        }

                        is AuthUiState.TamperDetected -> {
                            showError("⚠️ Security Warning: Tampered environment detected.\nApp may not be safe to use.")
                            disableButtons()
                        }

                        is AuthUiState.RateLimited -> {
                            startRateLimitCountdown(state.waitSeconds)
                        }

                        is AuthUiState.SeedGenerated -> {
                            // Handled inline in createNewVault — seed shown in AlertDialog
                        }
                    }
                }
            }
        }
    }

    // =========================================================
    // UPGRADE 7: TAMPER DETECTION
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
                    .setPositiveButton("I understand, continue") { _, _ -> /* proceed */ }
                    .setNegativeButton("Exit") { _, _ -> finish() }
                    .setCancelable(false)
                    .show()
            }
            is AuthViewModel.TamperResult.Clean -> { /* all good */ }
        }
    }

    // =========================================================
    // UPGRADE 5: STRONGBOX KEY INIT
    // =========================================================
    private fun initKeyStore() {
        try {
            val useStrongBox = viewModel.isStrongBoxAvailable(this)
            keyStoreManager.generateMasterKey(useStrongBox = useStrongBox)

            if (useStrongBox) {
                tvStatus.text = "🔒 Hardware StrongBox active"
            }
        } catch (e: Exception) {
            showError("Failed to initialize secure storage.\nReason: ${e.message ?: "Unknown"}")
            disableButtons()
        }
    }

    // =========================================================
    // UPGRADE 6: RATE LIMIT COUNTDOWN UI
    // =========================================================
    private fun startRateLimitCountdown(seconds: Int) {
        rateLimitTimer?.cancel()
        disableButtons()

        rateLimitTimer = object : CountDownTimer(seconds * 1000L, 1000L) {
            override fun onTick(ms: Long) {
                val s = (ms / 1000) + 1
                tvStatus.text = "⛔ Too many failed attempts.\nTry again in ${s}s..."
                tvStatus.setTextColor(resources.getColor(android.R.color.holo_orange_light, theme))
            }
            override fun onFinish() {
                viewModel.resetState()
                viewModel.emitVaultState(this@AuthActivity)
                enableButtons()
            }
        }.start()
    }

    // =========================================================
    // VAULT CREATION — True BIP39
    // =========================================================
    private fun createNewVault() {
        viewModel.emitLoading()

        lifecycleScope.launch(Dispatchers.Default) {
            // ✅ UPGRADE 1: True BIP39 generation (entropy + SHA256 checksum)
            val mnemonic = viewModel.generateTrueBip39Mnemonic()

            withContext(Dispatchers.Main) {
                encryptAndSaveSeed(mnemonic, isRestore = false)
            }
        }
    }

    // =========================================================
    // UNLOCK VAULT (Decrypt Flow)
    // =========================================================
    private fun unlockVault() {
        if (!viewModel.isAuthInProgress.compareAndSet(false, true)) return

        try {
            val prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

            val ivString = prefs.getString(KEY_IV, null)
            if (ivString.isNullOrEmpty()) {
                viewModel.isAuthInProgress.set(false)
                showError("Vault corrupted: IV missing.\nPlease recreate your identity.")
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

                            // ✅ Pass ByteArray to JNI — avoid String in RAM
                            val proofBytes  = SecureVaultJni.generateSecureIdentityProof(decryptedBytes)
                            val proofResult = String(proofBytes, Charsets.UTF_8)

                            // ✅ Auth succeeded — reset fail counter
                            viewModel.resetFailedAttempts(this@AuthActivity)

                            val isFromGlobalLock = intent.getBooleanExtra("from_global_lock", false)
                            viewModel.emitSuccess(proofResult, isFromGlobalLock)

                        } catch (e: Exception) {
                            // ✅ UPGRADE 6: Record failure for rate limiting
                            viewModel.recordFailedAttempt(this@AuthActivity)
                            viewModel.emitError("Decryption failed.\nReason: ${e.message}")
                        } finally {
                            // 🔥 KILL SWITCH: Zero sensitive bytes in RAM
                            decryptedBytes?.let { Arrays.fill(it, 0.toByte()) }
                            viewModel.isAuthInProgress.set(false)
                        }
                    }
                },
                onError = { errMsg ->
                    viewModel.isAuthInProgress.set(false)
                    // ✅ UPGRADE 6: Biometric failure = failed attempt
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
    // ENCRYPT AND SAVE SEED
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
                                .commit()  // synchronous — critical data

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
    // RESTORE DIALOG — BIP39 + Checksum Validation
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
                        showError("Got ${words.size} words — need exactly 12.")
                    }
                    words.any { it !in viewModel.bip39WordSet } -> {
                        // ✅ O(1) HashSet lookup
                        val bad = words.filter { it !in viewModel.bip39WordSet }
                        showError("Invalid BIP39 words: ${bad.joinToString(", ")}")
                    }
                    !viewModel.validateBip39Checksum(typedSeed) -> {
                        // ✅ UPGRADE 2: Checksum verification
                        showError("Invalid mnemonic: checksum mismatch.\nDouble-check your words.")
                    }
                    else -> {
                        encryptAndSaveSeed(typedSeed, isRestore = true)
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // =========================================================
    // UI HELPERS
    // =========================================================
    private fun refreshUIState(isLocked: Boolean) {
        if (isLocked) {
            tvStatus.text      = "Locked Vault Found 🔒\nAuthenticate to Decrypt"
            btnLogin.text      = "Unlock Vault"
            btnRestore.visibility = View.GONE
        } else {
            tvStatus.text      = "No Identity Found.\nCreate or Restore Recovery Seed"
            btnLogin.text      = "Create Secret"
            btnRestore.visibility = View.VISIBLE
        }
        enableButtons()
    }

    private fun showError(message: String) {
        runOnUiThread {
            tvStatus.text = "❌ $message"
            tvStatus.setTextColor(resources.getColor(android.R.color.holo_red_light, theme))
        }
    }

    private fun showSuccess(message: String) {
        runOnUiThread {
            tvStatus.text = "✅ $message"
            tvStatus.setTextColor(resources.getColor(android.R.color.holo_green_light, theme))
        }
    }

    private fun disableButtons() {
        btnLogin.isEnabled   = false
        btnRestore.isEnabled = false
    }

    private fun enableButtons() {
        btnLogin.isEnabled   = true
        btnRestore.isEnabled = true
    }
}