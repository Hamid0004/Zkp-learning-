package com.example.zkpapp.security

import android.util.Log
import androidx.annotation.MainThread
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

/**
 * ZkBiometricManager v2.1
 *
 * ═══════════════════════════════════════════════════════════════
 * v2.0 → v2.1 Fixes (The "Reverse Conflict" OS Bug):
 *
 * 🔴 [FIX] Single Instance Pattern for BiometricPrompt
 * v2.0: Created a new BiometricPrompt instance on every click.
 * Caused OS-level FragmentManager conflicts when switching
 * between Tier 1 and Tier 3 screens (popup wouldn't show).
 * v2.1: BiometricPrompt is initialized lazily ONCE per activity.
 * Callbacks are stored in state variables and updated dynamically.
 * This completely eliminates the "stuck" or "frozen" prompt bug.
 * ═══════════════════════════════════════════════════════════════
 */
class ZkBiometricManager(private val activity: FragmentActivity) {

    companion object {
        private const val TAG = "ZkBiometricManager"
    }

    // ── State variables to hold the latest callbacks ──
    private var onSuccessCallback: ((BiometricPrompt.AuthenticationResult) -> Unit)? = null
    private var onErrorCallback: ((String) -> Unit)? = null
    private var onFailedCallback: (() -> Unit)? = null

    // 🛠️ BUG FIX: Initialize BiometricPrompt ONLY ONCE using lazy delegation
    private val biometricPrompt by lazy {
        val executor = ContextCompat.getMainExecutor(activity)
        BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.d(TAG, "✅ Auth success — CryptoObject unlocked 🔓")
                onSuccessCallback?.invoke(result)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Log.w(TAG, "❌ Auth error [$errorCode]: $errString")
                onErrorCallback?.invoke(errString.toString())
            }

            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                Log.w(TAG, "⚠️ Auth failed — wrong biometric, user can retry")
                onFailedCallback?.invoke()
            }
        })
    }

    fun canAuthenticate(): Boolean {
        val mgr = BiometricManager.from(activity)
        return mgr.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS
    }

    /**
     * Show biometric prompt with hardware-bound CryptoObject.
     *
     * @param activity     FragmentActivity — kept for backward compatibility with calling classes
     * @param cryptoObject Cipher wrapped in CryptoObject — unlocked on success
     * @param subtitle     Claim-specific label shown to user.
     * @param onSuccess    Called with AuthenticationResult
     * @param onError      Called on hardware error or user cancel
     * @param onFailed     Called on wrong finger/face (retryable).
     */
    @MainThread
    fun authenticateUser(
        activity:     FragmentActivity,
        cryptoObject: BiometricPrompt.CryptoObject,
        subtitle:     String = "Touch sensor to access secured data",
        onSuccess:    (BiometricPrompt.AuthenticationResult) -> Unit,
        onError:      (String) -> Unit,
        onFailed:     () -> Unit = {}
    ) {
        // Update the state variables with the latest lambdas from the caller
        onSuccessCallback = onSuccess
        onErrorCallback   = onError
        onFailedCallback  = onFailed

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("ZK Identity Vault")
            .setSubtitle(subtitle)
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        // Reuse the single instance of biometricPrompt
        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
}