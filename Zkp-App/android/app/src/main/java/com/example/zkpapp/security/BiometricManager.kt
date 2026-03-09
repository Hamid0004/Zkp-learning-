package com.example.zkpapp.security

import android.content.Context
import android.util.Log
import androidx.annotation.MainThread
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity

/**
 * ZkBiometricManager v2.0
 *
 * ═══════════════════════════════════════════════════════════════
 * v1.0 → v2.0 Fixes:
 *
 * 🔴 [FIX] Class renamed: BiometricManager → ZkBiometricManager
 *    v1.0 class name shadowed androidx.biometric.BiometricManager.
 *    Inside canAuthenticate(), BiometricManager.from(context) was
 *    ambiguous — could resolve to this class (no .from()) and crash.
 *    Renamed to ZkBiometricManager — zero ambiguity.
 *
 * 🔴 [FIX] subtitle param added to authenticateUser()
 *    AuthActivity.requestBiometricForDiskRestore() passes claim label:
 *    "Age 18+ verify karne ke liye" / "Nationality verify..." etc.
 *    Default = "Touch sensor to access secured data" (existing behavior).
 *
 * 🟡 [FIX] onAuthenticationFailed() added
 *    v1.0: wrong finger → silence → user confused.
 *    v2.0: wrong finger → onFailed() callback → caller can show
 *    "Try again" or increment attempt counter.
 *
 * 🟡 [FIX] @MainThread annotation on authenticateUser()
 *    BiometricPrompt must be called from main thread.
 *    Annotation warns callers at compile time if called from IO/Default.
 *
 * 🟢 [FIX] Log tag changed from "BiometricManager" → "ZkBiometricManager"
 * ═══════════════════════════════════════════════════════════════
 */
class ZkBiometricManager(private val context: Context) {

    companion object {
        private const val TAG = "ZkBiometricManager"
    }

    fun canAuthenticate(): Boolean {
        // [FIX v2.0] No ambiguity — androidx class accessed directly via full reference
        val mgr = BiometricManager.from(context)
        return mgr.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS
    }

    /**
     * Show biometric prompt with hardware-bound CryptoObject.
     *
     * @param activity     FragmentActivity — required by BiometricPrompt
     * @param cryptoObject Cipher wrapped in CryptoObject — unlocked on success
     * @param subtitle     [NEW v2.0] Claim-specific label shown to user.
     *                     e.g. "Age 18+ verify karne ke liye"
     *                     Default: "Touch sensor to access secured data"
     * @param onSuccess    Called with AuthenticationResult — use result.cryptoObject!!.cipher!!
     * @param onError      Called on hardware error or user cancel
     * @param onFailed     [NEW v2.0] Called on wrong finger/face (retryable).
     *                     Default: no-op (existing callers unaffected)
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
        val executor = ContextCompat.getMainExecutor(context)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                Log.d(TAG, "✅ Auth success — CryptoObject unlocked 🔓")
                onSuccess(result)
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                Log.w(TAG, "❌ Auth error [$errorCode]: $errString")
                onError(errString.toString())
            }

            // [FIX v2.0] Wrong finger/face — retryable, not a hard error
            override fun onAuthenticationFailed() {
                super.onAuthenticationFailed()
                Log.w(TAG, "⚠️ Auth failed — wrong biometric, user can retry")
                onFailed()
            }
        }

        // [FIX v2.0] subtitle is dynamic — driven by claim type from AuthActivity
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("ZK Identity Vault")
            .setSubtitle(subtitle)
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        val biometricPrompt = BiometricPrompt(activity, executor, callback)
        biometricPrompt.authenticate(promptInfo, cryptoObject)
    }
}