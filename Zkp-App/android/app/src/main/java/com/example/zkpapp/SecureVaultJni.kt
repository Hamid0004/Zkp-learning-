package com.example.zkpapp

import java.util.Arrays

/**
 * JNI bridge to the Rust `zkp_mobile` library.
 *
 * Security contract:
 * - Callers MUST pass seed bytes as a [ByteArray] (never a [String]) to prevent
 *   clear-text residue on the JVM string pool.
 * - After [generateSecureIdentityProof] returns, callers MUST zeroize the
 *   input array with [wipeSensitiveBytes] — the JVM cannot guarantee GC timing.
 * - The returned proof bytes are not sensitive, but callers should still scope
 *   them to the minimum required lifetime.
 */
object SecureVaultJni {

    init {
        System.loadLibrary("zkp_mobile")
    }

    /**
     * Generates a ZKP-ready Poseidon Merkle root from a raw seed.
     *
     * @param seedBytes  Raw entropy — zeroize immediately after this call.
     * @return           32-byte Merkle root, or 32 zero bytes on KDF failure.
     */
    external fun generateSecureIdentityProof(seedBytes: ByteArray): ByteArray

    /**
     * Overwrites [sensitiveBytes] in-place with zeros.
     *
     * Call this immediately after [generateSecureIdentityProof] to minimize
     * the window during which seed material lives in heap memory.
     *
     * Example usage:
     * ```kotlin
     * val seed = getSeedFromSecureStorage()
     * try {
     *     val proof = SecureVaultJni.generateSecureIdentityProof(seed)
     *     processProof(proof)
     * } finally {
     *     SecureVaultJni.wipeSensitiveBytes(seed)
     * }
     * ```
     */
    fun wipeSensitiveBytes(sensitiveBytes: ByteArray) {
        Arrays.fill(sensitiveBytes, 0x00.toByte())
    }
}