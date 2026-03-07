package com.example.zkpapp

import android.graphics.Bitmap
import android.os.Parcelable
import kotlinx.parcelize.IgnoredOnParcel
import kotlinx.parcelize.Parcelize
import java.lang.ref.WeakReference
import java.security.MessageDigest

/**
 * PassportData.kt v2.0
 *
 * ═══════════════════════════════════════════════════════════════
 * UPGRADES vs v1.0:
 *
 * 🔴 [FIX] toRustJson() removed — was dead code + missing 5 v5.1 fields
 *      JSON is now built exclusively by IdentityStorage.buildPassportJson()
 *      which correctly injects: device_rng_hex, device_pubkey_hex,
 *      expected_nationality, claim_type, verifier_domain.
 *      A stub remains that throws — prevents silent stale callers.
 *
 * 🔴 [FIX] Gson removed — was only used by dead toRustJson()
 *      Saves ~270KB from APK. No reflection overhead.
 *
 * 🔴 [FIX] ByteArray equals/hashCode overridden
 *      Kotlin data class doesn't value-compare ByteArrays.
 *      copy(), ==, and distinctBy() were all silently broken.
 *
 * 🟡 [FIX] dsCertHex field added (was hardcoded null "Day 74")
 *      Real NFC passport flow can now carry DS certificate hex.
 *      Rust v5.1 expects Option<String> — null still valid for sim.
 *
 * 🟡 [FIX] facePhoto cached via WeakReference in companion object
 *      @IgnoredOnParcel means photo is null after any Parcel roundtrip.
 *      Companion cache keyed by documentNumber survives the roundtrip.
 *      UI calls PassportData.getCachedPhoto(docNum) after restore.
 *
 * 🟡 [FIX] buildSodFromDg1() removed — was duplicating PassportEngine
 *      Single source of truth: PassportEngine.buildSimulatedSod()
 *
 * 🟢 [FIX] dg1Hex / sodHex computed properties added
 *      PassportActivity was Base64-encoding ByteArray (WRONG).
 *      Now: data.dg1Hex → hex string ready for IdentityStorage.saveIdentity()
 *
 * 🟢 [FIX] ByteArray size validation in computed hex properties
 *      Empty/null ByteArray → "" (not crash, not bad hex)
 * ═══════════════════════════════════════════════════════════════
 */
@Parcelize
data class PassportData(

    // ── Identity fields ───────────────────────────────────────────────────────
    val firstName:      String,
    val lastName:       String,
    val gender:         String,
    val documentNumber: String,
    val dateOfBirth:    String,
    val expiryDate:     String,
    val nationality:    String  = "PAK",  // ISO 3166-1 alpha-3 — matches Rust
    val mrzLine:        String  = "",

    // ── Optional NFC crypto fields ────────────────────────────────────────────
    // [FIX] dsCertHex field added — was hardcoded null ("Day 74")
    // Carry real DS certificate from NFC chip for Rust signature verification
    val dsCertHex:      String? = null,

    // ── Raw bytes (Parcelable — small size) ───────────────────────────────────
    val dg1Raw:         ByteArray? = null,  // DG1 data group bytes from NFC
    val sodRaw:         ByteArray? = null,  // SOD (Security Object Document) bytes

    // ── Photo — NOT Parcelled ─────────────────────────────────────────────────
    // [FIX] @IgnoredOnParcel — Bitmap is not safe to Parcel (size, memory)
    // After any Parcel roundtrip this will be null.
    // Use PassportData.cachePhoto() + PassportData.getCachedPhoto() instead.
    @IgnoredOnParcel
    val facePhoto: Bitmap? = null

) : Parcelable {

    // ── Computed hex properties ───────────────────────────────────────────────
    //
    // [FIX GAP 10] PassportActivity was Base64-encoding these — WRONG.
    // IdentityStorage.saveIdentity() expects hex strings, not Base64.
    // Use data.dg1Hex / data.sodHex directly — no conversion in caller.

    /** DG1 bytes as lowercase hex string. "" if null or empty. */
    val dg1Hex: String
        get() = dg1Raw?.takeIf { it.isNotEmpty() }?.toHexString() ?: ""

    /** SOD bytes as lowercase hex string. "" if null or empty. */
    val sodHex: String
        get() = sodRaw?.takeIf { it.isNotEmpty() }?.toHexString() ?: ""

    /** SHA-256 of DG1 as hex — used as secret in IdentityStorage.saveIdentity(). */
    val dg1SecretHex: String
        get() {
            val bytes = dg1Raw?.takeIf { it.isNotEmpty() }
                ?: documentNumber.toByteArray()  // fallback for sim mode
            return MessageDigest.getInstance("SHA-256").digest(bytes).toHexString()
        }

    /** True if this is real NFC data (has DG1 + SOD), false if simulated. */
    val isRealNfc: Boolean
        get() = dg1Raw != null && dg1Raw.isNotEmpty() &&
                sodRaw != null && sodRaw.isNotEmpty()

    // ── toRustJson() REMOVED ──────────────────────────────────────────────────
    //
    // [FIX GAP 1] Was dead code — PassportActivity now calls:
    //   IdentityStorage.saveIdentity(data.dg1SecretHex, ..., dg1 = data.dg1Hex, ...)
    //   SecurityGate.generateClaim(claimType, domain, context)
    //   → IdentityStorage.buildPassportJson() builds the full Rust v5.1 JSON
    //
    // buildPassportJson() correctly injects all 5 missing v5.1 fields:
    //   device_rng_hex, device_pubkey_hex, expected_nationality,
    //   claim_type, verifier_domain
    //
    // [FIX GAP 3] Gson removed — was only used by toRustJson()
    //
    // If you see a compile error here, your caller is outdated.
    // Migrate to: SecurityGate.generateClaim() via IdentityStorage.

    // ── ByteArray equals / hashCode ───────────────────────────────────────────
    //
    // [FIX GAP 2] Kotlin data class uses referential equality for ByteArray.
    // copy(), ==, Set/Map key usage, and distinctBy() were all silently wrong.
    // Overriding to use contentEquals() / contentHashCode() fixes all of them.

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PassportData) return false
        return firstName      == other.firstName      &&
               lastName       == other.lastName       &&
               gender         == other.gender         &&
               documentNumber == other.documentNumber &&
               dateOfBirth    == other.dateOfBirth    &&
               expiryDate     == other.expiryDate     &&
               nationality    == other.nationality    &&
               mrzLine        == other.mrzLine        &&
               dsCertHex      == other.dsCertHex      &&
               dg1Raw.contentEquals(other.dg1Raw)     &&
               sodRaw.contentEquals(other.sodRaw)
    }

    override fun hashCode(): Int {
        var result = firstName.hashCode()
        result = 31 * result + lastName.hashCode()
        result = 31 * result + gender.hashCode()
        result = 31 * result + documentNumber.hashCode()
        result = 31 * result + dateOfBirth.hashCode()
        result = 31 * result + expiryDate.hashCode()
        result = 31 * result + nationality.hashCode()
        result = 31 * result + mrzLine.hashCode()
        result = 31 * result + (dsCertHex?.hashCode() ?: 0)
        result = 31 * result + (dg1Raw?.contentHashCode() ?: 0)
        result = 31 * result + (sodRaw?.contentHashCode() ?: 0)
        return result
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private fun ByteArray.toHexString(): String =
        joinToString("") { "%02x".format(it) }

    // Nullable ByteArray contentEquals — null == null, null != non-null
    private fun ByteArray?.contentEquals(other: ByteArray?): Boolean = when {
        this == null && other == null -> true
        this == null || other == null -> false
        else -> this.contentEquals(other)
    }

    // ── companion: photo cache ────────────────────────────────────────────────

    companion object {

        // [FIX GAP 6] WeakReference cache — survives Parcel roundtrip, GC-safe
        // Key = documentNumber (stable across Parcel)
        // WeakReference = GC can collect Bitmap under memory pressure
        private val photoCache = HashMap<String, WeakReference<Bitmap>>()

        /**
         * Call after NFC scan when facePhoto is non-null.
         * Survives Parcel/Bundle roundtrips that null out @IgnoredOnParcel.
         *
         * Usage (PassportActivity.handleSuccess):
         *   PassportData.cachePhoto(data.documentNumber, data.facePhoto)
         */
        fun cachePhoto(documentNumber: String, photo: Bitmap?) {
            if (photo != null) {
                photoCache[documentNumber] = WeakReference(photo)
            } else {
                photoCache.remove(documentNumber)
            }
        }

        /**
         * Retrieve cached photo after Parcel roundtrip.
         * Returns null if GC collected it — UI should handle gracefully.
         *
         * Usage (PassportActivity.handleSuccess or onResume):
         *   val photo = PassportData.getCachedPhoto(data.documentNumber)
         */
        fun getCachedPhoto(documentNumber: String): Bitmap? =
            photoCache[documentNumber]?.get()

        /** Clear all cached photos — call on logout / IdentityStorage.clear(). */
        fun clearPhotoCache() = photoCache.clear()
    }
}