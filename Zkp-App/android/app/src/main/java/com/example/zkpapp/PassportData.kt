package com.example.zkpapp

import android.graphics.Bitmap
import android.os.Parcelable
import com.google.gson.Gson
import kotlinx.parcelize.IgnoredOnParcel
import kotlinx.parcelize.Parcelize
import java.security.MessageDigest

@Parcelize
data class PassportData(
    val firstName:      String,
    val lastName:       String,
    val gender:         String,
    val documentNumber: String,
    val dateOfBirth:    String,
    val expiryDate:     String,
    val nationality:    String = "PK",
    val mrzLine:        String = "",   // ✅ Fix 3: Rust struct ke liye zaroori

    // ✅ Fix 5: Bitmap Parcel mein nahi jayega — memory safe
    @IgnoredOnParcel
    val facePhoto: Bitmap? = null,

    // Raw bytes — Parcel mein jaenge (small size)
    val dg1Raw: ByteArray? = null,
    val sodRaw: ByteArray? = null

) : Parcelable {

    companion object {
        // ✅ Fix 4: Gson ek baar banao
        private val gson = Gson()
    }

    // ── Bridge: Kotlin → Rust JSON ────────────────────────────────────────────
    fun toRustJson(): String {

        // ✅ Fix 1: Magic SOD hata diya
        // PassportEngine.buildSimulatedSod() se sahi SOD aata hai
        // Jo DG1 ka actual SHA256 embed karta hai — match guarantee
        val finalSodHex = when {
            sodRaw != null && sodRaw.size > 10 -> sodRaw.toHexString()
            dg1Raw != null -> buildSodFromDg1(dg1Raw)  // fallback
            else -> ""
        }

        val finalDg1Hex = dg1Raw?.toHexString() ?: ""

        // ✅ Fix 3: mrz_line add kiya — Rust struct match
        val rustPayload = mapOf(
            "mode"            to "NFC_PASSPORT",
            "first_name"      to firstName,
            "last_name"       to lastName,
            "document_number" to documentNumber,
            "date_of_birth"   to dateOfBirth,
            "nationality"     to nationality,
            "mrz_line"        to mrzLine,
            "dg1_hex"         to finalDg1Hex,
            "sod_hex"         to finalSodHex,
            "ds_cert_hex"     to null          // optional — Day 74
        )

        return gson.toJson(rustPayload)
    }

    // ✅ Fix 1: Runtime pe DG1 se SOD banao (hardcoded hash nahi)
    // PassportEngine.buildSimulatedSod() jaisa hi logic
    private fun buildSodFromDg1(dg1: ByteArray): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(dg1)
        val sodBytes = byteArrayOf(
            0x77.toByte(),
            (hash.size + 2).toByte(),
            0x04.toByte(),
            hash.size.toByte()
        ) + hash
        return sodBytes.toHexString()
    }

    // Helper: ByteArray → Hex String
    private fun ByteArray.toHexString(): String =
        joinToString("") { "%02x".format(it) }
}