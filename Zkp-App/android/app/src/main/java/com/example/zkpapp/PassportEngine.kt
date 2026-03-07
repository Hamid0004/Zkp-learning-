package com.example.zkpapp

import android.graphics.*
import android.nfc.tech.IsoDep
import android.util.Log
import kotlinx.coroutines.delay
import net.sf.scuba.smartcards.CardService
import org.jmrtd.BACKeySpec
import org.jmrtd.PassportService
import org.jmrtd.lds.icao.DG1File
import org.jmrtd.lds.icao.DG2File
import org.jmrtd.lds.iso19794.FaceImageInfo
import org.spongycastle.jce.provider.BouncyCastleProvider
import java.io.ByteArrayInputStream
import java.security.Security
import java.util.concurrent.atomic.AtomicBoolean

// ── Enums & Sealed Classes ────────────────────────────────────────────────────

enum class PassportMode { REAL, SIMULATION }

sealed class PassportState {
    object IDLE          : PassportState()
    object CONNECTING    : PassportState()
    object ANALYZING_MRZ : PassportState()
    object BAC_AUTH      : PassportState()
    object READING       : PassportState()
    object DONE          : PassportState()
    data class ERROR(val reason: String) : PassportState()
}

// ── PassportEngine ────────────────────────────────────────────────────────────

class PassportEngine(
    private val mode:   PassportMode,
    private val isoDep: IsoDep?,
    private val mrz:    String?
) {

    companion object {
        private const val TAG = "PassportEngine"

        // Race condition fix — AtomicBoolean se sirf ek baar init
        private val bcProviderInstalled = AtomicBoolean(false)

        // Simulation delays
        private const val DELAY_MRZ_MS  = 400L
        private const val DELAY_BAC_MS  = 600L
        private const val DELAY_READ_MS = 800L

        // Max size limits
        private const val MAX_DG1_BYTES  = 10_000
        private const val MAX_SOD_BYTES  = 50_000
        // [FIX 7] 300 → match PassportActivity 300x400 scale target (was 512 — wasted memory)
        private const val MAX_PHOTO_SIZE = 300

        // [FIX 5] Rust v5.1 simulation constants — MUST stay in sync with passport_security.rs
        // Rust sim hardcoded: first="ARSALAN", last="KHAN", doc="AB1234567", nat="PAK"
        // Divergence = different Merkle roots → proof cache mismatch → debug nightmare
        const val SIM_FIRST_NAME      = "ARSALAN"
        const val SIM_LAST_NAME       = "KHAN"
        const val SIM_DOCUMENT_NUMBER = "AB1234567"
        const val SIM_NATIONALITY     = "PAK"
        const val SIM_DOB             = "950101"   // 1995-01-01
        const val SIM_EXPIRY          = "300101"   // 2030-01-01
        // TD3 MRZ — 88 chars exactly, safe for BER-TLV single-byte length
        const val SIM_MRZ =
            "P<PAK${SIM_LAST_NAME}<<${SIM_FIRST_NAME}<<<<<<<<<<<<<<<<<<<<<<<<<" +
            "${SIM_DOCUMENT_NUMBER}PAK${SIM_DOB}M${SIM_EXPIRY}<<<<<<<<<<<<<<<4"

        fun ensureBouncyCastle() {
            if (bcProviderInstalled.compareAndSet(false, true)) {
                Security.removeProvider("BC")
                Security.insertProviderAt(BouncyCastleProvider(), 1)
                Log.d(TAG, "✅ BouncyCastle provider installed")
            }
        }
    }

    var state: PassportState = PassportState.IDLE
        private set

    // ── Entry Point ───────────────────────────────────────────────────────────

    suspend fun start(): PassportData {
        ensureBouncyCastle()
        state = PassportState.CONNECTING

        return try {
            when (mode) {
                PassportMode.REAL       -> connectRealChip()
                PassportMode.SIMULATION -> simulateChip()
            }
        } catch (e: Exception) {
            state = PassportState.ERROR(e.message ?: "Unknown error")
            Log.e(TAG, "❌ ENGINE FAILURE", e)
            throw e
        }
    }

    // =========================================================================
    // 🛂 REAL PASSPORT NFC FLOW
    // =========================================================================

    private suspend fun connectRealChip(): PassportData {
        requireNotNull(isoDep) { "IsoDep missing for REAL mode" }
        require(!mrz.isNullOrBlank()) { "MRZ missing for REAL mode" }

        // ── MRZ Parse ────────────────────────────────────────────────────────
        state = PassportState.ANALYZING_MRZ
        val bacKey: BACKeySpec = MrzUtil.extractBacKey(mrz!!)
            ?: throw Exception("MRZ parsing failed — check MRZ format")

        // ── NFC Connect ───────────────────────────────────────────────────────
        isoDep.timeout = 8000
        if (!isoDep.isConnected) isoDep.connect()

        val cardService = CardService.getInstance(isoDep)
        val service = PassportService(
            cardService,
            PassportService.NORMAL_MAX_TRANCEIVE_LENGTH,
            PassportService.DEFAULT_MAX_BLOCKSIZE,
            false,
            false
        )

        try {
            cardService.open()
            service.open()

            // ── BAC Authentication ────────────────────────────────────────────
            state = PassportState.BAC_AUTH
            service.sendSelectApplet(false)

            try {
                service.doBAC(bacKey)
                Log.d(TAG, "✅ BAC success")
            } catch (e: Exception) {
                throw Exception("BAC failed — wrong MRZ or weak NFC signal: ${e.message}")
            }

            state = PassportState.READING

            // ── DG1: Identity Data ────────────────────────────────────────────
            val dg1RawBytes = service
                .getInputStream(PassportService.EF_DG1)
                .readBytes()
                .also {
                    // ✅ Fix 3: Size limit
                    check(it.size <= MAX_DG1_BYTES) {
                        "DG1 too large: ${it.size} bytes (max $MAX_DG1_BYTES)"
                    }
                }

            val dg1  = DG1File(ByteArrayInputStream(dg1RawBytes))
            val info = dg1.mrzInfo

            val firstName = info.secondaryIdentifier.replace("<", " ").trim()
            val lastName  = info.primaryIdentifier.replace("<", " ").trim()

            // [FIX 3] Extract nationality from DG1 — not hardcoded "PK"
            // JMRTD returns ISO 3166-1 alpha-3 e.g. "PAK", "GBR", "DEU"
            val nationality = info.nationality?.trim()?.uppercase() ?: "PAK"

            // [FIX 8] Capture raw MRZ string for Rust mrz_line field
            // JMRTD MrzInfo.toString() returns the full MRZ lines joined
            val mrzLine = runCatching { info.toString() }.getOrDefault("")

            Log.d(TAG, "✅ DG1 read: $firstName $lastName nat=$nationality (${dg1RawBytes.size}B)")

            // ── DG2: Photo ────────────────────────────────────────────────────
            // ✅ Fix 4: OOM-safe bitmap decode with inSampleSize
            var faceBitmap: Bitmap? = null
            try {
                val dg2 = DG2File(service.getInputStream(PassportService.EF_DG2))
                if (dg2.faceInfos.isNotEmpty()) {
                    val faceInfo = dg2.faceInfos[0] as FaceImageInfo
                    faceBitmap = decodeSafeBitmap(faceInfo.imageInputStream.readBytes())
                }
            } catch (e: Exception) {
                Log.w(TAG, "⚠️ Photo read failed (non-critical): ${e.message}")
            }

            // ── SOD: Government Signature ─────────────────────────────────────
            var sodRawBytes: ByteArray? = null
            var dsCertHex:   String?    = null
            try {
                sodRawBytes = service
                    .getInputStream(PassportService.EF_SOD)
                    .readBytes()
                    .also {
                        check(it.size <= MAX_SOD_BYTES) {
                            "SOD too large: ${it.size} bytes"
                        }
                    }
                Log.d(TAG, "✅ SOD read: ${sodRawBytes.size} bytes")

                // [FIX GAP 1] Extract DS certificate from SOD for Rust signature verification
                // org.jmrtd.lds.SODFile parses CMS SignedData — DS cert is signerCertificate
                // This is optional — Rust v5.1 accepts null (Option<String>)
                try {
                    val sodFile = org.jmrtd.lds.SODFile(ByteArrayInputStream(sodRawBytes))
                    val dsCert  = sodFile.docSigningCertificate
                    if (dsCert != null) {
                        dsCertHex = dsCert.encoded.toHexString()
                        Log.d(TAG, "✅ DS cert extracted: ${dsCert.encoded.size}B")
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "⚠️ DS cert extraction failed (non-critical): ${e.message}")
                }

            } catch (e: Exception) {
                // [FIX 4] SOD failure in REAL mode = hard throw — not silent null
                // Silent null → PassportActivity shows success → Rust rejects → confusing UX
                // User should know NOW that SOD failed so they can retry NFC scan
                throw Exception(
                    "SOD (Security Object Document) read failed.\n" +
                    "Try holding phone steady — chip may need re-scan.\n" +
                    "Detail: ${e.message}"
                )
            }

            state = PassportState.DONE

            val data = PassportData(
                firstName      = firstName,
                lastName       = lastName,
                gender         = info.gender.toString(),
                documentNumber = info.documentNumber,
                dateOfBirth    = info.dateOfBirth,
                expiryDate     = info.dateOfExpiry,
                nationality    = nationality,          // [FIX 3] from DG1, not hardcoded
                mrzLine        = mrzLine,              // [FIX 8] Rust mrz_line field
                dsCertHex      = dsCertHex,            // [FIX GAP 1] DS cert for Rust sig verify
                facePhoto      = faceBitmap,
                dg1Raw         = dg1RawBytes,
                sodRaw         = sodRawBytes
            )

            // [FIX 2] Cache photo in companion WeakReference — survives Parcel roundtrip
            PassportData.cachePhoto(data.documentNumber, faceBitmap)

            return data

        } finally {
            // ✅ Cleanup — original code sahi tha, same rakhkha
            try { service.close()   } catch (_: Exception) {}
            try { cardService.close() } catch (_: Exception) {}
            try { if (isoDep.isConnected) isoDep.close() } catch (_: Exception) {}
        }
    }

    // =========================================================================
    // 🧪 SIMULATION MODE
    // =========================================================================

    private suspend fun simulateChip(): PassportData {
        state = PassportState.ANALYZING_MRZ; delay(DELAY_MRZ_MS)
        state = PassportState.BAC_AUTH;      delay(DELAY_BAC_MS)
        state = PassportState.READING;       delay(DELAY_READ_MS)

        // [FIX 10] Passport-style placeholder photo — looks professional in FYP screenshots
        val bmp    = Bitmap.createBitmap(300, 400, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bmp)
        // Dark background
        canvas.drawColor(Color.parseColor("#0a0a1a"))
        // Face circle outline
        val facePaint = Paint().apply {
            color  = Color.parseColor("#00f5ff")
            style  = Paint.Style.STROKE
            strokeWidth = 4f
            isAntiAlias = true
        }
        canvas.drawCircle(150f, 155f, 72f, facePaint)
        // Shoulders arc
        val bodyPaint = Paint().apply {
            color  = Color.parseColor("#00f5ff")
            style  = Paint.Style.STROKE
            strokeWidth = 4f
            isAntiAlias = true
        }
        canvas.drawArc(android.graphics.RectF(50f, 260f, 250f, 420f), 180f, 180f, false, bodyPaint)
        // Name label
        val textPaint = Paint().apply {
            color     = Color.parseColor("#00ff88")
            textSize  = 22f
            textAlign = Paint.Align.CENTER
            isAntiAlias = true
            typeface  = Typeface.DEFAULT_BOLD
        }
        canvas.drawText(SIM_FIRST_NAME, 150f, 355f, textPaint)
        val subPaint = Paint().apply {
            color     = Color.parseColor("#445566")
            textSize  = 14f
            textAlign = Paint.Align.CENTER
            isAntiAlias = true
        }
        canvas.drawText("SIMULATION", 150f, 378f, subPaint)

        // [FIX 5] Use SIM_MRZ constant — stays in sync with Rust v5.1 hardcoded sim values
        val fakeDg1Bytes = buildDg1Bytes(SIM_MRZ)
        val fakeSodBytes = buildSimulatedSod(fakeDg1Bytes)

        state = PassportState.DONE

        val data = PassportData(
            firstName      = SIM_FIRST_NAME,       // [FIX 5] synced with Rust
            lastName       = SIM_LAST_NAME,
            gender         = "M",
            documentNumber = SIM_DOCUMENT_NUMBER,
            dateOfBirth    = SIM_DOB,
            expiryDate     = SIM_EXPIRY,
            nationality    = SIM_NATIONALITY,       // [FIX GAP 1] explicit, not default
            mrzLine        = SIM_MRZ,               // [FIX 8] Rust mrz_line field
            dsCertHex      = null,                  // sim has no real DS cert
            facePhoto      = bmp,
            dg1Raw         = fakeDg1Bytes,
            sodRaw         = fakeSodBytes
        )

        // [FIX 2] Cache sim photo too — consistent API
        PassportData.cachePhoto(data.documentNumber, bmp)

        return data
    }

    // =========================================================================
    // 🔧 HELPERS
    // =========================================================================

    /**
     * ✅ Fix 4: OOM-safe bitmap decode
     * inSampleSize se large passport photos crash nahi karein
     */
    private fun decodeSafeBitmap(bytes: ByteArray): Bitmap? {
        return try {
            // First pass: sirf size check karo
            val opts = BitmapFactory.Options().apply { inJustDecodeBounds = true }
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, opts)

            // Sample size calculate karo
            var sampleSize = 1
            while (opts.outWidth / sampleSize > MAX_PHOTO_SIZE ||
                   opts.outHeight / sampleSize > MAX_PHOTO_SIZE) {
                sampleSize *= 2
            }

            // Second pass: actual decode with sample size
            BitmapFactory.decodeByteArray(bytes, 0, bytes.size,
                BitmapFactory.Options().apply { inSampleSize = sampleSize }
            )
        } catch (e: Exception) {
            Log.w(TAG, "Bitmap decode failed: ${e.message}")
            null
        }
    }

    /**
     * ICAO 9303 DG1 format — BER-TLV encoding
     * Tag 0x61 (DG1) wraps Tag 0x5F1F (MRZ data)
     *
     * [FIX 6] Proper BER-TLV length encoding — handles > 127 bytes correctly
     * Single-byte: len <= 127 → [len]
     * Two-byte:    len <= 255 → [0x81, len]
     * TD3 MRZ = 88 bytes → always single-byte safe, but defensive coding matters
     */
    private fun buildDg1Bytes(mrz: String): ByteArray {
        val mrzBytes = mrz.toByteArray(Charsets.UTF_8)

        // Inner TLV: 0x5F 0x1F + length + mrzBytes
        val innerLen   = mrzBytes.size
        val innerLenBytes = berLength(innerLen)
        val innerTlv  = byteArrayOf(0x5F.toByte(), 0x1F.toByte()) + innerLenBytes + mrzBytes

        // Outer TLV: 0x61 + length + innerTlv
        val outerLenBytes = berLength(innerTlv.size)
        return byteArrayOf(0x61.toByte()) + outerLenBytes + innerTlv
    }

    /** BER-TLV definite short/long length encoding */
    private fun berLength(len: Int): ByteArray = when {
        len <= 127  -> byteArrayOf(len.toByte())
        len <= 255  -> byteArrayOf(0x81.toByte(), len.toByte())
        else        -> byteArrayOf(
            0x82.toByte(),
            (len shr 8).toByte(),
            (len and 0xFF).toByte()
        )
    }

    /**
     * Simulated SOD — embeds real SHA-256(dg1Bytes)
     * passport_security.rs verify_sod_integrity() will PASS
     *
     * Format: SOD tag (0x77) + BER length + OCTET STRING (0x04) + hash
     */
    private fun buildSimulatedSod(dg1Bytes: ByteArray): ByteArray {
        val hash    = java.security.MessageDigest.getInstance("SHA-256").digest(dg1Bytes)
        val inner   = byteArrayOf(0x04.toByte(), hash.size.toByte()) + hash
        val lenBytes = berLength(inner.size)
        return byteArrayOf(0x77.toByte()) + lenBytes + inner
    }

    /** ByteArray → lowercase hex string */
    private fun ByteArray.toHexString(): String =
        joinToString("") { "%02x".format(it) }
}