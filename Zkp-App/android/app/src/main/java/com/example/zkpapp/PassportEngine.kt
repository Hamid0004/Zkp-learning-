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

        // ✅ Fix 2: Race condition fix — AtomicBoolean se sirf ek baar init
        private val bcProviderInstalled = AtomicBoolean(false)

        // ✅ Fix 5: Simulation delays constant mein
        private const val DELAY_MRZ_MS   = 400L
        private const val DELAY_BAC_MS   = 600L
        private const val DELAY_READ_MS  = 800L

        // ✅ Fix 3: Max size limits
        private const val MAX_DG1_BYTES  = 10_000
        private const val MAX_SOD_BYTES  = 50_000
        private const val MAX_PHOTO_SIZE = 512  // px — downsample target

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

            Log.d(TAG, "✅ DG1 read: $firstName $lastName (${dg1RawBytes.size} bytes)")

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
            try {
                sodRawBytes = service
                    .getInputStream(PassportService.EF_SOD)
                    .readBytes()
                    .also {
                        // ✅ Fix 3: SOD size limit
                        check(it.size <= MAX_SOD_BYTES) {
                            "SOD too large: ${it.size} bytes"
                        }
                    }
                Log.d(TAG, "✅ SOD read: ${sodRawBytes.size} bytes")
            } catch (e: Exception) {
                Log.w(TAG, "⚠️ SOD read failed — ZKP will fail: ${e.message}")
            }

            state = PassportState.DONE

            return PassportData(
                firstName      = firstName,
                lastName       = lastName,
                gender         = info.gender.toString(),
                documentNumber = info.documentNumber,
                dateOfBirth    = info.dateOfBirth,
                expiryDate     = info.dateOfExpiry,
                facePhoto      = faceBitmap,
                dg1Raw         = dg1RawBytes,
                sodRaw         = sodRawBytes
            )

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

        // ── Fake Photo ────────────────────────────────────────────────────────
        val bmp    = Bitmap.createBitmap(300, 400, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bmp)
        canvas.drawColor(Color.LTGRAY)
        canvas.drawText(
            "SIM USER", 150f, 200f,
            Paint().apply {
                color     = Color.BLUE
                textSize  = 60f
                textAlign = Paint.Align.CENTER
                isAntiAlias = true
            }
        )

        // ✅ Fix 6: Proper MRZ-like DG1 bytes
        // ICAO 9303 DG1 format: tag 0x61 + real MRZ data
        // "P<PAKTESTUSER<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\nPK12345670PK9501011M3001010<<<<<<<<<<<<<4"
        val fakeMrz    = "P<PAKTESTUSER<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<PK12345670PK9501011M3001010<<<<<<<<<<<<<4"
        val fakeDg1Bytes = buildDg1Bytes(fakeMrz)

        // ✅ Fix 1: Fake SOD mein DG1 ka actual SHA256 hash embed karo
        // Taake passport_security.rs ka integrity check PASS kare
        val fakeSodBytes = buildSimulatedSod(fakeDg1Bytes)

        state = PassportState.DONE

        return PassportData(
            firstName      = "TEST",
            lastName       = "USER",
            gender         = "M",
            documentNumber = "PK1234567",
            dateOfBirth    = "950101",
            expiryDate     = "300101",
            facePhoto      = bmp,
            dg1Raw         = fakeDg1Bytes,
            sodRaw         = fakeSodBytes
        )
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
     * ✅ Fix 6: ICAO 9303 DG1 format se bytes banana
     * DG1 tag = 0x61, content tag = 0x5F1F
     */
    private fun buildDg1Bytes(mrz: String): ByteArray {
        val mrzBytes    = mrz.toByteArray(Charsets.UTF_8)
        val contentLen  = mrzBytes.size + 4  // 0x5F 0x1F + 2-byte length
        return byteArrayOf(
            0x61.toByte(),
            (contentLen + 2).toByte(),
            0x5F.toByte(), 0x1F.toByte(),
            mrzBytes.size.toByte()
        ) + mrzBytes
    }

    /**
     * ✅ Fix 1: Simulated SOD mein real DG1 hash embed karo
     * passport_security.rs ka verify_sod_integrity() PASS karega
     *
     * Format: OCTET STRING (0x04) + hash_length + sha256(dg1)
     */
    private fun buildSimulatedSod(dg1Bytes: ByteArray): ByteArray {
        val sha256 = java.security.MessageDigest.getInstance("SHA-256")
        val hash   = sha256.digest(dg1Bytes)

        // SOD header + OCTET STRING tag + hash
        return byteArrayOf(
            0x77.toByte(),                   // SOD tag
            (hash.size + 2).toByte(),        // total length
            0x04.toByte(),                   // OCTET STRING tag
            hash.size.toByte()               // hash length
        ) + hash
    }
}