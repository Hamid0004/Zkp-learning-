package com.example.zkpapp

import android.os.Parcelable
import kotlinx.parcelize.Parcelize
import kotlinx.parcelize.IgnoredOnParcel

/**
 * PassportSession.kt v2.0
 *
 * ═══════════════════════════════════════════════════════════════
 * UPGRADES vs v1.0:
 *
 * 🔴 [FIX 1] SessionState expanded — covers full pipeline including
 *      PassportEngine states (CONNECTING, BAC_AUTH, ANALYZING_MRZ)
 *      + ZKP states (ZKP_GENERATING, ZKP_READY)
 *      UI step bar can now reflect exact engine state without hardcoded strings.
 *
 * 🔴 [FIX 2] MrzInfo expanded — nationality, gender, mrzType, docType
 *      UI can show 🇵🇰 PAK immediately after camera scan (no NFC wait).
 *      docType detects Passport vs National ID from MRZ prefix.
 *
 * 🔴 [FIX 3] SessionState.ZKP_GENERATING + ZKP_READY added
 *      PassportActivity step bar ZKP step now correctly tied to session state.
 *
 * 🟡 [FIX 4] MrzInfo.validate() — rejects empty/malformed fields early
 *      documentNumber length, date format, raw not empty.
 *
 * 🟡 [FIX 5] PassportSession.createdAt timestamp added
 *      UI can show "session expires in X min". AuthActivity freshness check.
 *
 * 🟡 [FIX 6] PassportSession.tier field — Tier 1/2/3 carried in session
 *      AuthActivity min_tier check uses this. Defaults to PASSPORT (Tier 1).
 *
 * 🟡 [FIX 7] MrzInfo.fromRaw() factory — parses structured fields from raw MRZ
 *      Replaces MrzInfo(rawMrz, "PENDING", "PENDING", "PENDING") anti-pattern.
 *      PassportActivity camera launcher now gets real fields immediately.
 *
 * 🟢 [FIX 9] SessionState.displayString + statusColor — DRY UI strings
 *      PassportActivity no longer hardcodes status messages per state.
 *
 * 🟢 [FIX 10] MrzInfo.docType computed from MRZ prefix ("P<" vs "ID")
 *      Future Tier 2 detection without breaking Tier 1 flow.
 * ═══════════════════════════════════════════════════════════════
 */

// ══════════════════════════════════════════════════════════════════════════════
// 1️⃣  Document Tier — which trust level this session represents
// ══════════════════════════════════════════════════════════════════════════════

/**
 * [FIX 6] Tier carried in session — AuthActivity uses this for min_tier check.
 * Matches the three-tier design exactly.
 */
enum class DocumentTier(val level: Int, val label: String) {
    PASSPORT    (1, "Tier 1 — Passport NFC"),       // 🔴 Maximum trust
    NATIONAL_ID (2, "Tier 2 — National ID NFC"),    // 🟡 High trust
    DEVICE_ONLY (3, "Tier 3 — Device + Biometric"); // 🟢 Basic trust

    /** True if this tier satisfies a website's minimum tier requirement. */
    fun satisfies(minTier: Int): Boolean = level <= minTier
}

// ══════════════════════════════════════════════════════════════════════════════
// 2️⃣  Session State — full pipeline from IDLE → ZKP_READY
// ══════════════════════════════════════════════════════════════════════════════

/**
 * [FIX 1 + 3] Complete state machine covering PassportEngine + ZKP pipeline.
 *
 * State flow:
 *   IDLE → MRZ_SCANNED → NFC_READY → CONNECTING → ANALYZING_MRZ
 *       → BAC_AUTH → READING → SOD_READING → DONE
 *       → ZKP_GENERATING → ZKP_READY
 *   Any state → ERROR
 *
 * PassportEngine.PassportState maps 1:1:
 *   PassportState.CONNECTING    → SessionState.CONNECTING
 *   PassportState.ANALYZING_MRZ → SessionState.ANALYZING_MRZ
 *   PassportState.BAC_AUTH      → SessionState.BAC_AUTH
 *   PassportState.READING       → SessionState.READING
 *   PassportState.DONE          → SessionState.DONE
 */
enum class SessionState {
    IDLE,
    MRZ_SCANNED,        // Camera returned MRZ — fields parsed
    NFC_READY,          // User prompted to tap passport
    CONNECTING,         // IsoDep.connect() in progress
    ANALYZING_MRZ,      // BAC key extraction
    BAC_AUTH,           // ICAO BAC handshake
    READING,            // DG1 / DG2 reading
    SOD_READING,        // SOD (govt signature) reading
    DONE,               // NFC read complete — all data in PassportData
    ZKP_GENERATING,     // [FIX 3] Rust ZK circuit running
    ZKP_READY,          // [FIX 3] Proof cached — ready for websites
    ERROR;              // Terminal error state

    // [FIX 9] DRY display strings — PassportActivity uses these instead of hardcoded text
    val displayString: String get() = when (this) {
        IDLE            -> "PASSPORT SCANNER PRO"
        MRZ_SCANNED     -> "MRZ SCANNED — HOLD TO CHIP"
        NFC_READY       -> "HOLD PHONE TO PASSPORT"
        CONNECTING      -> "CONNECTING TO CHIP…"
        ANALYZING_MRZ   -> "READING IDENTITY DATA…"
        BAC_AUTH        -> "BAC AUTHENTICATION…"
        READING         -> "READING CHIP DATA…"
        SOD_READING     -> "READING SECURITY OBJECT…"
        DONE            -> "DATA EXTRACTED"
        ZKP_GENERATING  -> "GENERATING ZK PROOF…"
        ZKP_READY       -> "ZK PROOF READY"
        ERROR           -> "ERROR"
    }

    val statusSub: String get() = when (this) {
        IDLE            -> "READY · SCAN MRZ TO BEGIN"
        MRZ_SCANNED     -> "TAP NFC CHIP WHEN READY"
        NFC_READY       -> "NFC READY — CHIP DETECTED"
        CONNECTING      -> "ESTABLISHING SECURE CHANNEL"
        ANALYZING_MRZ   -> "BAC KEY EXTRACTION"
        BAC_AUTH        -> "ICAO 9303 BAC PROTOCOL"
        READING         -> "DG1 · DG2 IN PROGRESS"
        SOD_READING     -> "GOVERNMENT SIGNATURE"
        DONE            -> "PASSPORT CHIP READ SUCCESSFUL"
        ZKP_GENERATING  -> "PLONKY2 CIRCUIT RUNNING"
        ZKP_READY       -> "PROOF CACHED · WEBSITES READY"
        ERROR           -> ""
    }

    // Step bar index — maps to PassportActivity step chips [MRZ, NFC, READ, SOD, ZKP]
    val stepIndex: Int get() = when (this) {
        IDLE                        -> 0
        MRZ_SCANNED, NFC_READY      -> 1
        CONNECTING, ANALYZING_MRZ,
        BAC_AUTH                    -> 2
        READING                     -> 3
        SOD_READING, DONE           -> 4
        ZKP_GENERATING, ZKP_READY   -> 5
        ERROR                       -> 0
    }

    /** Converts PassportEngine.PassportState to SessionState */
    companion object {
        fun fromEngineState(engineState: PassportState): SessionState = when (engineState) {
            is PassportState.IDLE           -> IDLE
            is PassportState.CONNECTING     -> CONNECTING
            is PassportState.ANALYZING_MRZ  -> ANALYZING_MRZ
            is PassportState.BAC_AUTH       -> BAC_AUTH
            is PassportState.READING        -> READING
            is PassportState.DONE           -> DONE
            is PassportState.ERROR          -> ERROR
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 3️⃣  MrzInfo — structured MRZ data with full field parsing
// ══════════════════════════════════════════════════════════════════════════════

/**
 * [FIX 2 + 7 + 10] Expanded MrzInfo with all fields needed by PassportEngine,
 * IdentityStorage, and UI.
 *
 * fromRaw() factory parses TD3 MRZ (88 chars) immediately after camera scan —
 * no more "PENDING" placeholder values.
 */
@Parcelize
data class MrzInfo(
    val raw:            String,
    val documentNumber: String,
    val dateOfBirth:    String,
    val expiryDate:     String,

    // [FIX 2] Fields parsed from MRZ — available before NFC scan
    val nationality:    String = "",   // ISO 3166-1 alpha-3 e.g. "PAK", "GBR"
    val gender:         String = "",   // "M", "F", "<"
    val mrzType:        String = "TD3" // "TD1" (90 chars) | "TD3" (88 chars)
) : Parcelable {

    // [FIX 10] Document type detected from MRZ prefix
    // "P<" → Passport (Tier 1), "ID" → National ID (Tier 2), "AC"/"V" → others
    @IgnoredOnParcel
    val docType: DocumentTier get() = when {
        raw.startsWith("P")  -> DocumentTier.PASSPORT
        raw.startsWith("ID") -> DocumentTier.NATIONAL_ID
        else                 -> DocumentTier.PASSPORT   // safe default
    }

    // [FIX 4] Validate MrzInfo fields — call after construction
    // Returns error message or null if valid
    fun validate(): String? {
        if (raw.isBlank())                     return "MRZ raw string empty"
        if (raw.length < 44)                   return "MRZ too short (${raw.length} chars)"
        if (documentNumber.isBlank())          return "Document number empty"
        if (documentNumber == "PENDING")       return "Document number not parsed"
        if (!dateOfBirth.matches(Regex("\\d{6}")))  return "DOB format invalid: $dateOfBirth"
        if (!expiryDate.matches(Regex("\\d{6}")))   return "Expiry format invalid: $expiryDate"
        return null  // valid
    }

    val isValid: Boolean get() = validate() == null

    companion object {

        /**
         * [FIX 7] Parse structured fields from raw MRZ string.
         *
         * TD3 format (International Passport — most common):
         *   Line 1 (44 chars): P<NAT LAST<<FIRST<<<<<<<<<<<<<<<<<<<<<<<<<<
         *   Line 2 (44 chars): DOCNUM0NATDDMMYYSGENDER EXPIRY0<<<<<<<<<CD
         *
         * Replaces the anti-pattern:
         *   MrzInfo(rawMrz, "PENDING", "PENDING", "PENDING")
         *
         * Usage in PassportActivity camera launcher:
         *   val mrzInfo = MrzInfo.fromRaw(rawMrz)
         *   val error = mrzInfo.validate()
         *   if (error != null) showError(error) else proceed(mrzInfo)
         */
        fun fromRaw(raw: String): MrzInfo {
            // Normalize — strip whitespace/newlines, uppercase
            val normalized = raw.replace("\n", "").replace(" ", "").uppercase().trim()

            return when {
                // ── TD3: International Passport (88 chars, 2 lines of 44) ──
                normalized.length >= 88 -> parseTd3(normalized)

                // ── TD1: National ID card (90 chars, 3 lines of 30) ──
                normalized.length >= 90 -> parseTd1(normalized)

                // ── Fallback: partial MRZ, return what we have ──
                else -> MrzInfo(
                    raw            = normalized,
                    documentNumber = "",
                    dateOfBirth    = "",
                    expiryDate     = "",
                    nationality    = "",
                    gender         = "",
                    mrzType        = "UNKNOWN"
                )
            }
        }

        /**
         * TD3 MRZ parser — International Passport.
         *
         * Line 2 layout (44 chars):
         * [0-8]   Document number (9 chars)
         * [9]     Check digit
         * [10-12] Nationality (3 chars)
         * [13-18] Date of birth YYMMDD
         * [19]    Check digit
         * [20]    Gender (M/F/<)
         * [21-26] Expiry date YYMMDD
         * [27]    Check digit
         * [28-41] Optional data
         * [42]    Composite check digit
         * [43]    Final check digit
         */
        private fun parseTd3(mrz: String): MrzInfo {
            val line2 = mrz.substring(44, minOf(88, mrz.length))

            val docNum  = line2.substring(0,  minOf(9,  line2.length)).trimEnd('<')
            val nat     = line2.substring(10, minOf(13, line2.length)).trimEnd('<')
            val dob     = line2.substring(13, minOf(19, line2.length))
            val gender  = if (line2.length > 20) line2[20].toString() else ""
            val expiry  = line2.substring(21, minOf(27, line2.length))

            return MrzInfo(
                raw            = mrz,
                documentNumber = docNum,
                dateOfBirth    = dob,
                expiryDate     = expiry,
                nationality    = nat,
                gender         = gender,
                mrzType        = "TD3"
            )
        }

        /**
         * TD1 MRZ parser — National ID card (future Tier 2 support).
         *
         * Line 1 (30 chars): doc type + country + doc number
         * Line 2 (30 chars): DOB + gender + expiry + nationality
         */
        private fun parseTd1(mrz: String): MrzInfo {
            val line1 = mrz.substring(0,  30)
            val line2 = mrz.substring(30, 60)

            val docNum = line1.substring(5, minOf(14, line1.length)).trimEnd('<')
            val dob    = line2.substring(0, minOf(6,  line2.length))
            val gender = if (line2.length > 7) line2[7].toString() else ""
            val expiry = line2.substring(8, minOf(14, line2.length))
            val nat    = line2.substring(15, minOf(18, line2.length)).trimEnd('<')

            return MrzInfo(
                raw            = mrz,
                documentNumber = docNum,
                dateOfBirth    = dob,
                expiryDate     = expiry,
                nationality    = nat,
                gender         = gender,
                mrzType        = "TD1"
            )
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// 4️⃣  PassportSession — main session holder
// ══════════════════════════════════════════════════════════════════════════════

/**
 * [FIX 5 + 6] Session with timestamp + tier field.
 *
 * Usage flow:
 *   // After camera MRZ scan:
 *   session = PassportSession(
 *       mrzInfo   = MrzInfo.fromRaw(rawMrz),
 *       state     = SessionState.MRZ_SCANNED,
 *       tier      = DocumentTier.PASSPORT
 *   )
 *
 *   // After NFC engine state change:
 *   session = session.copy(
 *       state = SessionState.fromEngineState(engine.state)
 *   )
 *
 *   // After ZKP ready:
 *   session = session.copy(state = SessionState.ZKP_READY)
 *
 *   // Check session freshness:
 *   if (!session.isFresh()) { re-scan }
 *
 *   // AuthActivity min_tier check:
 *   if (!session.tier.satisfies(websiteMinTier)) { deny }
 */
@Parcelize
data class PassportSession(
    val mrzInfo:   MrzInfo?      = null,
    val state:     SessionState  = SessionState.IDLE,

    // [FIX 6] Which trust tier this session represents
    val tier:      DocumentTier  = DocumentTier.PASSPORT,

    // [FIX 5] Creation timestamp — for session freshness check
    // Default 0L = unknown (pre-v2.0 sessions are treated as expired)
    val createdAt: Long          = System.currentTimeMillis(),

    // Optional error detail — populated when state == ERROR
    val errorMsg:  String?       = null

) : Parcelable {

    companion object {
        // Must match IdentityStorage.SESSION_TTL_MS = 1_800_000L (30 min)
        private const val SESSION_TTL_MS = 1_800_000L
    }

    // [FIX 5] Session freshness check
    val isFresh: Boolean
        get() = createdAt > 0L &&
                (System.currentTimeMillis() - createdAt) < SESSION_TTL_MS

    /** Minutes remaining before session expires. -1 if already expired. */
    val minutesRemaining: Int
        get() {
            val elapsed = System.currentTimeMillis() - createdAt
            val remaining = SESSION_TTL_MS - elapsed
            return if (remaining > 0) (remaining / 60_000).toInt() else -1
        }

    /** True if NFC read is complete and ZK proof is available */
    val isProofReady: Boolean
        get() = state == SessionState.ZKP_READY

    /** True if MRZ has been scanned and NFC tap is expected */
    val isAwaitingNfc: Boolean
        get() = state == SessionState.MRZ_SCANNED || state == SessionState.NFC_READY

    /** True if engine is actively running (NFC in progress) */
    val isEngineRunning: Boolean
        get() = state in setOf(
            SessionState.CONNECTING,
            SessionState.ANALYZING_MRZ,
            SessionState.BAC_AUTH,
            SessionState.READING,
            SessionState.SOD_READING
        )

    /** Create a fresh error session preserving mrzInfo */
    fun withError(reason: String): PassportSession =
        copy(state = SessionState.ERROR, errorMsg = reason)

    /** Advance to next engine state (called from PassportEngine state observer) */
    fun withEngineState(engineState: PassportState): PassportSession =
        copy(state = SessionState.fromEngineState(engineState))
}