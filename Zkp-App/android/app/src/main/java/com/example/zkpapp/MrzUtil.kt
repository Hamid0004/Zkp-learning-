package com.example.zkpapp

import android.util.Log
import org.jmrtd.BACKey
import org.jmrtd.BACKeySpec

object MrzUtil {

    private const val TAG = "MrzUtil"

    // ── Check Digit Table (ICAO 9303) ─────────────────────────────────────────
    private val WEIGHTS = intArrayOf(7, 3, 1)
    private val CHAR_VALUES = buildMap<Char, Int> {
        ('A'..'Z').forEachIndexed { i, c -> put(c, i + 10) }
        ('0'..'9').forEach { c -> put(c, c - '0') }
        put('<', 0)
    }

    // ── Main Entry Point ──────────────────────────────────────────────────────

    fun extractBacKey(rawMrz: String?): BACKeySpec? {
        if (rawMrz.isNullOrEmpty()) {
            Log.w(TAG, "MRZ is null or empty")
            return null
        }

        return try {
            // Normalize — uppercase, spaces hata do
            val normalized = rawMrz.uppercase().trim()

            // ✅ Fix 2 + 4: TD3 extract — 2 lines of 44 chars
            val line2 = extractTd3Line2(normalized)
                ?: run {
                    Log.e(TAG, "TD3 Line 2 not found in MRZ:\n$normalized")
                    return null
                }

            // ✅ Fix 3: Clean field (< aur spaces dono)
            val docNumber = line2.substring(0, 9).cleanMrzField()
            val docCheck  = line2[9].toString()

            val dob       = line2.substring(13, 19)
            val dobCheck  = line2[19].toString()

            val expiry    = line2.substring(21, 27)
            val expCheck  = line2[27].toString()

            // ✅ Fix 1: Check digit validate karo
            val docValid = validateCheckDigit(line2.substring(0, 9), docCheck)
            val dobValid = validateCheckDigit(dob, dobCheck)
            val expValid = validateCheckDigit(expiry, expCheck)

            if (!docValid) Log.w(TAG, "⚠️ Doc number check digit mismatch — OCR error?")
            if (!dobValid) Log.w(TAG, "⚠️ DOB check digit mismatch — OCR error?")
            if (!expValid) Log.w(TAG, "⚠️ Expiry check digit mismatch — OCR error?")

            // Agar sab fail hoon toh return null
            if (!docValid && !dobValid && !expValid) {
                Log.e(TAG, "❌ All check digits failed — MRZ likely corrupted")
                return null
            }

            Log.d(TAG, "✅ BAC Key extracted → Doc: $docNumber | DOB: $dob | Exp: $expiry")
            Log.d(TAG, "Check digits → Doc: $docValid | DOB: $dobValid | Exp: $expValid")

            BACKey(docNumber, dob, expiry)

        } catch (e: Exception) {
            Log.e(TAG, "❌ MRZ parse failed", e)
            null
        }
    }

    // ── TD3 Line 2 Extract ────────────────────────────────────────────────────

    /**
     * ✅ Fix 2 + 4: TD3 passport Line 2 dhundho
     * TD3 format: exactly 2 lines, each 44 chars
     * Line 1: P< + country + name
     * Line 2: doc number + check + nationality + dob + check + expiry + check + ...
     */
    private fun extractTd3Line2(mrz: String): String? {
        // Option A: 2 newline-separated lines
        val lines = mrz.lines()
            .map { it.replace(" ", "").replace("«", "<") }
            .filter { it.length >= 44 }

        if (lines.size >= 2) {
            // TD3: Line 2 starts with document number (numeric/alpha), NOT "P<"
            val line2 = lines.firstOrNull { !it.startsWith("P<") && !it.startsWith("P ") }
            if (line2 != null) return line2.substring(0, 44)
        }

        // Option B: Single line — split at position 44
        if (lines.size == 1 && lines[0].length >= 88) {
            return lines[0].substring(44, 88)
        }

        // Option C: Ek hi 44-char line — directly yeh Line 2 ho sakti hai
        if (lines.size == 1 && lines[0].length == 44) {
            // Check karo yeh Line 2 jaisi lagti hai
            val candidate = lines[0]
            if (candidate[9].isDigit() || candidate[9] == '<') {
                return candidate
            }
        }

        return null
    }

    // ── Check Digit Validation (ICAO 9303) ───────────────────────────────────

    /**
     * ✅ Fix 1: ICAO 9303 check digit algorithm
     * weights: 7, 3, 1 repeating
     * char values: A=10..Z=35, 0-9=0-9, <=0
     */
    private fun validateCheckDigit(field: String, checkDigit: String): Boolean {
        val expected = checkDigit.trim().replace("<", "0").firstOrNull()?.toString()?.toIntOrNull()
            ?: return false

        var sum = 0
        field.forEachIndexed { i, c ->
            val value = CHAR_VALUES[c] ?: 0
            sum += value * WEIGHTS[i % 3]
        }

        val calculated = sum % 10
        return calculated == expected
    }

    // ── String Helpers ────────────────────────────────────────────────────────

    /**
     * ✅ Fix 3: MRZ field clean karo
     * < aur «  aur spaces sab hata do
     */
    private fun String.cleanMrzField(): String =
        this.replace("<", "")
            .replace("«", "")
            .replace(" ", "")
            .trim()
}