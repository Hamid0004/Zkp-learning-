package com.example.zkpapp

import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.cardview.widget.CardView
import java.text.SimpleDateFormat
import java.util.*
import kotlin.concurrent.thread

/**
 * TestProofActivity
 *
 * Offline ZK Proof Benchmark Screen
 *
 * Measurements:
 * 🔴 MUST  → Proof Generation Time, Verification Time, Proof Size, Status
 * 🟡 GOOD  → Memory Usage (KB), CPU Peak, Circuit Setup, Witness Gen (µs), Constraint Count
 * 🟢 BONUS → Device, Android Version, CPU Arch, Run Count, Avg Time, Min/Max Time
 */
class TestProofActivity : AppCompatActivity() {

    // ── UI References ─────────────────────────────────────────────────────────
    private lateinit var btnRunTest: Button
    private lateinit var btnBack: ImageButton
    private lateinit var tvStatus: TextView
    private lateinit var tvStatusEmoji: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var tvProgressStep: TextView
    private lateinit var layoutProgress: LinearLayout
    private lateinit var layoutResults: LinearLayout
    private lateinit var tvTimestamp: TextView

    private lateinit var cardMust: CardView
    private lateinit var cardGood: CardView
    private lateinit var cardBonus: CardView
    private lateinit var layoutMustRows: LinearLayout
    private lateinit var layoutGoodRows: LinearLayout
    private lateinit var layoutBonusRows: LinearLayout

    // ── State ─────────────────────────────────────────────────────────────────
    private var isRunning = false
    private val handler = Handler(Looper.getMainLooper())
    private val runTimes = mutableListOf<Long>()
    private var runCount = 0

    // ── Data Model ────────────────────────────────────────────────────────────
    data class MetricResult(
        val label: String,
        val value: String,
        val unit: String,
        val emoji: String,
        val valueColor: Int
    )

    // ── Lifecycle ─────────────────────────────────────────────────────────────
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_test_proof)
        bindViews()
        setupClickListeners()
        showIdleState()
    }

    private fun bindViews() {
        btnRunTest     = findViewById(R.id.btnRunTest)
        btnBack        = findViewById(R.id.btnBack)
        tvStatus       = findViewById(R.id.tvStatus)
        tvStatusEmoji  = findViewById(R.id.tvStatusEmoji)
        progressBar    = findViewById(R.id.progressBar)
        tvProgressStep = findViewById(R.id.tvProgressStep)
        layoutProgress = findViewById(R.id.layoutProgress)
        layoutResults  = findViewById(R.id.layoutResults)
        tvTimestamp    = findViewById(R.id.tvTimestamp)
        cardMust       = findViewById(R.id.cardMust)
        cardGood       = findViewById(R.id.cardGood)
        cardBonus      = findViewById(R.id.cardBonus)
        layoutMustRows = findViewById(R.id.layoutMustRows)
        layoutGoodRows = findViewById(R.id.layoutGoodRows)
        layoutBonusRows= findViewById(R.id.layoutBonusRows)
    }

    private fun setupClickListeners() {
        btnBack.setOnClickListener { finish() }
        btnRunTest.setOnClickListener { if (!isRunning) startBenchmark() }
    }

    // =========================================================================
    // BENCHMARK ENGINE
    // =========================================================================

    private fun startBenchmark() {
        isRunning = true
        runCount++
        showRunningState()

        thread {
            try {
                val result = runFullBenchmark()
                handler.post { showResults(result) }
            } catch (e: Exception) {
                handler.post { showFailedState(e.message ?: "Unknown error") }
            } finally {
                isRunning = false
            }
        }
    }

    private fun runFullBenchmark(): BenchmarkResult {
        updateStep("Setting up Plonky2 circuit…", 10)
        val memBefore = getUsedMemoryMb()

        // ── 🦁 REAL JNI CALL ─────────────────────────────────────────────────
        updateStep("Running Rust benchmark…", 30)
        val rustResult: ProofBenchmarkResult = ZkpJni.runProofBenchmark()
        // ─────────────────────────────────────────────────────────────────────

        updateStep("Proof generated ✓", 75)
        updateStep("Verifying proof…", 85)
        updateStep("Collecting device info…", 95)

        val memAfter  = getUsedMemoryMb()
        val deviceModel = "${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL}"
        val androidVer  = android.os.Build.VERSION.RELEASE
        val cpuArch     = System.getProperty("os.arch") ?: "Unknown"
        val cpuPeakPct  = estimateCpuPeak()

        runTimes.add(rustResult.proofGenMs)

        if (!rustResult.isValid && rustResult.errorMsg.isNotEmpty()) {
            throw Exception(rustResult.errorMsg)
        }

        updateStep("Done! ✓", 100)

        return BenchmarkResult(
            // 🔴 MUST
            proofGenerationMs = rustResult.proofGenMs,
            verificationMs    = rustResult.verifyMs,
            proofSizeKb       = rustResult.proofSizeKb,
            isValid           = rustResult.isValid,
            // 🟡 GOOD — now accurate
            memoryKb          = rustResult.memoryKb,           // ✅ Rust heap KB
            peakMemoryKb      = rustResult.peakMemoryKb,       // ✅ Peak memory
            cpuPeakPct        = cpuPeakPct,
            circuitSetupMs    = rustResult.circuitSetupMs,
            witnessGenUs      = rustResult.witnessGenUs,        // ✅ microseconds
            constraintCount   = rustResult.constraintCount,
            // 🟢 BONUS
            deviceModel       = deviceModel,
            androidVersion    = androidVer,
            cpuArch           = cpuArch,
            runCount          = runCount,
            avgTimeMs         = runTimes.average().toLong(),
            minTimeMs         = runTimes.min(),
            maxTimeMs         = runTimes.max()
        )
    }

    // =========================================================================
    // UI STATE MANAGEMENT
    // =========================================================================

    private fun showIdleState() {
        tvStatusEmoji.text = "🧪"
        tvStatus.text      = "Ready to run benchmark"
        tvStatus.setTextColor(Color.parseColor("#94A3B8"))
        layoutProgress.visibility = View.GONE
        layoutResults.visibility  = View.GONE
        btnRunTest.text           = "▶  RUN TEST PROOF"
        btnRunTest.isEnabled      = true
    }

    private fun showRunningState() {
        tvStatusEmoji.text = "⚡"
        tvStatus.text      = "Generating proof…"
        tvStatus.setTextColor(Color.parseColor("#3B82F6"))
        layoutProgress.visibility = View.VISIBLE
        layoutResults.visibility  = View.GONE
        progressBar.progress      = 0
        btnRunTest.text           = "RUNNING…"
        btnRunTest.isEnabled      = false
    }

    private fun showResults(result: BenchmarkResult) {
        tvStatusEmoji.text = if (result.isValid) "✅" else "❌"
        tvStatus.text      = if (result.isValid) "All tests passed!" else "Proof verification failed!"
        tvStatus.setTextColor(
            if (result.isValid) Color.parseColor("#22C55E")
            else Color.parseColor("#EF4444")
        )
        layoutProgress.visibility = View.GONE
        layoutResults.visibility  = View.VISIBLE

        val sdf = SimpleDateFormat("dd MMM yyyy  HH:mm:ss", Locale.getDefault())
        tvTimestamp.text = "Last run: ${sdf.format(Date())}"

        buildMustRows(result)
        buildGoodRows(result)
        buildBonusRows(result)

        cardMust.visibility  = View.VISIBLE
        cardGood.visibility  = View.VISIBLE
        cardBonus.visibility = View.VISIBLE

        btnRunTest.text      = "▶  RUN AGAIN"
        btnRunTest.isEnabled = true
    }

    private fun showFailedState(error: String) {
        tvStatusEmoji.text = "❌"
        tvStatus.text      = "Error: $error"
        tvStatus.setTextColor(Color.parseColor("#EF4444"))
        layoutProgress.visibility = View.GONE
        btnRunTest.text           = "▶  RETRY"
        btnRunTest.isEnabled      = true
    }

    // =========================================================================
    // METRIC ROW BUILDERS
    // =========================================================================

    private fun buildMustRows(r: BenchmarkResult) {
        layoutMustRows.removeAllViews()
        val rows = listOf(
            MetricResult("Proof Generation",  "${r.proofGenerationMs}", "ms",  "⚡", Color.parseColor("#3B82F6")),
            MetricResult("Verification Time", "${r.verificationMs}",    "ms",  "✅", Color.parseColor("#22C55E")),
            MetricResult("Proof Size", String.format("%.2f", r.proofSizeKb), "KB", "📦", Color.parseColor("#F59E0B")),
            MetricResult("Status", if (r.isValid) "SUCCESS" else "FAILED", "", "🔒",
                if (r.isValid) Color.parseColor("#22C55E") else Color.parseColor("#EF4444"))
        )
        rows.forEach { layoutMustRows.addView(createMetricRow(it)) }
    }

    private fun buildGoodRows(r: BenchmarkResult) {
        layoutGoodRows.removeAllViews()

        // ✅ Witness: microseconds display
        val witnessDisplay = if (r.witnessGenUs < 1000) "${r.witnessGenUs} µs"
                             else "${r.witnessGenUs / 1000}.${(r.witnessGenUs % 1000)/100} ms"

        // ✅ Memory: KB or MB
        val memDisplay = if (r.memoryKb < 1024) "${r.memoryKb} KB"
                         else "${r.memoryKb / 1024} MB"

        val peakMemDisplay = if (r.peakMemoryKb < 1024) "${r.peakMemoryKb} KB"
                             else "${r.peakMemoryKb / 1024} MB"

        val rows = listOf(
            MetricResult("Memory Used",        memDisplay,            "",   "🧠", Color.parseColor("#A855F7")),
            MetricResult("Peak Memory",        peakMemDisplay,        "",   "📉", Color.parseColor("#A855F7")),
            MetricResult("CPU Peak",           "${r.cpuPeakPct}",     "%",  "⚙️", Color.parseColor("#F59E0B")),
            MetricResult("Circuit Setup",      "${r.circuitSetupMs}", "ms", "🔧", Color.parseColor("#06B6D4")),
            MetricResult("Witness Generation", witnessDisplay,        "",   "👁", Color.parseColor("#3B82F6")),
            MetricResult("Constraint Count",   "${r.constraintCount}","",   "🧩", Color.parseColor("#A855F7"))
        )
        rows.forEach { layoutGoodRows.addView(createMetricRow(it)) }
    }

    private fun buildBonusRows(r: BenchmarkResult) {
        layoutBonusRows.removeAllViews()
        val rows = listOf(
            MetricResult("Device",       r.deviceModel,    "",   "📱", Color.parseColor("#64748B")),
            MetricResult("Android",      r.androidVersion, "",   "🤖", Color.parseColor("#64748B")),
            MetricResult("CPU Arch",     r.cpuArch,        "",   "🏗", Color.parseColor("#64748B")),
            MetricResult("Test Runs",    "${r.runCount}",  "x",  "🔁", Color.parseColor("#64748B")),
            MetricResult("Average Time", "${r.avgTimeMs}", "ms", "📊", Color.parseColor("#06B6D4")),
            MetricResult("Min / Max",    "${r.minTimeMs} / ${r.maxTimeMs}", "ms", "📈", Color.parseColor("#06B6D4"))
        )
        rows.forEach { layoutBonusRows.addView(createMetricRow(it)) }
    }

    private fun createMetricRow(metric: MetricResult): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(0, 16, 0, 16)
        }
        val tvEmoji = TextView(this).apply {
            text         = metric.emoji
            textSize     = 18f
            layoutParams = LinearLayout.LayoutParams(80, LinearLayout.LayoutParams.WRAP_CONTENT)
        }
        val tvLabel = TextView(this).apply {
            text         = metric.label
            textSize     = 12f
            setTextColor(Color.parseColor("#64748B"))
            layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
        }
        val tvValue = TextView(this).apply {
            text     = metric.value
            textSize = 15f
            setTextColor(metric.valueColor)
            typeface = android.graphics.Typeface.DEFAULT_BOLD
        }
        val tvUnit = TextView(this).apply {
            text         = "  ${metric.unit}"
            textSize     = 11f
            setTextColor(Color.parseColor("#64748B"))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            )
        }
        row.addView(tvEmoji)
        row.addView(tvLabel)
        row.addView(tvValue)
        if (metric.unit.isNotEmpty()) row.addView(tvUnit)
        return row
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    private fun updateStep(step: String, progress: Int) {
        handler.post {
            tvProgressStep.text  = step
            progressBar.progress = progress
        }
    }

    private fun getUsedMemoryMb(): Long {
        val runtime = Runtime.getRuntime()
        return (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024)
    }

    private fun estimateCpuPeak(): Int {
        return try {
            val reader1 = java.io.RandomAccessFile("/proc/stat", "r")
            val line1   = reader1.readLine(); reader1.close()
            Thread.sleep(200)
            val reader2 = java.io.RandomAccessFile("/proc/stat", "r")
            val line2   = reader2.readLine(); reader2.close()
            val toks1   = line1.split(" ").drop(2).map { it.toLongOrNull() ?: 0L }
            val toks2   = line2.split(" ").drop(2).map { it.toLongOrNull() ?: 0L }
            val idle1   = toks1[3]; val total1 = toks1.sum()
            val idle2   = toks2[3]; val total2 = toks2.sum()
            val totalDiff = total2 - total1
            val idleDiff  = idle2  - idle1
            if (totalDiff == 0L) 0
            else ((1.0 - idleDiff.toDouble() / totalDiff) * 100).toInt().coerceIn(0, 100)
        } catch (e: Exception) { 0 }
    }

    // =========================================================================
    // DATA CLASS — updated fields
    // =========================================================================

    data class BenchmarkResult(
        // 🔴 MUST
        val proofGenerationMs : Long,
        val verificationMs    : Long,
        val proofSizeKb       : Double,
        val isValid           : Boolean,
        // 🟡 GOOD
        val memoryKb          : Long,       // ✅ Rust heap KB
        val peakMemoryKb      : Long,       // ✅ Peak memory
        val cpuPeakPct        : Int,
        val circuitSetupMs    : Long,
        val witnessGenUs      : Long,       // ✅ microseconds
        val constraintCount   : Int,
        // 🟢 BONUS
        val deviceModel       : String,
        val androidVersion    : String,
        val cpuArch           : String,
        val runCount          : Int,
        val avgTimeMs         : Long,
        val minTimeMs         : Long,
        val maxTimeMs         : Long
    )
}